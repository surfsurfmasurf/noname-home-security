# Noname Security — 아키텍처 및 배포 가이드

## 개요

Noname Security는 [Noname Security](https://nonamesecurity.com)에서 영감을 받은 홈 네트워크 API 보안 모니터링 시스템입니다. 현실적인 API 트래픽을 생성하고, ML 앙상블로 이상을 탐지하며, 선택적으로 LLM(Claude)으로 위협을 분석하고, 모든 데이터를 Elasticsearch에 저장하여 Kibana로 시각화합니다.

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────────┐
│                      서버 1 (ES/Kibana)                             │
│                      172.233.75.253                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │ Elasticsearch │  │    Kibana    │  │  Python (직접 실행)     │    │
│  │   :9200       │  │    :5601     │  │  scripts.run_continuous │    │
│  └──────────────┘  └──────────────┘  └────────────────────────┘    │
└───────────────────────────▲─────────────────────────────────────────┘
                            │  HTTP :9200
┌───────────────────────────┼─────────────────────────────────────────┐
│                  서버 2 (K3s 워커)                                    │
│                  172.234.80.251                                       │
│                                                                      │
│  ┌──────────────────── K3s 클러스터 ────────────────────────┐       │
│  │  namespace: noname-security                               │       │
│  │                                                           │       │
│  │  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐       │       │
│  │  │  Pod 1      │ │  Pod 2      │ │  Pod 3       │       │       │
│  │  │  데스크톱   │ │  모바일     │ │  카메라      │       │       │
│  │  │  rate: 5/s  │ │  rate: 3/s  │ │  rate: 4/s   │       │       │
│  │  └─────────────┘ └─────────────┘ └──────────────┘       │       │
│  │  ┌─────────────┐                                         │       │
│  │  │  Pod 4      │    ConfigMap: noname-config              │       │
│  │  │  백엔드     │    (ES 호스트가 포함된 settings.yaml)    │       │
│  │  │  rate: 8/s  │                                         │       │
│  │  └─────────────┘                                         │       │
│  └───────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
```

## 파이프라인 단계

각 컨테이너(Pod)는 독립적으로 전체 탐지 파이프라인을 실행합니다:

```
Generator → Collector → Detector → [LLM 필터] → Responder → Elasticsearch
   │            │           │            │              │
   │ Raw HTTP   │ 특성 벡터  │ 스코어링   │ 분석 완료    │ Alert
   │ 이벤트     │           │ 알림       │ 알림         │ + 이메일
   ▼            ▼           ▼            ▼              ▼
 LocalQueue  LocalQueue  LocalQueue  LocalQueue     ES 인덱스
```

| 단계 | 모듈 | 설명 |
|------|------|------|
| **Generator** | `src/generator/` | 현실적인 API 트래픽 생성 (50+ 엔드포인트, 헤더, 쿼리 파라미터, 응답 코드). 4가지 프로필: desktop_browser, mobile_app, smart_camera, backend_service |
| **Collector** | `src/collector/` | 원시 HTTP 이벤트에서 13차원 특성 벡터 추출. 5분 슬라이딩 윈도우로 IP 집계 |
| **Detector** | `src/detector/` | 앙상블 모델 스코어링: Isolation Forest (40%) + Autoencoder (40%) + 시그니처 매칭 (20%). 이상 점수 0-100 출력 |
| **LLM Analyst** | `src/analyst/` | 선택사항. Claude가 고점수 알림을 분석하여 위협 분류. `--llm-threshold`로 제어 (기본값: 50) |
| **Responder** | `src/action/` | 알림 로깅, ES 저장 (`noname-alerts` 인덱스), 고점수 알림 이메일 발송 (score >= `EMAIL_MIN_SCORE`) |

## ML 모델

두 모델이 앙상블로 작동합니다:

| 모델 | 타입 | 파일 | 역할 |
|------|------|------|------|
| Isolation Forest | sklearn | `src/models/isolation_forest.pkl` | 특성 공간에서 이상치 탐지 |
| Autoencoder | PyTorch | `src/models/autoencoder.pt` | 재구성 오류를 통한 이상 탐지 |

배포 전 모델 학습:
```bash
python -m scripts.train
```

## 공격 유형

Generator는 10가지 공격 카테고리를 현실적인 페이로드로 시뮬레이션합니다:

| 공격 유형 | 비율 | 설명 |
|-----------|------|------|
| SQL Injection | 18% | Union 기반, 에러 기반, 인코딩 변형 |
| Brute Force | 15% | 자격 증명 목록을 이용한 로그인 시도 |
| XSS | 12% | 스크립트 삽입, 이벤트 핸들러, 인코딩 |
| C2 Communication | 10% | 비커닝 패턴, DNS 터널링 |
| Path Traversal | 10% | 인코딩 트릭을 사용한 디렉토리 순회 |
| Credential Stuffing | 10% | 유출된 자격 증명으로 분산 로그인 |
| Port Scan | 8% | 순차/랜덤 포트 탐색 |
| API Abuse | 7% | 속도 제한 우회, 엔드포인트 열거 |
| Slow POST | 5% | 애플리케이션 레이어 DoS |
| Encoded Payload | 5% | 이중 인코딩, 유니코드 트릭 |

## Elasticsearch 인덱스

| 인덱스 | 용도 | 주요 필드 |
|--------|------|-----------|
| `noname-all-traffic` | 처리된 전체 트래픽 | timestamp, src_ip, anomaly_score, label, container_id |
| `noname-alerts` | 이상 이벤트 (score >= 임계값) | 전체 트래픽 필드 + severity, llm_analysis, recommended_action, is_threat, attack_type, llm_analyzed, model_scores |

## Docker 구성

### Dockerfile

- 베이스: `python:3.11-slim`
- PyTorch CPU 전용 (~200MB, CUDA 2GB+ 대비)
- 엔트리포인트: `python -m scripts.run_continuous --no-llm`
- 기본 속도: 5 events/sec (CMD로 오버라이드 가능)

### Docker Compose (4개 컨테이너)

| 서비스 | 컨테이너 ID | 프로필 | 속도 |
|--------|-------------|--------|------|
| desktop-browser | container-1-desktop | desktop_browser | 5/s |
| mobile-app | container-2-mobile | mobile_app | 3/s |
| smart-camera | container-3-camera | smart_camera | 4/s |
| backend-service | container-4-backend | backend_service | 8/s |

```bash
# 4개 컨테이너 빌드 및 실행
docker compose up -d --build

# 로그 확인
docker compose logs -f

# 중지
docker compose down
```

## K3s (Kubernetes) 배포

### K3s를 선택한 이유

- 경량 Kubernetes (~50MB 바이너리)
- 라이선스 불필요 (Apache 2.0)
- containerd 사용 (Docker 대신)
- 홈 랩 / 엣지 환경에 적합

### 매니페스트 파일

```
k8s/
├── namespace.yaml    # noname-security 네임스페이스
├── configmap.yaml    # settings.yaml (ES 호스트, 탐지기 설정)
└── deployments.yaml  # 4개 Deployment (트래픽 프로필별 1개)
```

### Pod 당 리소스 제한

| 리소스 | 요청 | 제한 |
|--------|------|------|
| 메모리 | 256Mi | 512Mi |
| CPU | 100m | 500m |

### 배포 방법

**방법 A: 자동 스크립트**
```bash
chmod +x scripts/setup_k3s.sh
sudo bash scripts/setup_k3s.sh
```

**방법 B: 수동 설치**
```bash
# 1. K3s 설치
curl -sfL https://get.k3s.io | sh -

# 2. Docker 이미지 빌드 후 K3s containerd로 임포트
docker build -t noname-security:latest .
docker save noname-security:latest | sudo k3s ctr images import -

# 3. 매니페스트 적용
sudo k3s kubectl apply -f k8s/namespace.yaml
sudo k3s kubectl apply -f k8s/configmap.yaml
sudo k3s kubectl apply -f k8s/deployments.yaml

# 4. 확인
sudo k3s kubectl get pods -n noname-security
```

### 주요 kubectl 명령어

```bash
# Pod 조회
sudo k3s kubectl get pods -n noname-security -o wide

# 로그 확인 (특정 프로필)
sudo k3s kubectl logs -n noname-security -l profile=desktop-browser --tail=20

# 로그 확인 (전체)
sudo k3s kubectl logs -n noname-security -l app=noname-security --tail=50

# Deployment 스케일링
sudo k3s kubectl scale deployment noname-desktop-browser -n noname-security --replicas=3

# Deployment 재시작
sudo k3s kubectl rollout restart deployment noname-desktop-browser -n noname-security

# 전체 삭제
sudo k3s kubectl delete namespace noname-security

# K3s 제거
/usr/local/bin/k3s-uninstall.sh
```

## LLM 연동

### 임계값 기반 필터링

API 비용 절감을 위해 설정된 임계값 이상의 알림에만 LLM 분석을 적용합니다:

```
점수 < 임계값  →  LLM 건너뜀, "(Below LLM threshold)" 라벨
점수 >= 임계값  →  Claude에 전송하여 분석
```

```bash
# 점수 82 이상 알림에 LLM 분석 활성화
python -m scripts.run_continuous --rate 5 --llm-threshold 82
```

**환경 변수:**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 이메일 알림

고점수 알림 발생 시 Gmail로 알림을 받을 수 있습니다:

```bash
export GMAIL_USER="your@gmail.com"
export GMAIL_APP_PASS="xxxx xxxx xxxx xxxx"   # Google 앱 비밀번호
export ALERT_EMAIL_TO="recipient@example.com"
export EMAIL_MIN_SCORE=95                       # 점수 95 이상만 이메일 발송
```

**Google 앱 비밀번호 설정:**
1. [Google 계정 보안](https://myaccount.google.com/security)에서 2단계 인증 활성화
2. [앱 비밀번호](https://myaccount.google.com/apppasswords)에서 생성

## Kibana 대시보드

### 추천 패널 구성

| 패널 | 인덱스 | 시각화 유형 | 설정 |
|------|--------|-------------|------|
| 컨테이너별 트래픽 | noname-all-traffic | Area Stacked | Y: Count, Breakdown: container_id.keyword Top values |
| 이상 점수 타임라인 | noname-all-traffic | Line | Y: anomaly_score 평균, X: timestamp |
| 유형별 알림 수 | noname-alerts | Bar | Y: Count, Breakdown: label.keyword Top values |
| 고점수 알림 테이블 | noname-alerts | Table | 컬럼: timestamp, src_ip, anomaly_score, severity, label, llm_analysis |
| LLM 분석 알림 | noname-alerts | Table | 필터: llm_analyzed = true, 컬럼: timestamp, src_ip, score, severity, llm_analysis |

### LLM 결과 필터링

Kibana Discover 또는 대시보드에서 KQL 사용:
```
anomaly_score >= 82 AND llm_analyzed: true
```

## 프로젝트 구조

```
noname-security/
├── config/
│   └── settings.yaml           # 메인 설정 파일
├── k8s/
│   ├── namespace.yaml          # K8s 네임스페이스
│   ├── configmap.yaml          # K8s ConfigMap
│   └── deployments.yaml        # 4개 Deployment 매니페스트
├── scripts/
│   ├── run_continuous.py       # 메인 진입점
│   ├── run_pipeline.py         # 단발성 파이프라인 실행
│   ├── train.py                # 모델 학습
│   ├── benchmark.py            # 모델 벤치마크
│   ├── setup_k3s.sh            # K3s 설정 자동화
│   └── setup_kibana.py         # Kibana 대시보드 설정
├── src/
│   ├── generator/
│   │   ├── generator.py        # 트래픽 생성 엔진
│   │   ├── profiles.py         # 4가지 트래픽 프로필 (50+ 엔드포인트)
│   │   ├── attack_patterns.py  # 10가지 공격 유형
│   │   └── replay.py           # CICIDS 데이터셋 리플레이
│   ├── collector/
│   │   ├── collector.py        # 이벤트 수집
│   │   └── feature_extractor.py # 13차원 특성 추출
│   ├── detector/
│   │   ├── detector.py         # 앙상블 오케스트레이터
│   │   ├── isolation_forest.py # Isolation Forest 모델
│   │   ├── autoencoder.py      # Autoencoder 모델
│   │   └── scorer.py           # 점수 결합
│   ├── analyst/
│   │   └── analyst.py          # LLM (Claude) 분석
│   ├── action/
│   │   └── responder.py        # 알림 + 이메일 처리
│   ├── storage/
│   │   └── es_client.py        # Elasticsearch 클라이언트
│   ├── queue/
│   │   ├── base.py             # 큐 인터페이스
│   │   └── local_queue.py      # 스레드 안전 큐
│   └── models/                 # 학습된 모델 파일
│       ├── isolation_forest.pkl
│       └── autoencoder.pt
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .dockerignore
```

## 빠른 시작

### 서버 1 (Python 직접 실행)
```bash
# 의존성 설치
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cpu

# 모델 학습
python -m scripts.train

# 실행 (LLM 없이)
python -m scripts.run_continuous --rate 5 --no-llm

# 실행 (LLM 포함)
export ANTHROPIC_API_KEY="sk-ant-..."
python -m scripts.run_continuous --rate 5 --llm-threshold 82
```

### 서버 2 (K3s)
```bash
# 먼저 모델 학습 (또는 서버 1에서 복사)
python -m scripts.train

# K3s로 배포
sudo bash scripts/setup_k3s.sh
```
