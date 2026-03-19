# Noname Security — Architecture & Deployment Guide

## Overview

Noname Security is a home-network API security monitoring system inspired by [Noname Security](https://nonamesecurity.com). It generates realistic API traffic, detects anomalies using an ML ensemble, optionally analyzes threats with an LLM (Claude), and stores everything in Elasticsearch for visualization via Kibana.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Server 1 (ES/Kibana)                        │
│                        172.233.75.253                               │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │ Elasticsearch │  │    Kibana    │  │  Python (direct run)   │    │
│  │   :9200       │  │    :5601     │  │  scripts.run_continuous │    │
│  └──────────────┘  └──────────────┘  └────────────────────────┘    │
└───────────────────────────▲─────────────────────────────────────────┘
                            │  HTTP :9200
┌───────────────────────────┼─────────────────────────────────────────┐
│                  Server 2 (K3s Worker)                               │
│                  172.234.80.251                                      │
│                                                                      │
│  ┌──────────────────── K3s Cluster ─────────────────────────┐       │
│  │  namespace: noname-security                               │       │
│  │                                                           │       │
│  │  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐       │       │
│  │  │  Pod 1      │ │  Pod 2      │ │  Pod 3       │       │       │
│  │  │  desktop    │ │  mobile     │ │  camera      │       │       │
│  │  │  rate: 5/s  │ │  rate: 3/s  │ │  rate: 4/s   │       │       │
│  │  └─────────────┘ └─────────────┘ └──────────────┘       │       │
│  │  ┌─────────────┐                                         │       │
│  │  │  Pod 4      │    ConfigMap: noname-config              │       │
│  │  │  backend    │    (settings.yaml with ES host)          │       │
│  │  │  rate: 8/s  │                                         │       │
│  │  └─────────────┘                                         │       │
│  └───────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
```

## Pipeline Stages

Each container (Pod) runs the full detection pipeline independently:

```
Generator → Collector → Detector → [LLM Filter] → Responder → Elasticsearch
   │            │           │            │              │
   │ Raw HTTP   │ Feature   │ Scored     │ Enriched     │ Alert
   │ events     │ vectors   │ alerts     │ alerts       │ + Email
   ▼            ▼           ▼            ▼              ▼
 LocalQueue  LocalQueue  LocalQueue  LocalQueue     ES Index
```

| Stage | Module | Description |
|-------|--------|-------------|
| **Generator** | `src/generator/` | Produces realistic API traffic (50+ endpoints, headers, query params, response codes). 4 traffic profiles: desktop_browser, mobile_app, smart_camera, backend_service. |
| **Collector** | `src/collector/` | Extracts 13-dimensional feature vectors from raw HTTP events using a 5-minute sliding window for IP aggregation. |
| **Detector** | `src/detector/` | Ensemble model scoring: Isolation Forest (40%) + Autoencoder (40%) + Signature matching (20%). Outputs anomaly score 0-100. |
| **LLM Analyst** | `src/analyst/` | Optional. Claude analyzes high-score alerts for threat classification. Controlled by `--llm-threshold` (default: 50). |
| **Responder** | `src/action/` | Logs alerts, stores to ES (`noname-alerts` index), sends email for critical alerts (score >= `EMAIL_MIN_SCORE`). |

## ML Models

Two models work as an ensemble:

| Model | Type | File | Role |
|-------|------|------|------|
| Isolation Forest | sklearn | `src/models/isolation_forest.pkl` | Detects outliers in feature space |
| Autoencoder | PyTorch | `src/models/autoencoder.pt` | Detects anomalies via reconstruction error |

Train models before deployment:
```bash
python -m scripts.train
```

## Attack Types

The generator simulates 10 attack categories with realistic payloads:

| Attack | Weight | Description |
|--------|--------|-------------|
| SQL Injection | 18% | Union-based, error-based, encoded variants |
| Brute Force | 15% | Login attempts with credential lists |
| XSS | 12% | Script injection, event handlers, encoded |
| C2 Communication | 10% | Beaconing patterns, DNS tunneling |
| Path Traversal | 10% | Directory traversal with encoding tricks |
| Credential Stuffing | 10% | Distributed login with leaked creds |
| Port Scan | 8% | Sequential/random port probing |
| API Abuse | 7% | Rate limit evasion, endpoint enumeration |
| Slow POST | 5% | Application-layer DoS |
| Encoded Payload | 5% | Double encoding, unicode tricks |

## Elasticsearch Indices

| Index | Purpose | Key Fields |
|-------|---------|------------|
| `noname-all-traffic` | All processed traffic | timestamp, src_ip, anomaly_score, label, container_id |
| `noname-alerts` | Anomalous events (score >= threshold) | All traffic fields + severity, llm_analysis, recommended_action, is_threat, attack_type, llm_analyzed, model_scores |

## Docker Configuration

### Dockerfile

- Base: `python:3.11-slim`
- PyTorch CPU-only (~200MB vs 2GB+ CUDA)
- Entrypoint: `python -m scripts.run_continuous --no-llm`
- Default rate: 5 events/sec (override via CMD)

### Docker Compose (4 containers)

| Service | Container ID | Profile | Rate |
|---------|-------------|---------|------|
| desktop-browser | container-1-desktop | desktop_browser | 5/s |
| mobile-app | container-2-mobile | mobile_app | 3/s |
| smart-camera | container-3-camera | smart_camera | 4/s |
| backend-service | container-4-backend | backend_service | 8/s |

```bash
# Build and run all 4 containers
docker compose up -d --build

# View logs
docker compose logs -f

# Stop
docker compose down
```

## K3s (Kubernetes) Deployment

### Why K3s?

- Lightweight Kubernetes (~50MB binary)
- No license required (Apache 2.0)
- Uses containerd instead of Docker for runtime
- Ideal for home lab / edge environments

### Manifest Files

```
k8s/
├── namespace.yaml    # noname-security namespace
├── configmap.yaml    # settings.yaml (ES host, detector config)
└── deployments.yaml  # 4 Deployments (one per traffic profile)
```

### Resource Limits Per Pod

| Resource | Request | Limit |
|----------|---------|-------|
| Memory | 256Mi | 512Mi |
| CPU | 100m | 500m |

### Deployment Steps

**Option A: Automated Script**
```bash
chmod +x scripts/setup_k3s.sh
sudo bash scripts/setup_k3s.sh
```

**Option B: Manual**
```bash
# 1. Install K3s
curl -sfL https://get.k3s.io | sh -

# 2. Build Docker image & import to K3s containerd
docker build -t noname-security:latest .
docker save noname-security:latest | sudo k3s ctr images import -

# 3. Apply manifests
sudo k3s kubectl apply -f k8s/namespace.yaml
sudo k3s kubectl apply -f k8s/configmap.yaml
sudo k3s kubectl apply -f k8s/deployments.yaml

# 4. Verify
sudo k3s kubectl get pods -n noname-security
```

### Useful kubectl Commands

```bash
# View pods
sudo k3s kubectl get pods -n noname-security -o wide

# View logs (specific profile)
sudo k3s kubectl logs -n noname-security -l profile=desktop-browser --tail=20

# View logs (all)
sudo k3s kubectl logs -n noname-security -l app=noname-security --tail=50

# Scale a deployment
sudo k3s kubectl scale deployment noname-desktop-browser -n noname-security --replicas=3

# Restart a deployment
sudo k3s kubectl rollout restart deployment noname-desktop-browser -n noname-security

# Delete everything
sudo k3s kubectl delete namespace noname-security

# Uninstall K3s
/usr/local/bin/k3s-uninstall.sh
```

## LLM Integration

### Threshold-Based Filtering

To control API costs, LLM analysis is only triggered for alerts above a configurable threshold:

```
Score < threshold  →  Skip LLM, label as "(Below LLM threshold)"
Score >= threshold  →  Send to Claude for analysis
```

```bash
# Enable LLM for alerts with score >= 82
python -m scripts.run_continuous --rate 5 --llm-threshold 82
```

**Environment variables:**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Email Notifications

High-score alerts can trigger Gmail notifications:

```bash
export GMAIL_USER="your@gmail.com"
export GMAIL_APP_PASS="xxxx xxxx xxxx xxxx"   # Google App Password
export ALERT_EMAIL_TO="recipient@example.com"
export EMAIL_MIN_SCORE=95                       # Only email score >= 95
```

**Setup Google App Password:**
1. Enable 2-Step Verification at [Google Account Security](https://myaccount.google.com/security)
2. Create App Password at [App Passwords](https://myaccount.google.com/apppasswords)

## Kibana Dashboards

### Recommended Panels

| Panel | Index | Visualization | Configuration |
|-------|-------|---------------|---------------|
| Traffic per Container | noname-all-traffic | Area Stacked | Y: Count, Breakdown: Top values of container_id.keyword |
| Anomaly Score Timeline | noname-all-traffic | Line | Y: Average of anomaly_score, X: timestamp |
| Alert Count by Type | noname-alerts | Bar | Y: Count, Breakdown: Top values of label.keyword |
| High Score Alerts Table | noname-alerts | Table | Columns: timestamp, src_ip, anomaly_score, severity, label, llm_analysis |
| LLM Analyzed Alerts | noname-alerts | Table | Filter: llm_analyzed = true, Columns: timestamp, src_ip, score, severity, llm_analysis |

### Filtering LLM Results

In Kibana Discover or Dashboard, use KQL:
```
anomaly_score >= 82 AND llm_analyzed: true
```

## Project Structure

```
noname-security/
├── config/
│   └── settings.yaml           # Main configuration
├── k8s/
│   ├── namespace.yaml          # K8s namespace
│   ├── configmap.yaml          # K8s ConfigMap
│   └── deployments.yaml        # 4 Deployment manifests
├── scripts/
│   ├── run_continuous.py       # Main entry point
│   ├── run_pipeline.py         # One-shot pipeline run
│   ├── train.py                # Model training
│   ├── benchmark.py            # Model benchmarking
│   ├── setup_k3s.sh            # K3s setup automation
│   └── setup_kibana.py         # Kibana dashboard setup
├── src/
│   ├── generator/
│   │   ├── generator.py        # Traffic generation engine
│   │   ├── profiles.py         # 4 traffic profiles (50+ endpoints)
│   │   ├── attack_patterns.py  # 10 attack types
│   │   └── replay.py           # CICIDS dataset replay
│   ├── collector/
│   │   ├── collector.py        # Event collection
│   │   └── feature_extractor.py # 13-dim feature extraction
│   ├── detector/
│   │   ├── detector.py         # Ensemble orchestrator
│   │   ├── isolation_forest.py # Isolation Forest model
│   │   ├── autoencoder.py      # Autoencoder model
│   │   └── scorer.py           # Score combination
│   ├── analyst/
│   │   └── analyst.py          # LLM (Claude) analysis
│   ├── action/
│   │   └── responder.py        # Alert + Email actions
│   ├── storage/
│   │   └── es_client.py        # Elasticsearch client
│   ├── queue/
│   │   ├── base.py             # Queue interface
│   │   └── local_queue.py      # Thread-safe queue
│   └── models/                 # Trained model files
│       ├── isolation_forest.pkl
│       └── autoencoder.pt
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .dockerignore
```

## Quick Start

### Server 1 (Direct Python)
```bash
# Install dependencies
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Train models
python -m scripts.train

# Run (no LLM)
python -m scripts.run_continuous --rate 5 --no-llm

# Run (with LLM)
export ANTHROPIC_API_KEY="sk-ant-..."
python -m scripts.run_continuous --rate 5 --llm-threshold 82
```

### Server 2 (K3s)
```bash
# Train models first (or copy from Server 1)
python -m scripts.train

# Deploy via K3s
sudo bash scripts/setup_k3s.sh
```
