# Noname Home Security

API security monitoring system inspired by Noname Security, designed for home network environments.

## Architecture

```
Generator → [Queue] → Collector → [Queue] → Detector → [Queue] → LLM Analyst → [Queue] → Responder
                                                 ↓
                                          Elasticsearch
```

**Agents:**
- **Traffic Generator** — Synthetic normal + attack traffic (SQLi, XSS, brute force, C2, port scan, path traversal)
- **Collector** — Feature extraction (15 features per request)
- **ML Detector** — Isolation Forest + Autoencoder ensemble scoring (0-100)
- **LLM Analyst** — Claude API interprets anomalies
- **Responder** — Alerts and auto-blocking

## Quick Start

### 1. Install

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/noname-home-security.git
cd noname-home-security

# Create conda environment
conda env create -f environment.yml
conda activate noname-sec

# Install PyTorch (CPU) + other pip packages
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install elasticsearch anthropic
```

### 2. Configure

Edit `config/settings.yaml`:
```yaml
elasticsearch:
  host: "http://YOUR_ES_HOST:9200"
```

### 3. Train

```bash
python -m scripts.train --samples 10000
```

### 4. Run Pipeline

```bash
# Without LLM/ES (test mode)
python -m scripts.run_pipeline --events 100 --no-llm --no-es

# With Elasticsearch
python -m scripts.run_pipeline --events 100 --no-llm

# Full (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=your-key
python -m scripts.run_pipeline --events 50
```

### 5. Test

```bash
python -m pytest tests/ -v
```

## Design Principles

- **Queue abstraction** — Swap local Queue → Redis → Kafka via config
- **Modular agents** — Each agent is independent, communicates only via queues
- **Ensemble scoring** — 40% Isolation Forest + 40% Autoencoder + 20% Signature matching
