FROM python:3.11-slim

WORKDIR /app

# Install PyTorch CPU-only (much smaller than full CUDA build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install other dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY scripts/ scripts/
COPY config/ config/

# Copy trained models (must exist locally — run train.py first)
COPY src/models/isolation_forest.pkl src/models/isolation_forest.pkl
COPY src/models/autoencoder.pt src/models/autoencoder.pt

# Environment
ENV CONTAINER_ID=default
ENV PROFILE=""
ENV PYTHONUNBUFFERED=1

# Default: run continuous monitoring without LLM
ENTRYPOINT ["python", "-m", "scripts.run_continuous", "--no-llm"]
CMD ["--rate", "5"]
