#!/bin/bash
# ============================================================
# Noname Security — K3s Setup Script
# Installs K3s, builds Docker image, deploys 4 agents
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "  Noname Security — K3s Deployment"
echo "============================================"

# --- Step 0: Check model files ---
echo ""
echo "[Step 0] Checking trained model files..."
if [ ! -f "$PROJECT_DIR/src/models/isolation_forest.pkl" ] || \
   [ ! -f "$PROJECT_DIR/src/models/autoencoder.pt" ]; then
    echo "ERROR: Model files not found!"
    echo "Run 'python -m scripts.train' first to generate models."
    exit 1
fi
echo "  Models found."

# --- Step 1: Install K3s ---
echo ""
echo "[Step 1] Installing K3s..."
if command -v k3s &> /dev/null; then
    echo "  K3s already installed: $(k3s --version)"
else
    curl -sfL https://get.k3s.io | sh -
    echo "  K3s installed successfully."
fi

# Wait for K3s to be ready
echo "  Waiting for K3s to be ready..."
sudo k3s kubectl wait --for=condition=Ready node --all --timeout=60s
echo "  K3s is ready."

# --- Step 2: Build Docker image ---
echo ""
echo "[Step 2] Building Docker image..."
cd "$PROJECT_DIR"

# Check if docker is available
if command -v docker &> /dev/null; then
    docker build -t noname-security:latest .
    echo "  Docker image built."

    # Import image into K3s containerd
    echo "  Importing image into K3s..."
    docker save noname-security:latest | sudo k3s ctr images import -
    echo "  Image imported."
else
    echo "ERROR: Docker not installed. Install Docker first:"
    echo "  curl -fsSL https://get.docker.com | sh"
    exit 1
fi

# --- Step 3: Apply K8s manifests ---
echo ""
echo "[Step 3] Deploying to K3s..."

# Create namespace
sudo k3s kubectl apply -f k8s/namespace.yaml
echo "  Namespace created."

# Apply ConfigMap
sudo k3s kubectl apply -f k8s/configmap.yaml
echo "  ConfigMap applied."

# Apply Deployments
sudo k3s kubectl apply -f k8s/deployments.yaml
echo "  Deployments applied."

# --- Step 4: Wait and verify ---
echo ""
echo "[Step 4] Waiting for pods to be ready..."
sudo k3s kubectl -n noname-security wait --for=condition=Ready pod --all --timeout=120s 2>/dev/null || true

echo ""
echo "============================================"
echo "  Deployment Status"
echo "============================================"
sudo k3s kubectl get pods -n noname-security -o wide
echo ""
sudo k3s kubectl get deployments -n noname-security
echo ""

echo "============================================"
echo "  Useful Commands"
echo "============================================"
echo ""
echo "# View all pods:"
echo "  sudo k3s kubectl get pods -n noname-security"
echo ""
echo "# View logs for a specific pod:"
echo "  sudo k3s kubectl logs -n noname-security -l profile=desktop-browser --tail=20"
echo ""
echo "# View logs for all pods:"
echo "  sudo k3s kubectl logs -n noname-security -l app=noname-security --tail=50"
echo ""
echo "# Scale a deployment (e.g., add 2 more desktop agents):"
echo "  sudo k3s kubectl scale deployment noname-desktop-browser -n noname-security --replicas=3"
echo ""
echo "# Restart a deployment:"
echo "  sudo k3s kubectl rollout restart deployment noname-desktop-browser -n noname-security"
echo ""
echo "# Delete everything:"
echo "  sudo k3s kubectl delete namespace noname-security"
echo ""
echo "# Uninstall K3s:"
echo "  /usr/local/bin/k3s-uninstall.sh"
echo ""
echo "Done! Check Kibana at http://172.233.75.253:5601 for data."
