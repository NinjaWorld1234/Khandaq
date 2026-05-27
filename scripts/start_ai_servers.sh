#!/usr/bin/env bash
###############################################################################
# SOC Platform — Offline AI Inference Engine Starter
# مشغل عقول الذكاء الاصطناعي كخوادم محلية لمعمارية خندق
# This script uses llama.cpp to host the GGUF models on local ports.
###############################################################################

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

readonly MODELS_DIR="/root/Khandaq/soc_models"
readonly LOG_DIR="/var/log/soc_ai"

mkdir -p "$LOG_DIR"

log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${RED}[WARNING]${NC} $1"; }

if ! command -v docker &> /dev/null; then
    echo "⚠️ Docker is not installed. This script uses the official llama.cpp docker container."
    exit 1
fi

log_info "Ensuring llama.cpp docker image is available..."
# In a fully air-gapped environment, you would load this from a .tar file.
# For now, we attempt to pull it if it doesn't exist.
docker pull ghcr.io/ggerganov/llama.cpp:server || true

# Function to start a model
start_model() {
    local name=$1
    local port=$2
    local model_path=$3
    local ctx_size=$4

    log_step "Starting ${name} on port ${port}..."

    if docker ps -a --format '{{.Names}}' | grep -Eq "^${name}\$"; then
        log_warn "Container ${name} already exists. Stopping and removing..."
        docker rm -f "${name}" >/dev/null
    fi

    # Find the actual GGUF file in the directory
    local gguf_file=$(find "$model_path" -name "*.gguf" | head -n 1)

    if [ -z "$gguf_file" ]; then
        log_warn "No GGUF file found in ${model_path}. Skipping ${name}..."
        return
    fi

    # Run the server in detached mode
    docker run -d \
        --name "${name}" \
        --restart unless-stopped \
        -p "${port}:8080" \
        -v "$model_path:/models" \
        ghcr.io/ggerganov/llama.cpp:server \
        -m "/models/$(basename "$gguf_file")" \
        -c "${ctx_size}" \
        --host 0.0.0.0 \
        --port 8080 > "${LOG_DIR}/${name}.log"

    log_info "${name} is booting up on http://127.0.0.1:${port}/v1"
}

echo "================================================================"
echo "Initializing AI Inference Engines (CPU-based, limited context)"
echo "Note: If your server RAM is limited (<16GB), you should stop"
echo "some of these containers to prevent OOM (Out Of Memory) crashes."
echo "================================================================"


# Start Qwen Commander (Strategic decisions — needs long context)
start_model "ai-commander-qwen" 8000 "${MODELS_DIR}/Commander-Qwen" 32768

# Start WhiteRabbitNeo Workers (Cybersecurity-specialized tactical analysis)
start_model "ai-workers-whiterabbitneo" 8001 "${MODELS_DIR}/WhiteRabbitNeo-13B" 8192

echo "================================================================"
log_info "All enabled AI servers have been launched."
log_info "To view logs for a model: docker logs -f ai-commander-qwen"
log_info "To stop a model: docker stop ai-commander-qwen"
echo "================================================================"
