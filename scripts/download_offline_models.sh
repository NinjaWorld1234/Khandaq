#!/usr/bin/env bash
###############################################################################
# SOC Platform — Offline AI Models Downloader (Naser Server)
# أداة تحميل النماذج لسيرفر ناصر (التخزين غير المتصل)
# Architecture: Distributed Cognitive Cyber Defense Platform
###############################################################################

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

export PATH="$PATH:/root/.local/bin:$HOME/.local/bin"

readonly MODELS_DIR="/root/Khandaq/soc_models"

log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

mkdir -p "${MODELS_DIR}"

log_step "Checking prerequisites (hf & hf_transfer)..."
if ! command -v huggingface-cli &> /dev/null; then
    log_info "Installing huggingface_hub via pipx..."
    pipx install "huggingface_hub[cli]"
fi

pipx runpip huggingface-hub install hf_transfer || true
export HF_HUB_ENABLE_HF_TRANSFER=1

# =============================================================================
# 1. Strategic Commander (Qwen-2.5-7B) - Long Context & Reasoning
# =============================================================================
log_step "Downloading Strategic Commander: Qwen-2.5-7B-Instruct (GGUF Q4_K_M)..."
huggingface-cli download Qwen/Qwen2.5-7B-Instruct-GGUF --include "*q4_k_m*.gguf" --local-dir "${MODELS_DIR}/Commander-Qwen"

# =============================================================================
# 2. Cyber Analyst (WhiteRabbitNeo-13B) — Cybersecurity-Specialized Tactical Analysis
# =============================================================================
log_step "Downloading Cyber Analyst: WhiteRabbitNeo-13B (GGUF Q4_K_M)..."
huggingface-cli download TheBloke/WhiteRabbitNeo-13B-GGUF --include "*Q4_K_M*.gguf" --local-dir "${MODELS_DIR}/WhiteRabbitNeo-13B"

# =============================================================================
# 3. [REMOVED] Mistral Router — no longer used in Khandaq architecture
# =============================================================================
# log_step "Skipped: Mistral router removed from architecture"

# =============================================================================
# 4. Fast Classifier (SecureBERT) - Initial Filter
# =============================================================================
log_step "Downloading Fast Classifier: SecureBERT..."
huggingface-cli download ehsanaghaei/SecureBERT --local-dir "${MODELS_DIR}/Filter-SecureBERT"

log_info "✅ All architectural models have been successfully downloaded for storage in ${MODELS_DIR}."

