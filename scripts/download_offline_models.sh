#!/usr/bin/env bash
###############################################################################
# SOC Platform — Offline AI Models Downloader (Naser Server)
# أداة تحميل النماذج لسيرفر ناصر (التخزين غير المتصل)
#
# هذا السكريبت يقوم بسحب أوزان نماذج الذكاء الاصطناعي المتفق عليها
# وتخزينها محلياً في مجلد (soc_models) لتعمل الحاويات بدون إنترنت.
###############################################################################

set -euo pipefail

# الألوان
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly MODELS_DIR="${PROJECT_DIR}/soc_models"

log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

mkdir -p "${MODELS_DIR}"
cd "${MODELS_DIR}"

log_step "Checking prerequisites (huggingface-cli)..."
if ! command -v huggingface-cli &> /dev/null; then
    log_info "Installing huggingface_hub..."
    pip3 install -U "huggingface_hub[cli]"
fi

# =============================================================================
# 1. القائد والمشرفين (Kimi 2.6-Mini)
# =============================================================================
log_step "Downloading Commander Model: Kimi K2.6-Mini (13B) into Naser Server..."
huggingface-cli download MoonshotAI/Kimi-K2.6-Mini --local-dir "${MODELS_DIR}/Kimi-K2.6-Mini" --local-dir-use-symlinks False

# =============================================================================
# 2. الوكلاء الميدانيين (WhiteRabbitNeo)
# =============================================================================
log_step "Downloading Field Workers Model: WhiteRabbitNeo-13B-v1 into Naser Server..."
huggingface-cli download WhiteRabbitNeo/WhiteRabbitNeo-13B-v1 --local-dir "${MODELS_DIR}/WhiteRabbitNeo-13B-v1" --local-dir-use-symlinks False

# =============================================================================
# 3. محرك التصفية السريع (SecureBERT)
# =============================================================================
log_step "Downloading Fast Filter Model: SecureBERT into Naser Server..."
huggingface-cli download ehsanaghaei/SecureBERT --local-dir "${MODELS_DIR}/SecureBERT" --local-dir-use-symlinks False

log_info "✅ All models have been successfully downloaded into Naser Server storage (${MODELS_DIR})."
log_info "✅ The SOC is now ready to operate in 100% Air-Gapped (Offline) mode."
