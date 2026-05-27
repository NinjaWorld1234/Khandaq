#!/usr/bin/env bash
###############################################################################
# SOC Platform — Offline CrowdSec Downloader (Naser Server)
# أداة تحميل CrowdSec وملحقاته للتخزين غير المتصل
###############################################################################

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

readonly CROWDSEC_DIR="/root/Khandaq/crowdsec_offline"
readonly CROWDSEC_VERSION="v1.6.2" # Current stable version

log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

mkdir -p "${CROWDSEC_DIR}"
cd "${CROWDSEC_DIR}"

# =============================================================================
# 1. Download CrowdSec Linux Binaries
# =============================================================================
log_step "Downloading CrowdSec Linux Binaries (tar.gz)..."
wget -q --show-progress -c "https://github.com/crowdsecurity/crowdsec/releases/download/${CROWDSEC_VERSION}/crowdsec-release.tgz" -O crowdsec-release.tgz

# =============================================================================
# 2. Download CrowdSec Bouncers (Firewall Bouncer)
# =============================================================================
log_step "Downloading CrowdSec iptables Bouncer..."
wget -q --show-progress -c "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/v0.0.28/crowdsec-firewall-bouncer-linux-amd64.tgz" -O crowdsec-firewall-bouncer.tgz

# =============================================================================
# 3. Download Docker Images for the "Air-Gapped Bubble"
# =============================================================================
log_step "Pulling required Docker Images for offline transport..."
if command -v docker &> /dev/null; then
    log_info "Pulling CrowdSec official Docker image..."
    docker pull crowdsecurity/crowdsec:latest
    docker save crowdsecurity/crowdsec:latest -o crowdsec_docker_image.tar

    log_info "Pulling Python Alpine image (for the Ephemeral Puller Bubble)..."
    docker pull python:3.11-alpine
    docker save python:3.11-alpine -o python_alpine_image.tar
else
    echo "⚠️ Docker is not installed on this server. Skipping Docker image downloads."
    echo "If you need the Docker images, install Docker first or run this on a machine with Docker."
fi

log_info "✅ CrowdSec offline assets have been successfully downloaded to ${CROWDSEC_DIR}."
