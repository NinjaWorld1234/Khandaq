#!/usr/bin/env bash
###############################################################################
# SOC Platform — Offline Docker Images Downloader
# أداة تحميل حاويات الدوكر للعمل في بيئة معزولة (Air-Gapped)
###############################################################################

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

readonly OFFLINE_DIR="/root/Khandaq/soc_offline_images"

log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

mkdir -p "${OFFLINE_DIR}"

IMAGES=(
    # --- SIEM & Data Lake ---
    "wazuh/wazuh-manager:4.9.2"
    "wazuh/wazuh-dashboard:4.9.2"
    "opensearchproject/opensearch:2.17.0"
    "opensearchproject/opensearch-dashboards:2.17.0"
    "timberio/vector:0.40.0-alpine"
    
    # --- AI & Databases ---
    "vllm/vllm-openai:latest"
    "qdrant/qdrant:latest"
    "neo4j:5.14"
    "redis:7-alpine"
    "postgres:16-alpine"
    "python:3.11-slim"
    "python:3.11-alpine"
    
    # --- Network Security & Intel ---
    "jasonish/suricata:7.0.6"
    "zeek/zeek:7.0.0"
    "crowdsecurity/crowdsec:latest"
    "misp/misp-docker:latest"
    "strangebee/thehive:5.2.11"
    "thehiveproject/cortex:3.1.7"
    "blacktop/cuckoo:latest"
    
    # --- Message Brokers ---
    "confluentinc/cp-zookeeper:7.5.0"
    "confluentinc/cp-kafka:7.5.0"
    
    # --- Observability ---
    "prom/prometheus:v2.53.1"
    "grafana/grafana-oss:11.1.0"
    "louislam/uptime-kuma:1.23.13"
    "prom/node-exporter:v1.8.2"
    
    # --- Deception & Honeypots ---
    "cowrie/cowrie:latest"
    "dinotools/dionaea:latest"
    "telekom-security/tpotce:24.04"
    
    # --- Zero Trust & Security ---
    "lscr.io/linuxserver/webtop:ubuntu-xfce"
    "lscr.io/linuxserver/wireguard:latest"
    "cloudflare/cloudflared:latest"
    "netbirdio/netbird:latest"
    "netbirdio/signal:latest"
    "netbirdio/management:latest"
    "quay.io/keycloak/keycloak:25.0.2"
    "greenbone/community-edition:22.4.1"
)

TOTAL_IMAGES=${#IMAGES[@]}
CURRENT=1

log_step "Starting offline download for $TOTAL_IMAGES Docker images..."

for img in "${IMAGES[@]}"; do
    safe_name=$(echo "$img" | tr '/:' '_')
    tar_path="${OFFLINE_DIR}/${safe_name}.tar"

    if [ -f "$tar_path" ]; then
        log_info "[$CURRENT/$TOTAL_IMAGES] Skipping $img - already saved at $tar_path"
    else
        log_info "[$CURRENT/$TOTAL_IMAGES] Pulling $img ..."
        if docker pull "$img"; then
            log_info "Saving $img to $tar_path ..."
            docker save -o "$tar_path" "$img"
            log_info "Cleaning up docker cache for $img to save space..."
            docker rmi "$img" || true
        else
            log_error "Failed to pull $img. Skipping..."
        fi
    fi
    CURRENT=$((CURRENT + 1))
done

log_step "Building custom SOC AI Agents container locally..."
if [ -d "/root/Khandaq/docker" ]; then
    cd /root/Khandaq
    # Assuming there's a Dockerfile for the agents, we build it
    # docker build -t soc-ai-agents:latest -f docker/Dockerfile.agents .
    # docker save -o "${OFFLINE_DIR}/soc-ai-agents_latest.tar" soc-ai-agents:latest
    log_info "Custom AI agents build step prepared."
fi

log_step "Done! All successfully downloaded images are stored in ${OFFLINE_DIR}."
