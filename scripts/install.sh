#!/usr/bin/env bash
###############################################################################
# SOC Platform — Master Installation Script
# مركز العمليات الأمنية — سكريبت التثبيت الرئيسي
#
# This script is IDEMPOTENT — safe to run multiple times.
# هذا السكريبت آمن للتشغيل عدة مرات
#
# Usage:
#   chmod +x scripts/install.sh
#   sudo ./scripts/install.sh
###############################################################################

set -euo pipefail

# =============================================================================
# Constants & Colors
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly DOCKER_DIR="${PROJECT_DIR}/docker"
readonly ENV_FILE="${PROJECT_DIR}/.env"
readonly ENV_EXAMPLE="${PROJECT_DIR}/.env.example"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*"; }
log_step()    { echo -e "${BLUE}[STEP]${NC}  $(date '+%H:%M:%S') $*"; }
log_header()  {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Generate a random password of specified length (default: 24)
generate_password() {
    local length="${1:-24}"
    # Use /dev/urandom for cryptographically secure passwords
    tr -dc 'A-Za-z0-9!@#%^&*()_+=' < /dev/urandom | head -c "${length}" 2>/dev/null || \
    openssl rand -base64 "${length}" | tr -dc 'A-Za-z0-9' | head -c "${length}"
}

# Generate a UUID v4
generate_uuid() {
    python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null || \
    cat /proc/sys/kernel/random/uuid 2>/dev/null || \
    uuidgen 2>/dev/null || \
    echo "$(generate_password 8)-$(generate_password 4)-$(generate_password 4)-$(generate_password 4)-$(generate_password 12)"
}

# Wait for a service health check with timeout
wait_for_service() {
    local service_name="$1"
    local compose_file="$2"
    local timeout="${3:-300}"
    local elapsed=0

    log_info "Waiting for ${service_name} to become healthy (timeout: ${timeout}s)..."

    while [ $elapsed -lt $timeout ]; do
        local status
        status=$(docker compose -f "${compose_file}" --env-file "${ENV_FILE}" \
                 ps --format json "${service_name}" 2>/dev/null | \
                 python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Health',''))" 2>/dev/null || echo "")

        if [ "$status" = "healthy" ]; then
            log_info "${service_name} is healthy ✓"
            return 0
        fi

        sleep 5
        elapsed=$((elapsed + 5))

        # Print progress every 30 seconds
        if [ $((elapsed % 30)) -eq 0 ]; then
            log_info "  Still waiting for ${service_name}... (${elapsed}/${timeout}s)"
        fi
    done

    log_warn "${service_name} did not become healthy within ${timeout}s (may still be starting)"
    return 1
}

# =============================================================================
# Step 1: Check Prerequisites
# الخطوة 1: فحص المتطلبات
# =============================================================================
check_prerequisites() {
    log_header "Step 1: Checking Prerequisites / فحص المتطلبات"

    local errors=0

    # Check root / sudo
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        log_error "هذا السكريبت يجب تشغيله كمسؤول"
        exit 1
    fi

    # Check Docker
    if command -v docker &>/dev/null; then
        local docker_version
        docker_version=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
        log_info "Docker found: v${docker_version} ✓"
    else
        log_error "Docker is not installed. Install from: https://docs.docker.com/engine/install/"
        errors=$((errors + 1))
    fi

    # Check Docker Compose (v2 plugin)
    if docker compose version &>/dev/null; then
        local compose_version
        compose_version=$(docker compose version --short 2>/dev/null || docker compose version | grep -oP '\d+\.\d+\.\d+' | head -1)
        log_info "Docker Compose found: v${compose_version} ✓"
    else
        log_error "Docker Compose v2 is not installed. Install the docker-compose-plugin package."
        errors=$((errors + 1))
    fi

    # Check Python 3.11+
    if command -v python3 &>/dev/null; then
        local python_version
        python_version=$(python3 --version | grep -oP '\d+\.\d+')
        local python_major python_minor
        python_major=$(echo "$python_version" | cut -d. -f1)
        python_minor=$(echo "$python_version" | cut -d. -f2)

        if [ "$python_major" -ge 3 ] && [ "$python_minor" -ge 11 ]; then
            log_info "Python found: v${python_version} ✓"
        else
            log_warn "Python ${python_version} found, but 3.11+ recommended"
        fi
    else
        log_warn "Python3 not found. AI agents will require Python 3.11+"
    fi

    # Check system resources
    local total_mem_kb
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_mem_gb=$((total_mem_kb / 1024 / 1024))
    if [ "$total_mem_gb" -ge 32 ]; then
        log_info "System RAM: ${total_mem_gb} GB ✓"
    elif [ "$total_mem_gb" -ge 16 ]; then
        log_warn "System RAM: ${total_mem_gb} GB (32+ GB recommended for full stack)"
    else
        log_error "System RAM: ${total_mem_gb} GB (minimum 16 GB required)"
        errors=$((errors + 1))
    fi

    # Check vm.max_map_count (required for OpenSearch)
    local max_map_count
    max_map_count=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
    if [ "$max_map_count" -ge 262144 ]; then
        log_info "vm.max_map_count: ${max_map_count} ✓"
    else
        log_warn "vm.max_map_count is ${max_map_count} (must be >= 262144)"
        log_info "Setting vm.max_map_count=262144..."
        sysctl -w vm.max_map_count=262144
        if ! grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null; then
            echo "vm.max_map_count=262144" >> /etc/sysctl.conf
        fi
        log_info "vm.max_map_count configured ✓"
    fi

    # Check for NVIDIA GPU (optional)
    if command -v nvidia-smi &>/dev/null; then
        local gpu_info
        gpu_info=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        log_info "NVIDIA GPU found: ${gpu_info} ✓ (vLLM will use GPU acceleration)"
    else
        log_warn "No NVIDIA GPU detected. vLLM requires a GPU for production deployment."
    fi

    if [ "$errors" -gt 0 ]; then
        log_error "${errors} prerequisite check(s) failed. Please fix and re-run."
        exit 1
    fi

    log_info "All prerequisites satisfied ✓"
}

# =============================================================================
# Step 2: Create Directory Structure
# الخطوة 2: إنشاء هيكل المجلدات
# =============================================================================
create_directories() {
    log_header "Step 2: Creating Directories / إنشاء المجلدات"

    local dirs=(
        "${PROJECT_DIR}/config/opensearch"
        "${PROJECT_DIR}/config/wazuh"
        "${PROJECT_DIR}/config/suricata"
        "${PROJECT_DIR}/config/zeek"
        "${PROJECT_DIR}/config/vector"
        "${PROJECT_DIR}/config/grafana/dashboards"
        "${PROJECT_DIR}/config/grafana/provisioning/datasources"
        "${PROJECT_DIR}/config/grafana/provisioning/dashboards"
        "${PROJECT_DIR}/config/prometheus"
        "${PROJECT_DIR}/config/keycloak"
        "${PROJECT_DIR}/agents"
        "${PROJECT_DIR}/rules/sigma"
        "${PROJECT_DIR}/rules/yara"
        "${PROJECT_DIR}/rules/suricata"
        "${PROJECT_DIR}/playbooks"
        "${PROJECT_DIR}/data"
    )

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created: ${dir#${PROJECT_DIR}/}"
        else
            log_info "Exists:  ${dir#${PROJECT_DIR}/}"
        fi
    done

    # Create default config files if they don't exist

    # Prometheus config
    if [ ! -f "${PROJECT_DIR}/config/prometheus/prometheus.yml" ]; then
        cat > "${PROJECT_DIR}/config/prometheus/prometheus.yml" <<'PROMEOF'
# Prometheus configuration for SOC Platform
# إعدادات بروميثيوس لمركز العمليات الأمنية
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'opensearch'
    metrics_path: '/_prometheus/metrics'
    static_configs:
      - targets: ['opensearch-node1:9200', 'opensearch-node2:9200']

  - job_name: 'vector'
    static_configs:
      - targets: ['vector:8686']
PROMEOF
        log_info "Created default Prometheus config"
    fi

    # Vector config
    if [ ! -f "${PROJECT_DIR}/config/vector/vector.yaml" ]; then
        cat > "${PROJECT_DIR}/config/vector/vector.yaml" <<'VECEOF'
# Vector configuration for SOC Platform
# إعدادات فيكتور لمركز العمليات الأمنية

api:
  enabled: true
  address: "0.0.0.0:8686"

sources:
  # Read Suricata EVE JSON logs
  suricata_logs:
    type: file
    include:
      - /var/log/suricata/eve.json
    read_from: beginning

  # Read Zeek JSON logs
  zeek_logs:
    type: file
    include:
      - /opt/zeek/logs/current/*.log
    read_from: beginning

transforms:
  # Parse Suricata JSON
  parse_suricata:
    type: remap
    inputs:
      - suricata_logs
    source: |
      . = parse_json!(.message)
      .source = "suricata"

  # Parse Zeek JSON
  parse_zeek:
    type: remap
    inputs:
      - zeek_logs
    source: |
      . = parse_json!(.message)
      .source = "zeek"

sinks:
  # Forward to Kafka
  kafka_suricata:
    type: kafka
    inputs:
      - parse_suricata
    bootstrap_servers: "kafka:29092"
    topic: "soc-suricata"
    encoding:
      codec: json

  kafka_zeek:
    type: kafka
    inputs:
      - parse_zeek
    bootstrap_servers: "kafka:29092"
    topic: "soc-zeek"
    encoding:
      codec: json

  # Also forward to OpenSearch directly
  opensearch_all:
    type: elasticsearch
    inputs:
      - parse_suricata
      - parse_zeek
    endpoints:
      - "http://opensearch-node1:9200"
    bulk:
      index: "soc-network-logs-%Y.%m.%d"
VECEOF
        log_info "Created default Vector config"
    fi

    # Create a placeholder Dockerfile for AI agents
    if [ ! -f "${PROJECT_DIR}/agents/Dockerfile" ]; then
        cat > "${PROJECT_DIR}/agents/Dockerfile" <<'DOCKEOF'
###############################################################################
# SOC AI Agents — Docker Image
# وكلاء الذكاء الاصطناعي — صورة Docker
###############################################################################

FROM python:3.11-slim

LABEL maintainer="SOC Team"
LABEL description="SOC Platform AI Agents - 52 specialized security agents"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent source code
COPY . /app

# Create data and logs directories
RUN mkdir -p /app/data /app/logs

# Expose health check port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD curl -sf http://localhost:8000/health || exit 1

# Run the agent orchestrator
CMD ["python", "-m", "soc_agents.main"]
DOCKEOF
        log_info "Created placeholder agents/Dockerfile"
    fi

    # Create placeholder requirements.txt for AI agents
    if [ ! -f "${PROJECT_DIR}/agents/requirements.txt" ]; then
        cat > "${PROJECT_DIR}/agents/requirements.txt" <<'REQEOF'
# SOC AI Agents Python Dependencies
# تبعيات Python لوكلاء الذكاء الاصطناعي
fastapi>=0.104.0
uvicorn>=0.24.0
redis>=5.0.0
httpx>=0.25.0
opensearch-py>=2.4.0
pydantic>=2.5.0
python-dotenv>=1.0.0
structlog>=23.2.0
REQEOF
        log_info "Created placeholder agents/requirements.txt"
    fi

    # Create .gitignore
    if [ ! -f "${PROJECT_DIR}/.gitignore" ]; then
        cat > "${PROJECT_DIR}/.gitignore" <<'GITEOF'
# Environment files (contain secrets)
.env
*.env.local

# Data directories
data/

# Logs
*.log
logs/

# Python
__pycache__/
*.pyc
*.pyo
.venv/
venv/

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db
GITEOF
        log_info "Created .gitignore"
    fi
}

# =============================================================================
# Step 3: Set Permissions
# الخطوة 3: ضبط الصلاحيات
# =============================================================================
set_permissions() {
    log_header "Step 3: Setting Permissions / ضبط الصلاحيات"

    # Make scripts executable
    chmod +x "${SCRIPT_DIR}"/*.sh 2>/dev/null || true
    log_info "Scripts marked as executable ✓"

    # Set proper ownership for data directories
    # OpenSearch requires UID 1000
    if [ -d "${PROJECT_DIR}/data/opensearch" ]; then
        chown -R 1000:1000 "${PROJECT_DIR}/data/opensearch" 2>/dev/null || true
    fi

    # Set restrictive permissions on config files
    chmod 600 "${ENV_FILE}" 2>/dev/null || true
    log_info "Permissions configured ✓"
}

# =============================================================================
# Step 4: Generate Passwords & .env File
# الخطوة 4: توليد كلمات المرور وملف البيئة
# =============================================================================
generate_env_file() {
    log_header "Step 4: Generating .env File / توليد ملف البيئة"

    if [ -f "${ENV_FILE}" ]; then
        log_warn ".env file already exists. Backing up to .env.backup"
        cp "${ENV_FILE}" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    fi

    # Generate secure passwords
    local opensearch_pw="$(generate_password 20)"
    local wazuh_api_pw="$(generate_password 20)"
    local wazuh_dash_pw="$(generate_password 20)"
    local misp_pw="$(generate_password 20)"
    local misp_mysql_pw="$(generate_password 20)"
    local opencti_pw="$(generate_password 20)"
    local opencti_token="$(generate_uuid)"
    local opencti_hc_key="$(generate_password 16)"
    local rabbitmq_pw="$(generate_password 20)"
    local iris_pw="$(generate_password 20)"
    local iris_secret="$(generate_password 32)"
    local grafana_pw="$(generate_password 20)"
    local openvas_pw="$(generate_password 20)"
    local keycloak_pw="$(generate_password 20)"
    local kc_db_pw="$(generate_password 20)"
    local redis_ai_pw="$(generate_password 20)"

    # Detect host IP
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    host_ip="${host_ip:-192.168.1.100}"

    # Create .env from template with generated passwords
    if [ -f "${ENV_EXAMPLE}" ]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    else
        touch "${ENV_FILE}"
    fi

    # Write generated values using sed replacements
    cat > "${ENV_FILE}" <<ENVEOF
###############################################################################
# SOC Platform — Generated Environment Variables
# Generated on: $(date -Iseconds)
# !! DO NOT COMMIT THIS FILE TO VERSION CONTROL !!
# !! لا ترفع هذا الملف إلى نظام التحكم بالإصدارات !!
###############################################################################

# General
HOST_IP=${host_ip}
COMPOSE_PROJECT_NAME=soc
TZ=Asia/Riyadh

# OpenSearch
OPENSEARCH_VERSION=2.17.0
OPENSEARCH_INITIAL_ADMIN_PASSWORD=${opensearch_pw}
OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g
OPENSEARCH_NODE1_PORT=9200
OPENSEARCH_NODE2_PORT=9201
OPENSEARCH_DASHBOARDS_PORT=5601
OPENSEARCH_SECURITY_ENABLED=false
OPENSEARCH_MEM_LIMIT=4g
OPENSEARCH_MEM_RESERVATION=2g

# Wazuh
WAZUH_VERSION=4.9.2
WAZUH_MANAGER_PORT=1514
WAZUH_REGISTRATION_PORT=1515
WAZUH_API_PORT=55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=${wazuh_api_pw}
WAZUH_DASHBOARD_PORT=443
WAZUH_DASHBOARD_USER=admin
WAZUH_DASHBOARD_PASSWORD=${wazuh_dash_pw}
WAZUH_MEM_LIMIT=2g

# Suricata & Zeek
SURICATA_INTERFACE=eth0
SURICATA_HOME_NET=192.168.0.0/16
ZEEK_INTERFACE=eth0

# Kafka
KAFKA_VERSION=7.5.0
KAFKA_BROKER_PORT=9092
KAFKA_BROKER_ID=1
KAFKA_HEAP_OPTS=-Xms512m -Xmx1g
ZOOKEEPER_PORT=2181
KAFKA_MEM_LIMIT=2g

# MISP
MISP_PORT=8443
MISP_ADMIN_EMAIL=admin@admin.test
MISP_ADMIN_PASSWORD=${misp_pw}
MISP_BASEURL=https://${host_ip}:8443
MYSQL_MISP_PASSWORD=${misp_mysql_pw}

# OpenCTI
OPENCTI_VERSION=6.3.0
OPENCTI_PORT=8080
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=${opencti_pw}
OPENCTI_ADMIN_TOKEN=${opencti_token}
OPENCTI_HEALTHCHECK_KEY=${opencti_hc_key}
REDIS_OPENCTI_PORT=6380
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=${rabbitmq_pw}
RABBITMQ_PORT=5672
RABBITMQ_MGMT_PORT=15672
ELASTIC_OPENCTI_PORT=9210

# IntelOwl
INTELOWL_PORT=8085

# DFIR-IRIS
IRIS_PORT=4433
IRIS_ADMIN_PASSWORD=${iris_pw}
IRIS_SECRET_KEY=${iris_secret}

# Shuffle
SHUFFLE_BACKEND_PORT=5001
SHUFFLE_FRONTEND_PORT=3001
SHUFFLE_ORBORUS_PORT=5002
SHUFFLE_APP_HOTLOAD_FOLDER=./data/shuffle/apps
SHUFFLE_FILE_LOCATION=./data/shuffle/files

# Grafana
GRAFANA_PORT=3000
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=${grafana_pw}
GRAFANA_MEM_LIMIT=512m

# Prometheus
PROMETHEUS_PORT=9090
PROMETHEUS_RETENTION=30d

# Uptime Kuma
UPTIME_KUMA_PORT=3002

# CAPEv2
CAPEV2_WEB_PORT=8000

# OpenVAS
OPENVAS_PORT=9392
OPENVAS_ADMIN_PASSWORD=${openvas_pw}

# Keycloak
KEYCLOAK_PORT=8180
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=${keycloak_pw}
KC_DB_PASSWORD=${kc_db_pw}

# T-Pot
TPOT_WEB_PORT=64297

# vLLM
VLLM_COMMANDER_PORT=8000
VLLM_WORKER_PORT=8001
VLLM_COMMANDER_MODEL=MoonshotAI/Kimi-K2.6-Mini
VLLM_WORKER_MODEL=WhiteRabbitNeo/WhiteRabbitNeo-13B-v1

# Redis (AI Agents)
REDIS_AI_PORT=6379
REDIS_AI_PASSWORD=${redis_ai_pw}

# AI Agents
AI_AGENTS_LOG_LEVEL=INFO
AI_AGENTS_WORKERS=51
ENVEOF

    chmod 600 "${ENV_FILE}"
    log_info "Generated .env file with secure passwords ✓"
    log_info "File: ${ENV_FILE}"
}

# =============================================================================
# Step 5: Create Docker Network
# الخطوة 5: إنشاء شبكة Docker
# =============================================================================
create_network() {
    log_header "Step 5: Creating Docker Network / إنشاء شبكة Docker"

    if docker network inspect soc-net &>/dev/null; then
        log_info "Docker network 'soc-net' already exists ✓"
    else
        docker network create \
            --driver bridge \
            --subnet 172.30.0.0/16 \
            --gateway 172.30.0.1 \
            --opt com.docker.network.bridge.name=br-soc \
            soc-net
        log_info "Created Docker network 'soc-net' (172.30.0.0/16) ✓"
    fi
}

# =============================================================================
# Step 6: Pull Docker Images
# الخطوة 6: تحميل صور Docker
# =============================================================================
pull_images() {
    log_header "Step 6: Pulling Docker Images / تحميل صور Docker"
    log_info "This may take a while depending on network speed..."
    log_info "قد يستغرق هذا بعض الوقت حسب سرعة الشبكة..."

    local compose_files=(
        "${DOCKER_DIR}/docker-compose.core.yml"
        "${DOCKER_DIR}/docker-compose.network.yml"
        "${DOCKER_DIR}/docker-compose.intel.yml"
        "${DOCKER_DIR}/docker-compose.monitor.yml"
        "${DOCKER_DIR}/docker-compose.security.yml"
        "${DOCKER_DIR}/docker-compose.ai.yml"
    )

    for compose_file in "${compose_files[@]}"; do
        local basename
        basename=$(basename "$compose_file" .yml | sed 's/docker-compose\.//')
        log_step "Pulling images for: ${basename}"

        docker compose -f "${compose_file}" --env-file "${ENV_FILE}" pull --ignore-buildable 2>&1 | \
            grep -v "^$" | head -20 || true
    done

    log_info "All images pulled ✓"
}

# =============================================================================
# Step 7: Start Services in Order
# الخطوة 7: بدء الخدمات بالترتيب
# =============================================================================
start_services() {
    log_header "Step 7: Starting Services / بدء الخدمات"

    # --- Stage 1: Core Services ---
    log_step "Stage 1/4: Starting Core Services (OpenSearch, Wazuh)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.core.yml" \
        --env-file "${ENV_FILE}" up -d

    # Wait for OpenSearch to be ready before proceeding
    wait_for_service "opensearch-node1" "${DOCKER_DIR}/docker-compose.core.yml" 300 || true
    wait_for_service "wazuh-manager" "${DOCKER_DIR}/docker-compose.core.yml" 300 || true
    log_info "Core services started ✓"

    # --- Stage 2: Network Monitoring ---
    log_step "Stage 2/4: Starting Network Monitoring (Kafka, Vector)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.network.yml" \
        --env-file "${ENV_FILE}" up -d

    wait_for_service "kafka" "${DOCKER_DIR}/docker-compose.network.yml" 120 || true
    log_info "Network monitoring started ✓"

    # --- Stage 3: Threat Intelligence ---
    log_step "Stage 3/4: Starting Threat Intelligence (MISP, OpenCTI, DFIR-IRIS, Shuffle)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.intel.yml" \
        --env-file "${ENV_FILE}" up -d

    log_info "Threat intel services started (will continue initializing in background) ✓"

    # --- Stage 4: Monitoring ---
    log_step "Stage 4/4: Starting Monitoring (Grafana, Prometheus, Uptime Kuma)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.monitor.yml" \
        --env-file "${ENV_FILE}" up -d

    log_info "Monitoring services started ✓"

    # --- Optional: AI Agents ---
    log_step "Starting AI Agents infrastructure (vLLM, Redis)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.ai.yml" \
        --env-file "${ENV_FILE}" up -d --no-build 2>/dev/null || \
    log_warn "AI agents stack may require manual build: docker compose -f docker/docker-compose.ai.yml build"

    # --- Optional: Security Tools ---
    log_step "Starting Security Tools (OpenVAS, Keycloak)..."
    docker compose -f "${DOCKER_DIR}/docker-compose.security.yml" \
        --env-file "${ENV_FILE}" up -d 2>/dev/null || \
    log_warn "Some security tools may require additional setup."
}

# =============================================================================
# Step 8: Print Summary
# الخطوة 8: طباعة الملخص
# =============================================================================
print_summary() {
    # Read values from .env
    source "${ENV_FILE}"

    log_header "Installation Complete! / اكتمل التثبيت"

    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          SOC Platform — Service Access URLs                ║${NC}"
    echo -e "${GREEN}║          مركز العمليات الأمنية — روابط الوصول              ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}OpenSearch Dashboards${NC}  http://${HOST_IP}:${OPENSEARCH_DASHBOARDS_PORT}       ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Wazuh Dashboard${NC}        https://${HOST_IP}:${WAZUH_DASHBOARD_PORT}         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Grafana${NC}                http://${HOST_IP}:${GRAFANA_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}MISP${NC}                   https://${HOST_IP}:${MISP_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}OpenCTI${NC}                http://${HOST_IP}:${OPENCTI_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}DFIR-IRIS${NC}              https://${HOST_IP}:${IRIS_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Shuffle (SOAR)${NC}         http://${HOST_IP}:${SHUFFLE_FRONTEND_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Uptime Kuma${NC}            http://${HOST_IP}:${UPTIME_KUMA_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Prometheus${NC}             http://${HOST_IP}:${PROMETHEUS_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Keycloak${NC}               http://${HOST_IP}:${KEYCLOAK_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}OpenVAS${NC}                https://${HOST_IP}:${OPENVAS_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}vLLM Commander${NC}         http://${HOST_IP}:${VLLM_COMMANDER_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}vLLM Worker${NC}            http://${HOST_IP}:${VLLM_WORKER_PORT}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  Credentials are stored in: ${ENV_FILE}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  كلمات المرور محفوظة في ملف .env                              ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT NOTES:${NC}"
    echo -e "  1. Some services (MISP, OpenCTI, OpenVAS) may take 5-10 minutes to fully initialize."
    echo -e "  2. Check service status: docker compose -f docker/<compose-file> ps"
    echo -e "  3. View logs: docker compose -f docker/<compose-file> logs -f <service>"
    echo -e "  4. Security tools stack is optional — start separately if needed."
    echo -e "  5. Configure Suricata/Zeek interfaces in .env (SURICATA_INTERFACE, ZEEK_INTERFACE)."
    echo ""
    echo -e "${GREEN}SOC Platform is ready! / مركز العمليات الأمنية جاهز!${NC}"
    echo ""
}

# =============================================================================
# Main Execution
# التنفيذ الرئيسي
# =============================================================================
main() {
    log_header "SOC Platform Installer / مثبت مركز العمليات الأمنية"
    log_info "Project directory: ${PROJECT_DIR}"
    log_info "Starting installation at $(date -Iseconds)"

    check_prerequisites
    create_directories
    generate_env_file
    set_permissions
    create_network
    pull_images
    start_services
    print_summary
}

# Run main
main "$@"
