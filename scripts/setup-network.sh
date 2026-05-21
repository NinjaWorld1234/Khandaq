#!/usr/bin/env bash
###############################################################################
# SOC Platform — Network Setup Script
# مركز العمليات الأمنية — سكريبت إعداد الشبكة
#
# This script is IDEMPOTENT — safe to run multiple times.
# هذا السكريبت آمن للتشغيل عدة مرات
#
# Actions:
#   1. Creates/verifies Docker networks
#   2. Configures iptables firewall rules
#   3. Prints SPAN/TAP port mirroring instructions
#
# Usage:
#   chmod +x scripts/setup-network.sh
#   sudo ./scripts/setup-network.sh
###############################################################################

set -euo pipefail

# =============================================================================
# Constants & Colors
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

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

# =============================================================================
# Preflight Checks
# =============================================================================
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# =============================================================================
# Step 1: Create Docker Networks
# الخطوة 1: إنشاء شبكات Docker
# =============================================================================
create_docker_networks() {
    log_header "Step 1: Docker Networks / شبكات Docker"

    # Main SOC network (shared by all compose files)
    if docker network inspect soc-net &>/dev/null; then
        log_info "Network 'soc-net' already exists ✓"
    else
        docker network create \
            --driver bridge \
            --subnet 172.30.0.0/16 \
            --gateway 172.30.0.1 \
            --opt com.docker.network.bridge.name=br-soc \
            --opt com.docker.network.bridge.enable_icc=true \
            --opt com.docker.network.bridge.enable_ip_masquerade=true \
            --opt com.docker.network.bridge.host_binding_ipv4=0.0.0.0 \
            --label "project=soc-platform" \
            --label "managed-by=setup-network.sh" \
            soc-net
        log_info "Created network 'soc-net' (172.30.0.0/16) ✓"
    fi

    # Optional: Isolated network for honeypots (T-Pot)
    if docker network inspect soc-honeypot-net &>/dev/null; then
        log_info "Network 'soc-honeypot-net' already exists ✓"
    else
        docker network create \
            --driver bridge \
            --subnet 172.31.0.0/24 \
            --gateway 172.31.0.1 \
            --opt com.docker.network.bridge.name=br-soc-hp \
            --internal=false \
            --label "project=soc-platform" \
            --label "purpose=honeypot-isolation" \
            soc-honeypot-net
        log_info "Created network 'soc-honeypot-net' (172.31.0.0/24) ✓"
    fi

    # Optional: Management network (restricted access)
    if docker network inspect soc-mgmt-net &>/dev/null; then
        log_info "Network 'soc-mgmt-net' already exists ✓"
    else
        docker network create \
            --driver bridge \
            --subnet 172.32.0.0/24 \
            --gateway 172.32.0.1 \
            --opt com.docker.network.bridge.name=br-soc-mgmt \
            --label "project=soc-platform" \
            --label "purpose=management" \
            soc-mgmt-net
        log_info "Created network 'soc-mgmt-net' (172.32.0.0/24) ✓"
    fi

    echo ""
    log_info "Docker networks summary:"
    docker network ls --filter "label=project=soc-platform" --format "  {{.Name}}\t{{.Driver}}\t{{.Scope}}"
}

# =============================================================================
# Step 2: Configure Firewall Rules (iptables)
# الخطوة 2: تكوين قواعد الجدار الناري
# =============================================================================
configure_firewall() {
    log_header "Step 2: Firewall Rules / قواعد الجدار الناري"

    # Check if iptables is available
    if ! command -v iptables &>/dev/null; then
        log_warn "iptables not found. Skipping firewall configuration."
        log_warn "If using ufw or firewalld, configure manually."
        return 0
    fi

    # Create a custom chain for SOC rules (idempotent)
    if ! iptables -L SOC-RULES &>/dev/null 2>&1; then
        iptables -N SOC-RULES
        log_info "Created iptables chain: SOC-RULES"
    else
        # Flush existing SOC rules to rebuild
        iptables -F SOC-RULES
        log_info "Flushed existing SOC-RULES chain"
    fi

    # ── Allow established connections ──
    iptables -A SOC-RULES -m state --state ESTABLISHED,RELATED -j ACCEPT

    # ── Allow loopback ──
    iptables -A SOC-RULES -i lo -j ACCEPT

    # ── Allow SSH (management) ──
    iptables -A SOC-RULES -p tcp --dport 22 -j ACCEPT -m comment --comment "SOC: SSH management"

    # ── SOC Service Ports ──
    # Core
    iptables -A SOC-RULES -p tcp --dport 9200 -j ACCEPT -m comment --comment "SOC: OpenSearch"
    iptables -A SOC-RULES -p tcp --dport 9201 -j ACCEPT -m comment --comment "SOC: OpenSearch Node2"
    iptables -A SOC-RULES -p tcp --dport 5601 -j ACCEPT -m comment --comment "SOC: OpenSearch Dashboards"
    iptables -A SOC-RULES -p tcp --dport 443  -j ACCEPT -m comment --comment "SOC: Wazuh Dashboard"
    iptables -A SOC-RULES -p tcp --dport 1514 -j ACCEPT -m comment --comment "SOC: Wazuh Agent"
    iptables -A SOC-RULES -p tcp --dport 1515 -j ACCEPT -m comment --comment "SOC: Wazuh Registration"
    iptables -A SOC-RULES -p tcp --dport 55000 -j ACCEPT -m comment --comment "SOC: Wazuh API"
    iptables -A SOC-RULES -p udp --dport 514 -j ACCEPT -m comment --comment "SOC: Syslog UDP"

    # Network Monitoring
    iptables -A SOC-RULES -p tcp --dport 9092 -j ACCEPT -m comment --comment "SOC: Kafka"

    # Threat Intelligence
    iptables -A SOC-RULES -p tcp --dport 8443 -j ACCEPT -m comment --comment "SOC: MISP"
    iptables -A SOC-RULES -p tcp --dport 8080 -j ACCEPT -m comment --comment "SOC: OpenCTI"
    iptables -A SOC-RULES -p tcp --dport 8085 -j ACCEPT -m comment --comment "SOC: IntelOwl"
    iptables -A SOC-RULES -p tcp --dport 4433 -j ACCEPT -m comment --comment "SOC: DFIR-IRIS"
    iptables -A SOC-RULES -p tcp --dport 3001 -j ACCEPT -m comment --comment "SOC: Shuffle"

    # Monitoring
    iptables -A SOC-RULES -p tcp --dport 3000 -j ACCEPT -m comment --comment "SOC: Grafana"
    iptables -A SOC-RULES -p tcp --dport 9090 -j ACCEPT -m comment --comment "SOC: Prometheus"
    iptables -A SOC-RULES -p tcp --dport 3002 -j ACCEPT -m comment --comment "SOC: Uptime Kuma"

    # Security Tools
    iptables -A SOC-RULES -p tcp --dport 9392 -j ACCEPT -m comment --comment "SOC: OpenVAS"
    iptables -A SOC-RULES -p tcp --dport 8180 -j ACCEPT -m comment --comment "SOC: Keycloak"
    iptables -A SOC-RULES -p tcp --dport 8000 -j ACCEPT -m comment --comment "SOC: CAPEv2"

    # AI
    iptables -A SOC-RULES -p tcp --dport 11434 -j ACCEPT -m comment --comment "SOC: Ollama"

    # Hook SOC-RULES into INPUT chain (avoid duplicates)
    if ! iptables -C INPUT -j SOC-RULES &>/dev/null 2>&1; then
        iptables -I INPUT 1 -j SOC-RULES
        log_info "Hooked SOC-RULES into INPUT chain ✓"
    fi

    log_info "Firewall rules configured ✓"

    # Save rules if iptables-save is available
    if command -v iptables-save &>/dev/null; then
        local rules_file="/etc/iptables/rules.v4"
        if [ -d "$(dirname "$rules_file")" ]; then
            iptables-save > "$rules_file"
            log_info "Firewall rules saved to ${rules_file} ✓"
        else
            mkdir -p "$(dirname "$rules_file")"
            iptables-save > "$rules_file"
            log_info "Firewall rules saved to ${rules_file} ✓"
        fi
    fi

    echo ""
    log_info "Active SOC firewall rules:"
    iptables -L SOC-RULES -n --line-numbers 2>/dev/null | head -30
}

# =============================================================================
# Step 3: SPAN Port Mirroring Instructions
# الخطوة 3: تعليمات نسخ حركة المرور (SPAN)
# =============================================================================
print_span_instructions() {
    log_header "Step 3: SPAN Port Mirroring / نسخ حركة المرور"

    cat <<'SPANEOF'
══════════════════════════════════════════════════════════════
  SPAN/TAP Port Mirroring Setup Guide
  دليل إعداد نسخ حركة المرور
══════════════════════════════════════════════════════════════

Suricata and Zeek require a network interface that receives a copy
of all network traffic. This is achieved via SPAN (port mirroring)
on your network switch or a physical TAP device.

────────────────────────────────────────────────────────────
Option A: Physical Network TAP (Recommended for Production)
الخيار أ: جهاز TAP فيزيائي (موصى به للإنتاج)
────────────────────────────────────────────────────────────

  1. Install a passive TAP between your core switch and firewall
  2. Connect the TAP's monitor port to a dedicated NIC on this server
  3. Configure the NIC in promiscuous mode:

     ip link set <interface> promisc on
     ip link set <interface> up

  4. Update .env:
     SURICATA_INTERFACE=<interface>
     ZEEK_INTERFACE=<interface>

────────────────────────────────────────────────────────────
Option B: Switch SPAN Port (Cisco)
الخيار ب: منفذ SPAN على سويتش Cisco
────────────────────────────────────────────────────────────

  On your Cisco switch, configure SPAN:

  ! Mirror traffic from VLAN 10 to port Gi0/24
  monitor session 1 source vlan 10 both
  monitor session 1 destination interface GigabitEthernet0/24

  Then connect Gi0/24 to a NIC on this server.

────────────────────────────────────────────────────────────
Option C: Switch SPAN Port (Juniper)
الخيار ج: منفذ SPAN على سويتش Juniper
────────────────────────────────────────────────────────────

  set ethernet-switching-options analyzer mirror1 input ingress vlan servers
  set ethernet-switching-options analyzer mirror1 input egress vlan servers
  set ethernet-switching-options analyzer mirror1 output interface ge-0/0/47

────────────────────────────────────────────────────────────
Option D: Linux Bridge Mirroring (Virtual/Lab)
الخيار د: نسخ عبر جسر لينكس (للمختبرات)
────────────────────────────────────────────────────────────

  If running in a virtual environment, use tc (traffic control):

  # Create a mirror of br0 traffic to eth1
  tc qdisc add dev br0 ingress
  tc filter add dev br0 parent ffff: \
      protocol all u32 match u32 0 0 \
      action mirred egress mirror dev eth1

  # Or use Open vSwitch:
  ovs-vsctl -- set Bridge br0 mirrors=@m \
      -- --id=@p get Port br0 \
      -- --id=@m create Mirror name=span1 select-all=true output-port=@p

────────────────────────────────────────────────────────────
Option E: Proxmox / VMware (Virtual SPAN)
الخيار هـ: Proxmox / VMware (SPAN افتراضي)
────────────────────────────────────────────────────────────

  VMware: Configure port mirroring on the vSwitch/dvSwitch
  Proxmox: Use Open vSwitch with mirror configuration

────────────────────────────────────────────────────────────
Verification / التحقق
────────────────────────────────────────────────────────────

  After configuring mirroring, verify traffic is reaching the interface:

  # Check interface is up and receiving packets
  ip -s link show <interface>

  # Quick packet capture test
  tcpdump -i <interface> -c 10

  # Check Suricata is processing
  docker logs soc-suricata --tail 20

  # Check Zeek is processing
  docker logs soc-zeek --tail 20

══════════════════════════════════════════════════════════════
SPANEOF
}

# =============================================================================
# Step 4: Verify Setup
# الخطوة 4: التحقق من الإعداد
# =============================================================================
verify_setup() {
    log_header "Step 4: Verification / التحقق"

    # Check Docker networks
    echo "Docker Networks:"
    docker network ls --filter "label=project=soc-platform" --format "  ✓ {{.Name}} ({{.Driver}})"
    echo ""

    # Check if soc-net has containers attached
    local container_count
    container_count=$(docker network inspect soc-net --format '{{len .Containers}}' 2>/dev/null || echo "0")
    log_info "Containers on soc-net: ${container_count}"

    # Check network interfaces
    echo ""
    echo "Network Interfaces (potential SPAN targets):"
    ip -o link show | awk '{print "  " $2}' | sed 's/@.*//' | sort
    echo ""

    # Check if iptables rules are active
    if iptables -L SOC-RULES &>/dev/null 2>&1; then
        local rule_count
        rule_count=$(iptables -L SOC-RULES --line-numbers 2>/dev/null | tail -n +3 | wc -l)
        log_info "SOC firewall rules active: ${rule_count} rules ✓"
    else
        log_warn "SOC firewall rules not configured"
    fi

    log_info "Network setup verification complete ✓"
}

# =============================================================================
# Main
# =============================================================================
main() {
    log_header "SOC Network Setup / إعداد شبكة مركز العمليات الأمنية"

    check_root
    create_docker_networks
    configure_firewall
    print_span_instructions
    verify_setup

    log_info "Network setup complete! / اكتمل إعداد الشبكة"
}

main "$@"
