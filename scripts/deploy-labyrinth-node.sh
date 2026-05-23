#!/bin/bash
###############################################################################
# Khandaq Labyrinth Node Deployment Script
# سكربت النشر السريع لإنشاء خوادم وهمية (مصائد)
#
# Run this script ON THE DECOY VPS (e.g., Germany/Netherlands server).
# قم بتشغيل هذا السكربت على الخادم الوهمي الخارجي (التمويهي).
###############################################################################

set -e

echo "============================================================"
echo "🏰 Initializing Khandaq Labyrinth Node (Decoy Server)"
echo "============================================================"

# 1. Change Real SSH Port to 2222 to free Port 22 for Cowrie Honeypot
echo "[*] Moving real SSH daemon to port 2222 to free port 22 for honeypots..."
sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/^Port 22/Port 2222/' /etc/ssh/sshd_config
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    echo "Port 2222" >> /etc/ssh/sshd_config
fi
systemctl restart ssh || systemctl restart sshd
echo "[+] Real SSH moved to port 2222. (Make sure you use -p 2222 for future logins!)"

# 2. Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker and Docker Compose..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
else
    echo "[+] Docker is already installed."
fi

# 3. Create directories and config files
echo "[*] Preparing Labyrinth Compose File..."
mkdir -p /root/khandaq-labyrinth
cd /root/khandaq-labyrinth

# Note: The deployer should have already SCP'd docker-compose.labyrinth-node.yml to this folder.
# We assume it's here or we can just fetch it if it was hosted somewhere, but for air-gapped security
# it's better to SCP the file from the main machine.
if [ ! -f "docker-compose.labyrinth-node.yml" ]; then
    echo "[!] Warning: docker-compose.labyrinth-node.yml not found in /root/khandaq-labyrinth."
    echo "    Please copy it from the soc-system/docker/ directory."
    exit 1
fi

# 4. Start the Labyrinth Node
echo "[*] Launching Decoy Services (WireGuard, Cowrie, Dionaea)..."
docker compose -f docker-compose.labyrinth-node.yml up -d

echo "============================================================"
echo "✅ Labyrinth Node Deployed Successfully!"
echo "   Honeypots are now actively listening on ports 22, 23, 80, 443, 445..."
echo "   WireGuard is waiting for Khandaq's connection on port 51820 (UDP)."
echo ""
echo "   Next Steps:"
echo "   1. Find the client WireGuard config inside:"
echo "      /root/khandaq-labyrinth/labyrinth-wg-config/peer_khandaq-core/peer_khandaq-core.conf"
echo "   2. Copy that config file back to your MAIN Khandaq server."
echo "   3. Place it in /soc-system/docker/config/wireguard-client/wg0.conf"
echo "   4. Start docker-compose.dark-server.yml on Khandaq."
echo "============================================================"
