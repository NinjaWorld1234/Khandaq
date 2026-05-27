#!/bin/bash
# --------------------------------------------------------
# Execute the Ephemeral CrowdSec Intel Puller
# --------------------------------------------------------
# This script builds and runs the docker bubble, mapping a local 
# internal directory as a shared volume.
# The container runs once and immediately destroys itself (--rm).

set -e

# Directory on the HOST machine (Air-Gapped Core) where the intel will be saved
INTERNAL_SHARED_DIR="/var/ossec/etc/lists/crowdsec"

echo "[*] Preparing shared volume directory..."
mkdir -p "$INTERNAL_SHARED_DIR"
chmod 755 "$INTERNAL_SHARED_DIR"

echo "[*] Building the ephemeral docker image (if not exists)..."
docker build -t crowdsec-ephemeral-puller .

echo "[*] Launching the Suicide Container..."
# The --rm flag ensures the container leaves absolutely no trace after exiting
docker run --rm \
  --name crowdsec-puller \
  -v "$INTERNAL_SHARED_DIR:/shared" \
  -e CROWDSEC_CTI_KEY="YOUR_CTI_KEY_HERE" \
  crowdsec-ephemeral-puller

echo "[*] Container destroyed successfully."
echo "[*] Intel data securely written to $INTERNAL_SHARED_DIR/crowdsec_intel.json"
echo "[*] Ready for Wazuh/Qwen consumption."
