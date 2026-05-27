#!/bin/bash
###############################################################################
# Khandaq Active Defense - Traps Generator
# سكربت توليد فخاخ الدفاع النشط (ملفات استدراج وتعقب)
#
# Run this script ON THE DECOY VPS before starting the honeypot.
###############################################################################

set -e

echo "============================================================"
echo "💣 Generating Active Defense Traps..."
echo "============================================================"

HONEYFS_DIR="/root/khandaq-labyrinth/tarpit/honeyfs"
mkdir -p $HONEYFS_DIR/etc
mkdir -p $HONEYFS_DIR/root
mkdir -p $HONEYFS_DIR/home/admin

# 1. Generate Fake Credentials (Deception / Sinkholing)
# These files look extremely attractive to an attacker but contain trackable fake data.
echo "[*] Generating Fake Credentials (Database_Backup_2026_Credentials.txt)..."
cat << 'EOF' > $HONEYFS_DIR/root/Database_Backup_2026_Credentials.txt
# MASTER DATABASE EXPORT - STRICTLY CONFIDENTIAL
DB_HOST=10.0.0.99
DB_USER=root
DB_PASS=Sup3rS3cr3tP@ssw0rd!
# If you are reading this, your IP has been logged and contained.
EOF
echo "[+] Fake credentials placed in /root directory of the honeypot."

# 2. Setup Canary Token instructions
echo "[*] Generating Canary Token Placeholder..."
cat << 'EOF' > $HONEYFS_DIR/root/Financial_Report_Q1.pdf.README.txt
ATTENTION DEPLOYER:
To make the Canary Token work and get an email with the Hacker's real IP:
1. Go to https://canarytokens.org
2. Select "Acrobat Reader PDF Document"
3. Enter your email address and a reminder note (e.g., "Hacker opened decoy PDF").
4. Download the PDF file.
5. Rename it to "Financial_Report_Q1.pdf" and place it in this directory:
   $HONEYFS_DIR/root/
6. Delete this README text file.
EOF
echo "[+] Canary token instructions generated."

echo "============================================================"
echo "✅ Traps Generated successfully."
echo "   NOTE: Deception assets are placed. No destructive payloads are included."
echo "============================================================"
