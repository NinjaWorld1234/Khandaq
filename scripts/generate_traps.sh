#!/bin/bash
###############################################################################
# Khandaq Active Defense - Traps Generator
# سكربت توليد فخاخ الدفاع النشط (قنبلة البيانات وملفات التعقب)
#
# Run this script ON THE DECOY VPS before starting the honeypot.
###############################################################################

set -e

echo "============================================================"
echo "💣 Generating Active Defense Traps..."
echo "============================================================"

mkdir -p /root/khandaq-labyrinth/honeyfs/etc
mkdir -p /root/khandaq-labyrinth/honeyfs/root
mkdir -p /root/khandaq-labyrinth/honeyfs/home/admin

# 1. Generate Zip Bomb (Data Bomb)
# We will create a highly compressible file, compress it multiple times.
# When a hacker unzips it on their machine, it will consume hundreds of GBs.
echo "[*] Generating Zip Bomb (Database_Backup_2026.zip)..."
dd if=/dev/zero bs=1M count=1024 | gzip > /tmp/1gb_zero.gz
# We use dd to make a sparse file or just a big file of zeros which compresses tiny
cat /tmp/1gb_zero.gz /tmp/1gb_zero.gz /tmp/1gb_zero.gz /tmp/1gb_zero.gz > /tmp/4gb_zero.gz
zip -j /root/khandaq-labyrinth/honeyfs/root/Database_Backup_2026.zip /tmp/4gb_zero.gz
rm /tmp/1gb_zero.gz /tmp/4gb_zero.gz
echo "[+] Zip Bomb placed in /root directory of the honeypot."

# 2. Setup Canary Token instructions
echo "[*] Generating Canary Token Placeholder..."
cat << 'EOF' > /root/khandaq-labyrinth/honeyfs/root/Financial_Report_Q1.pdf.README.txt
ATTENTION DEPLOYER:
To make the Canary Token work and get an email with the Hacker's real IP:
1. Go to https://canarytokens.org
2. Select "Acrobat Reader PDF Document"
3. Enter your email address and a reminder note (e.g., "Hacker opened decoy PDF").
4. Download the PDF file.
5. Rename it to "Financial_Report_Q1.pdf" and place it in this directory:
   /root/khandaq-labyrinth/honeyfs/root/
6. Delete this README text file.
EOF
echo "[+] Canary token instructions generated."

echo "============================================================"
echo "✅ Traps Generated successfully."
echo "   WARNING: DO NOT unzip Database_Backup_2026.zip on your own machine!"
echo "============================================================"
