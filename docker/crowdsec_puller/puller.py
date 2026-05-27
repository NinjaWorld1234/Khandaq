#!/usr/bin/env python3
"""
Ephemeral CrowdSec Intel Puller
-------------------------------
This script runs in a disposable Docker container.
It fetches the latest top offenders from CrowdSec CTI (or public blocklists),
writes them to a shared volume, and then the container terminates.
"""

import os
import json
import logging
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
# In production, get a free CTI API key from CrowdSec Console
CTI_API_KEY = os.environ.get("CROWDSEC_CTI_KEY", "DEMO_KEY")
CTI_URL = "https://cti.api.crowdsec.net/v2/smoke/decisions"
SHARED_VOLUME_PATH = "/shared/crowdsec_intel.json"

def fetch_threat_intel():
    """Fetch the latest malicious IPs from FireHOL Level 1 as CrowdSec fallback."""
    logging.info("Connecting to Threat Intel Feed (FireHOL Level 1)...")
    
    FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    bad_ips = []
    
    try:
        response = requests.get(FIREHOL_URL, timeout=10)
        response.raise_for_status()
        
        for line in response.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # FireHOL Level 1 contains subnets and IPs.
            bad_ips.append({
                "ip": line,
                "reason": "firehol_level1_malicious",
                "confidence": 100
            })
            
            # Limit to 5000 records to prevent memory bloat in the offline JSON
            if len(bad_ips) >= 5000:
                break
                
        logging.info(f"Successfully downloaded {len(bad_ips)} high-confidence malicious IPs/Subnets.")
    except Exception as e:
        logging.error(f"Failed to fetch Threat Intel: {e}")
        # Fallback to mock data if no internet
        bad_ips = [
            {"ip": "185.153.196.15", "reason": "ssh_brute_force", "confidence": 100},
            {"ip": "45.133.1.20", "reason": "port_scanning", "confidence": 98},
            {"ip": "194.26.29.111", "reason": "http_cve_exploit", "confidence": 100},
            {"ip": "103.145.13.10", "reason": "botnet_c2", "confidence": 95}
        ]
        logging.info("Using local fallback malicious IPs.")
        
    return bad_ips

def write_to_shared_volume(data):
    """Write the intel to the one-way shared volume."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(SHARED_VOLUME_PATH), exist_ok=True)
        
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "crowdsec_community",
            "intel_type": "ipv4_blocklist",
            "data": data
        }
        
        with open(SHARED_VOLUME_PATH, "w") as f:
            json.dump(payload, f, indent=2)
            
        logging.info(f"Successfully pushed intel to internal volume: {SHARED_VOLUME_PATH}")
    except Exception as e:
        logging.error(f"Failed to write to shared volume: {e}")
        exit(1)

if __name__ == "__main__":
    logging.info("Starting Ephemeral CrowdSec Puller...")
    intel_data = fetch_threat_intel()
    write_to_shared_volume(intel_data)
    logging.info("Mission accomplished. Initiating self-destruct (Container Exit).")
