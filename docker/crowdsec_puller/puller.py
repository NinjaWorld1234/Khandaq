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
    """Fetch the latest malicious IPs from CrowdSec."""
    logging.info("Connecting to CrowdSec CTI...")
    
    # Mocking the fetch for demonstration. In reality, you'd pass the API key in headers:
    # headers = {"x-api-key": CTI_API_KEY}
    # response = requests.get(CTI_URL, headers=headers)
    
    # For this Air-Gapped demo, we simulate fetching a list of known bad IPs.
    # Replace this block with actual requests.get() logic.
    mock_bad_ips = [
        {"ip": "185.153.196.15", "reason": "ssh_brute_force", "confidence": 100},
        {"ip": "45.133.1.20", "reason": "port_scanning", "confidence": 98},
        {"ip": "194.26.29.111", "reason": "http_cve_exploit", "confidence": 100},
        {"ip": "103.145.13.10", "reason": "botnet_c2", "confidence": 95}
    ]
    
    logging.info(f"Successfully downloaded {len(mock_bad_ips)} high-confidence malicious IPs.")
    return mock_bad_ips

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
