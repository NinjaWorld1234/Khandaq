import os
import json
import time
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IntelFetcher")

# Destination directory for the intelligence feeds (mapped to docker volume)
DATA_DIR = os.environ.get("INTEL_DATA_DIR", "/data/intel_feeds")

# Global feeds to pull (simulating CrowdSec, MISP, AlienVault)
FEEDS = {
    "crowdsec_blocklist": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "cve_zero_day": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/recent_cves.json", # Simulated
    "darkweb_osint": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
}

def ensure_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created intelligence directory at {DATA_DIR}")

def fetch_feed(name, url):
    logger.info(f"Fetching {name} from {url} ...")
    try:
        # 10 second timeout so we don't hang
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Intel-Fetcher/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            
            # Save the raw file
            file_ext = "json" if "json" in url else "txt"
            filepath = os.path.join(DATA_DIR, f"{name}.{file_ext}")
            
            with open(filepath, "w") as f:
                f.write(content)
                
            logger.info(f"Successfully saved {name} to {filepath} ({len(content)} bytes)")
    except Exception as e:
        logger.error(f"Failed to fetch {name}: {str(e)}")

def generate_metadata():
    """Generates a metadata file telling agents when the feeds were last updated."""
    meta = {
        "last_updated": time.time(),
        "status": "success",
        "feeds": list(FEEDS.keys())
    }
    filepath = os.path.join(DATA_DIR, "metadata.json")
    with open(filepath, "w") as f:
        json.dump(meta, f)
    logger.info(f"Generated metadata at {filepath}")

if __name__ == "__main__":
    logger.info("🫧 Ephemeral Intel Bubble spawned. Starting fetch operations.")
    ensure_dir()
    
    for feed_name, feed_url in FEEDS.items():
        fetch_feed(feed_name, feed_url)
        time.sleep(1) # Be polite to servers
        
    generate_metadata()
    logger.info("🫧 Mission complete. Ephemeral Intel Bubble is now self-destructing.")
