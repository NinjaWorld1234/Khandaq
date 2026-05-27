"""
SOC Platform - Replay Engine & Time Machine
Injects historical packaged incidents into the SOC pipeline for agent training and benchmarking.
Supports Time Compression to accelerate long-running incidents.
"""

import os
import time
import json
import logging
import argparse
import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("soc.replay")

def load_incident(filepath: str) -> list:
    if not os.path.exists(filepath):
        logger.error(f"Incident file not found: {filepath}")
        return []
    with open(filepath, 'r') as f:
        data = json.load(f)
    # Sort by timestamp to ensure chronological replay
    data.sort(key=lambda x: x.get('timestamp', 0))
    return data

def replay_events(events: list, channel: str, max_sleep: float = 5.0):
    """
    Replays a sequence of events. Uses Time Compression by capping the sleep duration.
    """
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    redis_password = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")
    
    try:
        r = redis.Redis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
        r.ping()
        logger.info(f"✅ Connected to Redis at {redis_host}:{redis_port}")
    except Exception as e:
        logger.error(f"❌ Failed to connect to Redis: {e}")
        return

    logger.info(f"Starting replay of {len(events)} events to channel '{channel}'...")
    logger.info(f"Time Compression ACTIVE: Maximum sleep between events is {max_sleep} seconds.")

    last_timestamp = None

    for idx, event in enumerate(events):
        current_ts = event.get("timestamp", 0)
        
        if last_timestamp is not None:
            delta = current_ts - last_timestamp
            if delta > 0:
                # Time compression
                sleep_time = min(delta, max_sleep)
                logger.info(f"Original delay: {delta}s. Compressed delay: {sleep_time:.1f}s. Sleeping...")
                time.sleep(sleep_time)
        
        # Override timestamp to current time so the system accepts it as a live event
        event["original_timestamp"] = current_ts
        event["timestamp"] = time.time()
        event["is_replay"] = True
        
        payload = {
            "source": "replay_engine",
            "payload": event
        }
        
        r.publish(channel, json.dumps(payload))
        logger.info(f"[{idx+1}/{len(events)}] Published event: {event.get('event_type')} from {event.get('src_ip')}")
        
        last_timestamp = current_ts
        
    logger.info("🎉 Replay complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay Engine for SOC Training")
    parser.add_argument("--file", type=str, required=True, help="Path to the JSON incident package")
    parser.add_argument("--channel", type=str, default="soc:raw-alerts", help="Redis channel to publish to")
    parser.add_argument("--max-sleep", type=float, default=5.0, help="Maximum sleep time in seconds (Time Compression)")
    
    args = parser.parse_args()
    
    events = load_incident(args.file)
    if events:
        replay_events(events, args.channel, args.max_sleep)
