#!/usr/bin/env python3
"""
Human-in-the-Loop (HITL) Authorization Script
سكربت التفويض البشري لقرارات القائد الاستراتيجية.

Usage:
  python authorize.py <auth_id> approve
  python authorize.py <auth_id> reject
"""

import sys
import json
import redis
import os

def main():
    if len(sys.argv) != 3:
        print("Usage: python authorize.py <auth_id> [approve|reject]")
        sys.exit(1)

    auth_id = sys.argv[1]
    decision = sys.argv[2].lower()

    if decision not in ["approve", "reject"]:
        print("Error: Decision must be 'approve' or 'reject'")
        sys.exit(1)

    # Load Redis connection info from environment or defaults
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))

    try:
        r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        # Test connection
        r.ping()
        
        message = {
            "auth_id": auth_id,
            "decision": decision
        }
        
        # Publish to the human auth channel
        r.publish("soc:human-auth", json.dumps(message))
        
        if decision == "approve":
            print(f"[✅] Authorization APPROVED sent to Commander for Action ID: {auth_id}")
        else:
            print(f"[❌] Authorization REJECTED sent to Commander for Action ID: {auth_id}")
            
    except redis.ConnectionError:
        print(f"Error: Could not connect to Redis at {redis_host}:{redis_port}")
        sys.exit(1)
    except Exception as e:
        print(f"Error publishing authorization: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
