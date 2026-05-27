#!/usr/bin/env python3
"""
SOC Platform - End-to-End Mock Attack Simulator
This script injects a simulated, complex attack into the Redis bus to test
the entire AI pipeline (WhiteRabbitNeo Workers → Qwen Commander → HITL → CrowdSec).
"""

import json
import time
import datetime
import redis
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def inject_mock_attack():
    try:
        r = redis.Redis(host='localhost', port=6379, db=0, password='Ch@ngeMe_Redis_AI_2024!')
        
        # Simulate an advanced persistent threat (APT) pattern
        # 1. Multiple failed SSH logins (Brute Force)
        # 2. Followed by a successful login from a suspicious IP
        # 3. Followed by a sensitive file read (/etc/shadow)
        
        attacker_ip = "185.153.196.15"
        
        attack_events = [
            {
                "type": "ssh_brute_force",
                "source": "w10_port_scan",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "attacker_ip": attacker_ip,
                    "target_port": 22,
                    "failed_attempts": 50,
                    "message": "Repeated SSH login failures detected."
                }
            },
            {
                "type": "suspicious_login",
                "source": "w01_process_behavior",
                "severity": "critical",
                "timestamp": time.time() + 2,
                "details": {
                    "attacker_ip": attacker_ip,
                    "user": "root",
                    "message": "Successful login after brute force attempt."
                }
            },
            {
                "type": "file_access_anomaly",
                "source": "w02_fim_advanced",
                "severity": "critical",
                "timestamp": time.time() + 5,
                "details": {
                    "attacker_ip": attacker_ip,
                    "process": "cat",
                    "file": "/etc/shadow",
                    "message": "Unauthorized access to shadow file."
                }
            }
        ]
        
        logging.info("Injecting Mock Attack Data into Supervisors...")
        
        for event in attack_events:
            source = event["source"]
            if source == "w10_port_scan":
                channel = "soc:network-supervisor"
            elif source == "w01_process_behavior":
                channel = "soc:response-supervisor"
            elif source == "w02_fim_advanced":
                channel = "soc:endpoint-supervisor"
            else:
                channel = "soc:detection-supervisor"

            wrapper = {
                "sender": source,
                "type": "agent_report",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "payload": {
                    "agent_name": source,
                    "agent_description": "Mock Attack Generator",
                    **event
                }
            }
            
            r.publish(channel, json.dumps(wrapper))
            logging.info(f"Injected Event: {event['type']} to {channel}")
            time.sleep(0.5)
            
        logging.info("Mock attack injection complete. Watch the AI agents respond!")
        
    except redis.exceptions.ConnectionError:
        logging.error("Failed to connect to Redis. Make sure Redis is running.")

if __name__ == "__main__":
    inject_mock_attack()

