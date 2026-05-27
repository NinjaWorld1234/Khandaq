"""
SOC Platform - Lightweight Honeypot Node
Mimics sensitive services (like SSH, RDP) to attract attackers.
Any connection attempt is instantly published as a 100% confidence breach.
"""

import socket
import threading
import logging
import time
import os
import json
import redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("honeypot")

# Configure Redis connection
REDIS_HOST = os.environ.get("REDIS_HOST", "redis-ai")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")
REDIS_CHANNEL = "soc:deception-alerts"

try:
    r_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
    r_client.ping()
    logger.info("✅ Connected to Redis for Alerting.")
except Exception as e:
    logger.error(f"❌ Failed to connect to Redis: {e}")
    r_client = None

def handle_connection(conn, addr, service_name, port):
    """Handles the incoming connection, logs it, and optionally sends a fake banner."""
    client_ip, client_port = addr
    logger.warning(f"🚨 HONEYPOT TRIGGERED! Connection from {client_ip}:{client_port} on port {port} ({service_name})")
    
    # 1. Send High-Fidelity Alert
    if r_client:
        alert = {
            "timestamp": time.time(),
            "source": "honeypot_node",
            "event_type": "deception_triggered",
            "src_ip": client_ip,
            "dst_port": port,
            "service": service_name,
            "message": f"Unauthorized access attempt on Deception Mesh ({service_name})",
            "severity": "CRITICAL",
            "confidence": 1.0
        }
        try:
            r_client.publish(REDIS_CHANNEL, json.dumps({"payload": alert}))
            logger.info(f"Published alert for {client_ip} to {REDIS_CHANNEL}")
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")

    # 2. Fake Interaction (Tarpit)
    try:
        if service_name == "SSH":
            # Send fake SSH banner to keep scanner engaged
            conn.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
            time.sleep(2)
        elif service_name == "RDP":
            # Just hold connection open
            time.sleep(5)
            
        conn.close()
    except Exception:
        pass

def start_listener(port, service_name):
    """Starts a socket listener on the given port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind(("0.0.0.0", port))
        s.listen(5)
        logger.info(f"🍯 Honeypot listening on port {port} ({service_name})")
        
        while True:
            conn, addr = s.accept()
            # Handle connection in a new thread
            t = threading.Thread(target=handle_connection, args=(conn, addr, service_name, port))
            t.daemon = True
            t.start()
    except Exception as e:
        logger.error(f"Failed to start listener on {port}: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    # Define traps
    traps = [
        (2222, "SSH"), # Custom SSH
        (3389, "RDP"), # Windows RDP
        (5900, "VNC")  # VNC Remote Desktop
    ]
    
    threads = []
    for port, service in traps:
        t = threading.Thread(target=start_listener, args=(port, service))
        t.daemon = True
        t.start()
        threads.append(t)
        
    logger.info("Deception Mesh Node Active. Waiting for flies...")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot.")
