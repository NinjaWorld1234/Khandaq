#!/usr/bin/env python3
"""
Khandaq SOC - Memory Maintenance Script
This script cleans up old memories, compresses similar ones, and enforces limits.
It is intended to be run daily via a Cron job.
"""
import sys
import os
import logging

# Add parent dir to path so we can import modules correctly if run directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from agents.memory.memory_service import CyberMemory

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("memory_maintenance")

def run_maintenance():
    logger.info("Starting Daily Memory Maintenance...")
    mem = CyberMemory()
    
    if not mem.enabled:
        logger.warning("CyberMemory is disabled. Exiting.")
        return

    # 1. Enforce size limit first (OOM protection)
    logger.info("1. Enforcing Size Limits...")
    deleted = mem.enforce_size_limit()
    logger.info(f"Size limit enforcement removed {deleted} old points.")

    # 2. Cleanup age > 90 days
    logger.info("2. Cleaning up memories older than 90 days...")
    mem.cleanup_old_memories(max_age_days=90)

    # 3. Compress highly similar incidents (threshold > 0.95)
    logger.info("3. Compressing near-duplicate incidents...")
    compressed = mem.compress_similar(threshold=0.95, batch_size=200)
    logger.info(f"Compression removed {compressed} duplicate points.")

    logger.info("Daily Memory Maintenance Completed Successfully!")

if __name__ == "__main__":
    run_maintenance()
