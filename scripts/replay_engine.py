#!/usr/bin/env python3
"""
SOC Platform — Incident Replay Engine (آلة الزمن)
Packages past incidents from OpenSearch and replays them through the AI pipeline.

Usage:
    # Package an incident from the last 60 minutes
    python replay_engine.py package --minutes 60 --output incident_2024.json

    # Replay a packaged incident
    python replay_engine.py replay --input incident_2024.json

    # Replay in shadow mode (no real actions)
    python replay_engine.py replay --input incident_2024.json --shadow

    # Compare shadow results with original decisions
    python replay_engine.py compare --shadow-log shadow_results.log --original incident_2024.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis

# Add agents path for shared imports
sys.path.insert(0, str(Path(__file__).parent.parent / "agents"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("soc.replay_engine")


# ---------------------------------------------------------------------------
# Configuration / الإعدادات
# ---------------------------------------------------------------------------

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")

OPENSEARCH_HOSTS = os.environ.get("OPENSEARCH_HOSTS", "https://localhost:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "admin")


# ---------------------------------------------------------------------------
# Incident Packager / محزّم الحوادث
# ---------------------------------------------------------------------------

class IncidentPackager:
    """
    Extracts events from OpenSearch and packages them as a replayable JSON file.
    يسحب الأحداث من OpenSearch ويحفظها كملف JSON قابل لإعادة التشغيل
    """

    def __init__(self) -> None:
        try:
            from opensearchpy import OpenSearch
            self.os_client = OpenSearch(
                hosts=[OPENSEARCH_HOSTS],
                http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
                verify_certs=False,
                ssl_show_warn=False,
            )
        except ImportError:
            logger.error("opensearch-py not installed. Run: pip install opensearch-py")
            self.os_client = None
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            self.os_client = None

    def package(
        self,
        minutes: int = 60,
        index: str = "wazuh-alerts-*",
        severity_filter: Optional[str] = None,
        max_events: int = 5000,
    ) -> Dict[str, Any]:
        """
        Package events from the last N minutes into a replayable incident.

        Returns:
            Dict with metadata and ordered events list.
        """
        if not self.os_client:
            logger.error("OpenSearch client not available.")
            return {"events": [], "metadata": {}}

        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=minutes)

        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since.isoformat(), "lte": now.isoformat()}}},
                ],
            }
        }

        if severity_filter:
            query["bool"]["must"].append(
                {"term": {"rule.level": int(severity_filter)}}
            )

        try:
            result = self.os_client.search(
                index=index,
                body={
                    "query": query,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "size": max_events,
                },
            )
            events = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.error(f"OpenSearch query failed: {e}")
            events = []

        # Extract relative timestamps (offsets from first event)
        if events:
            first_ts = events[0].get("@timestamp", "")
            try:
                first_dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                first_dt = now

            for event in events:
                try:
                    evt_ts = event.get("@timestamp", "")
                    evt_dt = datetime.fromisoformat(evt_ts.replace("Z", "+00:00"))
                    event["_replay_offset_ms"] = int((evt_dt - first_dt).total_seconds() * 1000)
                except (ValueError, AttributeError):
                    event["_replay_offset_ms"] = 0

        package = {
            "metadata": {
                "packaged_at": now.isoformat(),
                "source_index": index,
                "time_range_minutes": minutes,
                "total_events": len(events),
                "first_timestamp": events[0].get("@timestamp") if events else None,
                "last_timestamp": events[-1].get("@timestamp") if events else None,
            },
            "events": events,
        }

        logger.info(f"📦 Packaged {len(events)} events from the last {minutes} minutes.")
        return package


# ---------------------------------------------------------------------------
# Incident Replayer / مُعيد التشغيل
# ---------------------------------------------------------------------------

class IncidentReplayer:
    """
    Replays a packaged incident through the SOC Redis pipeline.
    يُعيد تشغيل حادثة محفوظة عبر ناقل Redis للوكلاء
    """

    def __init__(self, shadow_mode: bool = False) -> None:
        self.shadow_mode = shadow_mode
        try:
            self.redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                db=0,
                decode_responses=True,
            )
            self.redis_client.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    def replay(
        self,
        package: Dict[str, Any],
        speed_multiplier: float = 1.0,
        target_channel: str = "soc:endpoint-supervisor",
    ) -> Dict[str, Any]:
        """
        Replay events into the SOC pipeline with original time spacing.

        Args:
            package: The incident package dict (from IncidentPackager).
            speed_multiplier: 1.0 = real-time, 2.0 = 2x speed, 0.5 = half speed.
            target_channel: Redis channel to publish events to.

        Returns:
            Summary of the replay.
        """
        if not self.redis_client:
            return {"error": "Redis not available"}

        events = package.get("events", [])
        if not events:
            logger.warning("No events to replay.")
            return {"replayed": 0}

        # Set shadow mode environment variable if requested
        if self.shadow_mode:
            logger.warning("🌑 SHADOW MODE — Actions will be logged but NOT executed.")
            self.redis_client.set("soc:shadow_mode", "true")

        logger.info(f"▶️ Replaying {len(events)} events at {speed_multiplier}x speed...")
        replayed = 0

        for i, event in enumerate(events):
            # Calculate delay from original timestamps
            if i > 0:
                delay_ms = event.get("_replay_offset_ms", 0) - events[i - 1].get("_replay_offset_ms", 0)
                delay_sec = max(0, (delay_ms / 1000.0) / speed_multiplier)
                if delay_sec > 0 and delay_sec < 30:  # Cap at 30 seconds
                    time.sleep(delay_sec)

            # Determine target channel based on event source/type
            channel = self._route_event(event, target_channel)

            # Wrap event in standard SOC message format
            wrapper = {
                "sender": "replay_engine",
                "type": "replayed_event",
                "replay_mode": True,
                "shadow_mode": self.shadow_mode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "original_timestamp": event.get("@timestamp"),
                "payload": {
                    "agent_name": "replay_engine",
                    "agent_description": "Incident Replay Engine",
                    **event,
                },
            }

            try:
                self.redis_client.publish(channel, json.dumps(wrapper, default=str))
                replayed += 1

                if replayed % 50 == 0:
                    logger.info(f"  ▶ Replayed {replayed}/{len(events)} events...")
            except Exception as e:
                logger.error(f"Failed to publish event {i}: {e}")

        # Cleanup shadow mode flag
        if self.shadow_mode:
            # Leave it on for a while so agents can process
            logger.info("Shadow mode flag will be cleaned up after 60 seconds.")

        logger.info(f"✅ Replay complete: {replayed}/{len(events)} events published.")
        return {
            "replayed": replayed,
            "total": len(events),
            "shadow_mode": self.shadow_mode,
            "speed_multiplier": speed_multiplier,
        }

    def _route_event(self, event: Dict[str, Any], default_channel: str) -> str:
        """Route an event to the appropriate supervisor channel based on its type."""
        rule_groups = event.get("rule", {}).get("groups", []) if isinstance(event.get("rule"), dict) else []

        if any(g in rule_groups for g in ["syscheck", "fim", "rootcheck"]):
            return "soc:endpoint-supervisor"
        elif any(g in rule_groups for g in ["firewall", "ids", "network"]):
            return "soc:network-supervisor"
        elif any(g in rule_groups for g in ["authentication_failed", "authentication_success"]):
            return "soc:detection-supervisor"
        elif any(g in rule_groups for g in ["honeypot", "cowrie", "dionaea"]):
            return "soc:deception-alerts"
        else:
            return default_channel


# ---------------------------------------------------------------------------
# Result Comparator / مقارن النتائج
# ---------------------------------------------------------------------------

class ResultComparator:
    """
    Compares shadow mode results with original/expected outcomes.
    يقارن نتائج الوضع الظلي مع النتائج الأصلية
    """

    @staticmethod
    def compare(shadow_log_path: str, original_package_path: str) -> Dict[str, Any]:
        """
        Compare shadow execution log with original incident data.

        Returns:
            Analysis summary with metrics.
        """
        # Load shadow results
        shadow_entries = []
        shadow_path = Path(shadow_log_path)
        if shadow_path.exists():
            with open(shadow_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        shadow_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Parse log format: "[SHADOW] action_type | target | ..."
                        shadow_entries.append({"raw": line})

        # Load original package for reference
        original_events = []
        original_path = Path(original_package_path)
        if original_path.exists():
            with open(original_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
                original_events = pkg.get("events", [])

        # Build comparison report
        report = {
            "shadow_actions_count": len(shadow_entries),
            "original_events_count": len(original_events),
            "shadow_actions": shadow_entries[:50],  # Limit for readability
            "analysis": {},
        }

        # Categorize shadow actions
        action_types = {}
        for entry in shadow_entries:
            atype = entry.get("action_type", entry.get("type", "unknown"))
            action_types[atype] = action_types.get(atype, 0) + 1

        report["analysis"]["action_distribution"] = action_types
        report["analysis"]["actions_per_event_ratio"] = (
            round(len(shadow_entries) / max(1, len(original_events)), 3)
        )

        # Summary assessment
        ratio = report["analysis"]["actions_per_event_ratio"]
        if ratio > 0.5:
            report["analysis"]["assessment"] = "HIGH_ACTIVITY — الوكلاء أصدروا إجراءات كثيرة"
        elif ratio > 0.1:
            report["analysis"]["assessment"] = "MODERATE — الوكلاء استجابوا بشكل مقبول"
        else:
            report["analysis"]["assessment"] = "LOW_ACTIVITY — الوكلاء لم يكتشفوا الكثير"

        logger.info(f"📊 Comparison: {len(shadow_entries)} shadow actions vs {len(original_events)} original events.")
        logger.info(f"   Assessment: {report['analysis']['assessment']}")

        return report


# ---------------------------------------------------------------------------
# CLI / واجهة سطر الأوامر
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SOC Incident Replay Engine — آلة الزمن",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Package command
    pkg_parser = subparsers.add_parser("package", help="Package events from OpenSearch")
    pkg_parser.add_argument("--minutes", type=int, default=60, help="Time window in minutes")
    pkg_parser.add_argument("--index", default="wazuh-alerts-*", help="OpenSearch index pattern")
    pkg_parser.add_argument("--output", required=True, help="Output JSON file path")
    pkg_parser.add_argument("--max-events", type=int, default=5000, help="Max events to package")

    # Replay command
    rep_parser = subparsers.add_parser("replay", help="Replay a packaged incident")
    rep_parser.add_argument("--input", required=True, help="Packaged incident JSON file")
    rep_parser.add_argument("--shadow", action="store_true", help="Run in shadow mode (no real actions)")
    rep_parser.add_argument("--speed", type=float, default=10.0, help="Speed multiplier (default: 10x)")
    rep_parser.add_argument("--channel", default="soc:endpoint-supervisor", help="Target Redis channel")

    # Compare command
    cmp_parser = subparsers.add_parser("compare", help="Compare shadow results with original")
    cmp_parser.add_argument("--shadow-log", required=True, help="Path to shadow_results.log")
    cmp_parser.add_argument("--original", required=True, help="Path to original incident JSON")
    cmp_parser.add_argument("--output", help="Output comparison JSON file")

    args = parser.parse_args()

    if args.command == "package":
        packager = IncidentPackager()
        package = packager.package(
            minutes=args.minutes,
            index=args.index,
            max_events=args.max_events,
        )
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"💾 Saved to {output_path}")

    elif args.command == "replay":
        input_path = Path(args.input)
        if not input_path.exists():
            logger.error(f"File not found: {input_path}")
            sys.exit(1)
        with open(input_path, "r", encoding="utf-8") as f:
            package = json.load(f)

        replayer = IncidentReplayer(shadow_mode=args.shadow)
        result = replayer.replay(
            package,
            speed_multiplier=args.speed,
            target_channel=args.channel,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "compare":
        report = ResultComparator.compare(args.shadow_log, args.original)
        print(json.dumps(report, indent=2, ensure_ascii=False))

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"💾 Report saved to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
