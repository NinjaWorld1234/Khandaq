"""
SOC Platform - Worker Agent W21: IOC Enrichment Agent
وكيل إثراء مؤشرات الاختراق

Queries unenriched IOCs from the soc-iocs index and performs local enrichment:
  - RFC1918 private IP detection
  - Common legitimate domain pattern matching
  - Hash format validation (MD5 / SHA1 / SHA256)
  - Geographic IP risk assessment via first-octet heuristics
  - Priority: IOCs linked to CRITICAL alerts are enriched first
  - Rate limit: max 50 IOCs per cycle to avoid overload

Interval: 120 seconds
Supervisor channel: soc:detection-supervisor
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w21_ioc_enrichment")

# ---------------------------------------------------------------------------
# Enrichment constants
# ---------------------------------------------------------------------------

MAX_IOCS_PER_CYCLE = 50
IOC_INDEX = "soc-iocs"

# RFC1918 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Common legitimate (benign) domain suffixes / patterns
_COMMON_LEGIT_DOMAINS: list[re.Pattern[str]] = [
    re.compile(r"\.google\.com$", re.IGNORECASE),
    re.compile(r"\.googleapis\.com$", re.IGNORECASE),
    re.compile(r"\.microsoft\.com$", re.IGNORECASE),
    re.compile(r"\.windows\.net$", re.IGNORECASE),
    re.compile(r"\.office365\.com$", re.IGNORECASE),
    re.compile(r"\.office\.com$", re.IGNORECASE),
    re.compile(r"\.azure\.com$", re.IGNORECASE),
    re.compile(r"\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"\.cloudflare\.com$", re.IGNORECASE),
    re.compile(r"\.akamai\.net$", re.IGNORECASE),
    re.compile(r"\.github\.com$", re.IGNORECASE),
    re.compile(r"\.apple\.com$", re.IGNORECASE),
    re.compile(r"\.ubuntu\.com$", re.IGNORECASE),
    re.compile(r"\.debian\.org$", re.IGNORECASE),
    re.compile(r"\.centos\.org$", re.IGNORECASE),
    re.compile(r"\.windowsupdate\.com$", re.IGNORECASE),
    re.compile(r"\.cdn\.mozilla\.net$", re.IGNORECASE),
]

# Hash format patterns
_HASH_PATTERNS: Dict[str, re.Pattern[str]] = {
    "md5":    re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":   re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

# Geographic risk bands (first-octet heuristic — rough proxy, not GeoIP)
# Higher score = higher risk geography based on common threat-intel patterns
_HIGH_RISK_FIRST_OCTETS = {5, 31, 37, 41, 46, 62, 77, 78, 79, 80, 85, 89,
                           91, 95, 109, 141, 176, 178, 185, 188, 193, 194,
                           195, 212, 213}
_LOW_RISK_FIRST_OCTETS = {8, 13, 15, 17, 20, 52, 54, 64, 65, 72, 96, 104,
                          142, 143, 157, 204, 205, 206, 207, 208}


class IOCEnrichmentAgent(BaseAgent):
    """
    IOC Enrichment Agent (W21).
    Locally enriches IOCs with metadata such as private-IP flag,
    common-domain flag, hash-format validity, and geo-risk score.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w21_ioc_enrichment",
            description="Enriches IOCs with local metadata (RFC1918, domain, hash, geo-risk)",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._ioc_index: str = self._agent_config.get("ioc_index", IOC_INDEX)
        self._max_per_cycle: int = self._agent_config.get("max_per_cycle", MAX_IOCS_PER_CYCLE)
        self._total_enriched: int = 0

    # ------------------------------------------------------------------
    # Collect: fetch unenriched IOCs, CRITICAL-priority first
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Query soc-iocs for IOCs where enriched=false, sorted by severity."""
        try:
            # First pass: CRITICAL-linked IOCs
            critical_query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"term": {"enriched": False}},
                        {"term": {"status": "active"}},
                        {"term": {"alert_severity": "CRITICAL"}},
                    ],
                }
            }
            critical_iocs = self.os_client.get_events_since(
                index=self._ioc_index,
                minutes=0,
                query=critical_query,
                size=self._max_per_cycle,
            )

            remaining = self._max_per_cycle - len(critical_iocs)
            other_iocs: list[dict[str, Any]] = []

            if remaining > 0:
                other_query: Dict[str, Any] = {
                    "bool": {
                        "must": [
                            {"term": {"enriched": False}},
                            {"term": {"status": "active"}},
                        ],
                        "must_not": [
                            {"term": {"alert_severity": "CRITICAL"}},
                        ],
                    }
                }
                other_iocs = self.os_client.get_events_since(
                    index=self._ioc_index,
                    minutes=0,
                    query=other_query,
                    size=remaining,
                )

            combined = critical_iocs + other_iocs
            logger.info(
                "Collected %d unenriched IOCs (%d CRITICAL-priority, %d other)",
                len(combined), len(critical_iocs), len(other_iocs),
            )
            return combined if combined else None
        except Exception as exc:
            logger.error("Failed to collect unenriched IOCs: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze: perform local enrichment on each IOC
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run enrichment logic based on IOC type (ip, domain, hash)."""
        findings: list[dict[str, Any]] = []

        for ioc in data:
            ioc_id = ioc.get("_id", ioc.get("id", "unknown"))
            ioc_value = ioc.get("value", "").strip()
            ioc_type = ioc.get("type", "unknown").lower()

            enrichment: Dict[str, Any] = {
                "ioc_id": ioc_id,
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "is_private": False,
                "is_common_domain": False,
                "geo_risk_score": 0.0,
                "format_valid": True,
                "enrichment_notes": [],
            }

            if ioc_type in ("ip", "ipv4", "ip-src", "ip-dst"):
                enrichment.update(self._enrich_ip(ioc_value))
            elif ioc_type in ("domain", "hostname", "fqdn"):
                enrichment.update(self._enrich_domain(ioc_value))
            elif ioc_type in ("hash", "md5", "sha1", "sha256"):
                enrichment.update(self._enrich_hash(ioc_value, ioc_type))
            elif ioc_type == "url":
                enrichment.update(self._enrich_url(ioc_value))
            else:
                enrichment["enrichment_notes"].append(
                    f"Unknown IOC type '{ioc_type}', no specific enrichment applied"
                )

            findings.append(enrichment)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        logger.info("Enriched %d IOCs locally", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide: build update actions
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create update actions; flag obviously benign IOCs for review."""
        actions: list[dict[str, Any]] = []

        for enrichment in findings:
            actions.append({
                "type": "update_enrichment",
                "ioc_id": enrichment["ioc_id"],
                "enrichment": enrichment,
            })

            # Flag private IPs / common domains as likely false-positive IOCs
            if enrichment["is_private"] or enrichment["is_common_domain"]:
                actions.append({
                    "type": "flag_benign",
                    "ioc_id": enrichment["ioc_id"],
                    "ioc_value": enrichment["ioc_value"],
                    "reason": (
                        "private_ip" if enrichment["is_private"]
                        else "common_legitimate_domain"
                    ),
                })

            # Flag invalid hashes
            if not enrichment["format_valid"] and enrichment["ioc_type"] in (
                "hash", "md5", "sha1", "sha256"
            ):
                actions.append({
                    "type": "flag_invalid",
                    "ioc_id": enrichment["ioc_id"],
                    "ioc_value": enrichment["ioc_value"],
                    "reason": "invalid_hash_format",
                })

        return actions

    # ------------------------------------------------------------------
    # Act: persist enrichment results
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Write enrichment data back to soc-iocs and flag anomalies."""
        updated = 0
        flagged_benign = 0
        flagged_invalid = 0
        errors = 0

        for action in actions:
            try:
                if action["type"] == "update_enrichment":
                    e = action["enrichment"]
                    self.os_client.index_document(
                        self._ioc_index,
                        document={
                            "enriched": True,
                            "enriched_at": datetime.now(timezone.utc).isoformat(),
                            "enriched_by": self.name,
                            "is_private": e["is_private"],
                            "is_common_domain": e["is_common_domain"],
                            "geo_risk_score": e["geo_risk_score"],
                            "format_valid": e["format_valid"],
                            "enrichment_notes": e["enrichment_notes"],
                        },
                        doc_id=action["ioc_id"],
                    )
                    updated += 1

                elif action["type"] == "flag_benign":
                    self.alerter.send_alert(
                        severity=Severity.LOW,
                        title="Potentially Benign IOC Detected",
                        details={
                            "ioc_value": action["ioc_value"],
                            "reason": action["reason"],
                            "recommendation": "Review and consider removing from active IOC list",
                        },
                        agent_name=self.name,
                    )
                    flagged_benign += 1

                elif action["type"] == "flag_invalid":
                    logger.warning(
                        "Invalid hash format for IOC %s: %s",
                        action["ioc_id"], action["ioc_value"],
                    )
                    flagged_invalid += 1

            except Exception as exc:
                errors += 1
                logger.error("Failed enrichment action %s for %s: %s",
                             action["type"], action.get("ioc_id"), exc)

        self._total_enriched += updated
        summary = {
            "updated": updated,
            "flagged_benign": flagged_benign,
            "flagged_invalid": flagged_invalid,
            "errors": errors,
            "total_enriched_cumulative": self._total_enriched,
        }
        logger.info("Enrichment cycle complete: %s", summary)

        if updated:
            self.report_to_supervisor({
                "type": "ioc_enrichment_report",
                **summary,
            })

        return summary

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _enrich_ip(ip_str: str) -> Dict[str, Any]:
        """Enrich an IP-type IOC."""
        result: Dict[str, Any] = {
            "is_private": False,
            "geo_risk_score": 0.5,
            "format_valid": True,
            "enrichment_notes": [],
        }
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            result["format_valid"] = False
            result["enrichment_notes"].append("Invalid IP address format")
            return result

        # Private / reserved check
        if any(addr in net for net in _PRIVATE_NETWORKS) or addr.is_private:
            result["is_private"] = True
            result["geo_risk_score"] = 0.0
            result["enrichment_notes"].append("RFC1918 / private address")
            return result

        if addr.is_multicast:
            result["is_private"] = True
            result["enrichment_notes"].append("Multicast address")
            return result

        # Geo-risk heuristic based on first octet
        if isinstance(addr, ipaddress.IPv4Address):
            first_octet = int(str(addr).split(".")[0])
            if first_octet in _HIGH_RISK_FIRST_OCTETS:
                result["geo_risk_score"] = 0.8
                result["enrichment_notes"].append("First-octet maps to higher-risk geography")
            elif first_octet in _LOW_RISK_FIRST_OCTETS:
                result["geo_risk_score"] = 0.2
                result["enrichment_notes"].append("First-octet maps to lower-risk geography")
            else:
                result["geo_risk_score"] = 0.5
                result["enrichment_notes"].append("Neutral geo-risk band")

        return result

    @staticmethod
    def _enrich_domain(domain: str) -> Dict[str, Any]:
        """Enrich a domain-type IOC."""
        result: Dict[str, Any] = {
            "is_common_domain": False,
            "format_valid": True,
            "enrichment_notes": [],
        }

        # Basic domain validation
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", domain):
            result["format_valid"] = False
            result["enrichment_notes"].append("Unusual domain format")

        # Check against known-legitimate patterns
        for pattern in _COMMON_LEGIT_DOMAINS:
            if pattern.search(domain):
                result["is_common_domain"] = True
                result["enrichment_notes"].append(
                    f"Matches common legitimate domain pattern: {pattern.pattern}"
                )
                break

        # DGA-style heuristic: very long random-looking subdomain
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain = parts[0]
            if len(subdomain) > 20 and re.match(r"^[a-z0-9]+$", subdomain):
                result["enrichment_notes"].append(
                    "Subdomain appears algorithmically generated (potential DGA)"
                )

        return result

    @staticmethod
    def _enrich_hash(hash_value: str, ioc_type: str) -> Dict[str, Any]:
        """Enrich a hash-type IOC by validating format."""
        result: Dict[str, Any] = {
            "format_valid": False,
            "enrichment_notes": [],
        }

        # Determine expected hash type
        check_types = [ioc_type] if ioc_type in _HASH_PATTERNS else list(_HASH_PATTERNS.keys())

        for htype in check_types:
            if _HASH_PATTERNS[htype].match(hash_value):
                result["format_valid"] = True
                result["enrichment_notes"].append(f"Valid {htype.upper()} format")
                return result

        result["enrichment_notes"].append(
            f"Hash value does not match any known format (length={len(hash_value)})"
        )
        return result

    @staticmethod
    def _enrich_url(url: str) -> Dict[str, Any]:
        """Enrich a URL-type IOC."""
        result: Dict[str, Any] = {
            "is_common_domain": False,
            "format_valid": True,
            "enrichment_notes": [],
        }

        if not re.match(r"^https?://", url, re.IGNORECASE):
            result["format_valid"] = False
            result["enrichment_notes"].append("URL missing http(s):// scheme")

        for pattern in _COMMON_LEGIT_DOMAINS:
            if pattern.search(url):
                result["is_common_domain"] = True
                result["enrichment_notes"].append("URL host matches common legitimate domain")
                break

        return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = IOCEnrichmentAgent()
    agent.run_loop()
