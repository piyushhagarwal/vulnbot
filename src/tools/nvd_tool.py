"""
NVD tools — wrap NVDClient methods and shape raw API responses
into clean, LLM-readable JSON strings.

Each tool corresponds to one LLM-callable function.
Parsing logic lives here, not in the client.
"""

import json
from datetime import datetime, timedelta, timezone

from src.clients.nvd_client import NVDClient
from src.logger import get_logger
from src.tools.base import Tool

logger = get_logger(__name__)

# Shared client instance across all NVD tools
_nvd = NVDClient()


# ── helpers ───────────────────────────────────────────────────────────────

def _extract_english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "No description available.")
    return "No description available."


def _extract_cvss(cve: dict) -> dict:
    """
    Extract the best available CVSS score — prefer v3.1, fall back to v3.0, then v2.
    Returns a flat dict with score, severity, and vector string.
    """
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        # Prefer 'Primary' source
        for entry in sorted(entries, key=lambda e: e.get("type", "") != "Primary"):
            data = entry.get("cvssData", {})
            return {
                "version":  data.get("version", ""),
                "score":    data.get("baseScore"),
                "severity": entry.get("baseSeverity", ""),
                "vector":   data.get("vectorString", ""),
            }

    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        return {
            "version":  "2.0",
            "score":    data.get("baseScore"),
            "severity": entry.get("baseSeverity", ""),
            "vector":   data.get("vectorString", ""),
        }

    return {}


def _extract_affected_products(cve: dict) -> list[str]:
    """Extract a flat list of CPE criteria strings from configurations."""
    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    products.append(match.get("criteria", ""))
    return products[:20]  # cap to avoid flooding the LLM context


def _extract_weaknesses(cve: dict) -> list[str]:
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def _extract_references(cve: dict, limit: int = 5) -> list[str]:
    return [r.get("url", "") for r in cve.get("references", [])[:limit]]


def _shape_cve(cve: dict) -> dict:
    """Transform a raw NVD cve object into a clean summary dict."""
    cvss = _extract_cvss(cve)
    return {
        "id":               cve.get("id", ""),
        "published":        cve.get("published", "")[:10],  # date only
        "last_modified":    cve.get("lastModified", "")[:10],
        "status":           cve.get("vulnStatus", ""),
        "description":      _extract_english_description(cve),
        "cvss":             cvss,
        "weaknesses":       _extract_weaknesses(cve),
        "affected_products": _extract_affected_products(cve),
        "references":       _extract_references(cve),
        # KEV fields — only present if CVE is in CISA's Known Exploited list
        "kev": {
            "in_kev":          "cisaExploitAdd" in cve,
            "exploit_added":   cve.get("cisaExploitAdd", ""),
            "action_due":      cve.get("cisaActionDue", ""),
            "required_action": cve.get("cisaRequiredAction", ""),
        } if "cisaExploitAdd" in cve else {"in_kev": False},
    }


def _shape_cve_summary(cve: dict) -> dict:
    """Compact version for list results — just the essentials."""
    cvss = _extract_cvss(cve)
    return {
        "id":          cve.get("id", ""),
        "published":   cve.get("published", "")[:10],
        "severity":    cvss.get("severity", "N/A"),
        "score":       cvss.get("score", "N/A"),
        "description": _extract_english_description(cve)[:200] + "...",
    }


# ── tools ─────────────────────────────────────────────────────────────────

class GetCVEDetailsTool(Tool):

    @property
    def name(self) -> str:
        return "get_cve_details"

    @property
    def description(self) -> str:
        return (
            "Fetch complete details for a specific CVE from the National Vulnerability Database. "
            "Use this when the user provides an exact CVE ID (e.g. CVE-2021-44228). "
            "Returns CVSS score, severity, description, affected products, weaknesses, "
            "references, and CISA KEV status if applicable."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier, e.g. CVE-2021-44228",
                }
            },
            "required": ["cve_id"],
        }

    def execute(self, **kwargs) -> str:
        cve_id = kwargs.get("cve_id", "").strip()
        if not cve_id:
            return json.dumps({"error": "cve_id is required"})

        raw = _nvd.get_cve_by_id(cve_id)
        if not raw:
            return json.dumps({"error": f"CVE '{cve_id}' not found in NVD."})

        return json.dumps(_shape_cve(raw), indent=2)


class SearchCVEsByKeywordTool(Tool):

    @property
    def name(self) -> str:
        return "search_cves_by_keyword"

    @property
    def description(self) -> str:
        return (
            "Search the NVD for CVEs matching a keyword or phrase. "
            "Use for queries like 'Log4j vulnerabilities', 'Apache RCE', "
            "'Windows privilege escalation'. Multiple words act as AND. "
            "Returns a ranked list of matching CVEs with severity and description."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search term(s), e.g. 'Apache Log4j' or 'remote code execution'",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10, max 20)",
                },
            },
            "required": ["keyword"],
        }

    def execute(self, **kwargs) -> str:
        keyword     = kwargs.get("keyword", "").strip()
        max_results = min(int(kwargs.get("max_results", 10)), 20)

        if not keyword:
            return json.dumps({"error": "keyword is required"})

        raw_list = _nvd.search_cves_by_keyword(keyword, max_results)
        if not raw_list:
            return json.dumps({"results": [], "message": f"No CVEs found for '{keyword}'"})

        return json.dumps({
            "keyword": keyword,
            "count":   len(raw_list),
            "results": [_shape_cve_summary(c) for c in raw_list],
        }, indent=2)


class SearchCVEsBySeverityTool(Tool):

    @property
    def name(self) -> str:
        return "search_cves_by_severity"

    @property
    def description(self) -> str:
        return (
            "Search NVD for CVEs filtered by CVSSv3 severity level. "
            "Use when the user asks for 'critical vulnerabilities' or "
            "'high severity CVEs'. Severity must be LOW, MEDIUM, HIGH, or CRITICAL."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "CVSSv3 severity level",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10)",
                },
            },
            "required": ["severity"],
        }

    def execute(self, **kwargs) -> str:
        severity    = kwargs.get("severity", "").upper()
        max_results = min(int(kwargs.get("max_results", 10)), 20)

        try:
            raw_list = _nvd.search_cves_by_severity(severity, max_results)
        except ValueError as e:
            return json.dumps({"error": str(e)})

        if not raw_list:
            return json.dumps({"results": [], "message": f"No {severity} CVEs found"})

        return json.dumps({
            "severity": severity,
            "count":    len(raw_list),
            "results":  [_shape_cve_summary(c) for c in raw_list],
        }, indent=2)


class SearchCVEsByDateRangeTool(Tool):

    @property
    def name(self) -> str:
        return "search_cves_by_date_range"

    @property
    def description(self) -> str:
        return (
            "Search NVD for CVEs published within a date range. "
            "Use for queries like 'CVEs from last 30 days', 'vulnerabilities published in January 2024'. "
            "You can pass natural values like 'last 7 days' or '30' for days_back, "
            "or provide explicit ISO dates. Max range is 120 days."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "days_back": {
                    "type": "integer",
                    "description": "Number of days back from today (e.g. 7, 30, 90). Use this OR start/end dates.",
                },
                "start_date": {
                    "type": "string",
                    "description": "Start date in YYYY-MM-DD format. Use with end_date.",
                },
                "end_date": {
                    "type": "string",
                    "description": "End date in YYYY-MM-DD format. Use with start_date.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10)",
                },
            },
            "required": [],  # either days_back or start_date+end_date
        }

    def execute(self, **kwargs) -> str:
        max_results = min(int(kwargs.get("max_results", 10)), 20)
        now = datetime.now(timezone.utc)

        # Resolve date range — prefer days_back for simplicity
        if kwargs.get("days_back"):
            days     = int(kwargs["days_back"])
            end_dt   = now
            start_dt = now - timedelta(days=days)
        elif kwargs.get("start_date") and kwargs.get("end_date"):
            try:
                start_dt = datetime.strptime(kwargs["start_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                end_dt   = datetime.strptime(kwargs["end_date"],   "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError as e:
                return json.dumps({"error": f"Invalid date format: {e}. Use YYYY-MM-DD."})
        else:
            # Default to last 30 days
            end_dt   = now
            start_dt = now - timedelta(days=30)

        # Enforce NVD's 120-day max range
        if (end_dt - start_dt).days > 120:
            return json.dumps({"error": "Date range exceeds NVD's 120-day maximum. Please narrow the range."})

        pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        raw_list = _nvd.search_cves_by_date_range(pub_start, pub_end, max_results)
        if not raw_list:
            return json.dumps({
                "results": [],
                "message": f"No CVEs found between {pub_start[:10]} and {pub_end[:10]}",
            })

        return json.dumps({
            "from":    pub_start[:10],
            "to":      pub_end[:10],
            "count":   len(raw_list),
            "results": [_shape_cve_summary(c) for c in raw_list],
        }, indent=2)