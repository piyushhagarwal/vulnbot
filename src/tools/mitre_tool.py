"""
MITRE ATT&CK tools — wrap MITREClient methods and shape raw STIX objects
into clean, LLM-readable JSON strings.
"""

import json

from src.clients.mitre_client import MITREClient
from src.logger import get_logger
from src.tools.base import Tool

logger = get_logger(__name__)

# Shared client instance across all MITRE tools
_mitre = MITREClient()


# ── helpers ───────────────────────────────────────────────────────────────

def _extract_technique_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _extract_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _extract_tactics(obj: dict) -> list[str]:
    """Extract tactic names from kill_chain_phases."""
    return [
        phase.get("phase_name", "").replace("-", " ").title()
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def _extract_platforms(obj: dict) -> list[str]:
    return obj.get("x_mitre_platforms", [])


def _extract_detection(obj: dict) -> str:
    return obj.get("x_mitre_detection", "No detection guidance available.")


def _shape_technique(obj: dict) -> dict:
    """Full technique shape — used for get_mitre_technique."""
    return {
        "id":               _extract_technique_id(obj),
        "name":             obj.get("name", ""),
        "tactics":          _extract_tactics(obj),
        "platforms":        _extract_platforms(obj),
        "description":      obj.get("description", "")[:1000],  # cap length
        "detection":        _extract_detection(obj),
        "is_subtechnique":  obj.get("x_mitre_is_subtechnique", False),
        "url":              _extract_url(obj),
        "revoked":          obj.get("revoked", False),
    }


def _shape_technique_summary(obj: dict) -> dict:
    """Compact shape for list results."""
    return {
        "id":      _extract_technique_id(obj),
        "name":    obj.get("name", ""),
        "tactics": _extract_tactics(obj),
        "url":     _extract_url(obj),
    }


def _shape_mitigation(obj: dict) -> dict:
    return {
        "id":          _extract_technique_id(obj),
        "name":        obj.get("name", ""),
        "description": obj.get("description", "")[:500],
    }


# ── tools ─────────────────────────────────────────────────────────────────

class GetMITRETechniqueTool(Tool):

    @property
    def name(self) -> str:
        return "get_mitre_technique"

    @property
    def description(self) -> str:
        return (
            "Fetch details for a specific MITRE ATT&CK technique by its T-ID. "
            "Use when the user provides a technique ID like T1059 or T1059.001. "
            "Returns the technique name, tactics, platforms, description, "
            "detection guidance, and mitigations."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "ATT&CK technique ID, e.g. T1059 or T1059.001",
                }
            },
            "required": ["technique_id"],
        }

    def execute(self, **kwargs) -> str:
        technique_id = kwargs.get("technique_id", "").strip()
        if not technique_id:
            return json.dumps({"error": "technique_id is required"})

        obj = _mitre.get_technique_by_id(technique_id)
        if not obj:
            return json.dumps({"error": f"Technique '{technique_id}' not found in MITRE ATT&CK."})

        shaped = _shape_technique(obj)

        # Fetch and attach mitigations in the same call — saves an extra tool call
        mitigations = _mitre.get_mitigations_for_technique(technique_id)
        shaped["mitigations"] = [_shape_mitigation(m) for m in mitigations]

        return json.dumps(shaped, indent=2)


class SearchMITREByKeywordTool(Tool):

    @property
    def name(self) -> str:
        return "search_mitre_by_keyword"

    @property
    def description(self) -> str:
        return (
            "Search MITRE ATT&CK techniques by keyword. "
            "Use for queries like 'command execution techniques', 'lateral movement', "
            "'persistence methods', 'credential dumping'. "
            "Returns a list of matching techniques with their tactics and IDs."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search term, e.g. 'powershell', 'lateral movement', 'phishing'",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10)",
                },
            },
            "required": ["keyword"],
        }

    def execute(self, **kwargs) -> str:
        keyword     = kwargs.get("keyword", "").strip()
        max_results = min(int(kwargs.get("max_results", 10)), 20)

        if not keyword:
            return json.dumps({"error": "keyword is required"})

        results = _mitre.search_techniques_by_keyword(keyword, max_results)
        if not results:
            return json.dumps({
                "results": [],
                "message": f"No MITRE techniques found for '{keyword}'",
            })

        return json.dumps({
            "keyword": keyword,
            "count":   len(results),
            "results": [_shape_technique_summary(r) for r in results],
        }, indent=2)