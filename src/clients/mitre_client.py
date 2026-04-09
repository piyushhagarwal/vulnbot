""" MITRE ATT&CK client using the STIX JSON file published on GitHub.
Source: https://github.com/mitre/cti

We download the enterprise-attack STIX bundle once, cache it to disk,
and query it entirely in memory — no TAXII server needed.

STIX object types we care about:
  - attack-pattern  → Techniques (T-IDs)
  - x-mitre-tactic  → Tactics (TA-IDs)
  - course-of-action → Mitigations
  - intrusion-set   → Threat actors / groups
  - malware         → Malware families
"""

import json
import os
import re

import httpx

from src.config import Config
from src.logger import get_logger

logger = get_logger(__name__)

# STIX types → human-readable labels
_TYPE_LABELS = {
    "attack-pattern":   "Technique",
    "x-mitre-tactic":  "Tactic",
    "course-of-action": "Mitigation",
    "intrusion-set":    "Threat Group",
    "malware":          "Malware",
}


class MITREClient:
    """
    In-memory query engine over the MITRE ATT&CK STIX bundle.

    On first use the bundle is downloaded from GitHub and written to
    Config.MITRE_CACHE_FILE. Subsequent runs load from the cache.
    Call refresh() to force a re-download.
    """

    def __init__(self):
        self._objects: list[dict] = []   # all STIX objects from the bundle
        self._loaded = False

    # ── public methods ────────────────────────────────────────────────────

    def get_technique_by_id(self, technique_id: str) -> dict | None:
        """
        Fetch a single ATT&CK technique by its T-ID (e.g. "T1059" or "T1059.001").

        Args:
            technique_id: ATT&CK technique ID, with or without sub-technique suffix.

        Returns:
            The STIX attack-pattern object, or None if not found.
        """
        self._ensure_loaded()
        tid = technique_id.upper()
        logger.info(f"Looking up MITRE technique: {tid}")

        for obj in self._objects:
            if obj.get("type") != "attack-pattern":
                continue
            if self._extract_technique_id(obj) == tid:
                return obj

        logger.warning(f"MITRE technique not found: {tid}")
        return None

    def search_techniques_by_keyword(self, keyword: str, max_results: int = 10) -> list[dict]:
        """
        Search techniques whose name or description contains the keyword.

        Args:
            keyword:     Case-insensitive search term.
            max_results: Cap on results returned.

        Returns:
            List of matching STIX attack-pattern objects.
        """
        self._ensure_loaded()
        kw = keyword.lower()
        logger.info(f"Searching MITRE techniques for: '{keyword}'")

        results = []
        for obj in self._objects:
            if obj.get("type") != "attack-pattern":
                continue
            # Skip revoked or deprecated entries
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()

            if kw in name or kw in desc:
                results.append(obj)
                if len(results) >= max_results:
                    break

        logger.info(f"Found {len(results)} matching techniques")
        return results

    def get_tactic_by_id(self, tactic_id: str) -> dict | None:
        """
        Fetch a tactic by its TA-ID (e.g. "TA0002").

        Args:
            tactic_id: ATT&CK tactic ID.

        Returns:
            The STIX x-mitre-tactic object, or None if not found.
        """
        self._ensure_loaded()
        tid = tactic_id.upper()
        logger.info(f"Looking up MITRE tactic: {tid}")

        for obj in self._objects:
            if obj.get("type") != "x-mitre-tactic":
                continue
            external = obj.get("external_references", [])
            for ref in external:
                if ref.get("external_id") == tid:
                    return obj

        logger.warning(f"MITRE tactic not found: {tid}")
        return None

    def get_mitigations_for_technique(self, technique_id: str) -> list[dict]:
        """
        Return all course-of-action objects that mitigate the given technique.
        Uses the STIX relationship graph to find mitigates → attack-pattern links.

        Args:
            technique_id: ATT&CK technique ID (e.g. "T1059")

        Returns:
            List of STIX course-of-action objects.
        """
        self._ensure_loaded()
        tid = technique_id.upper()

        # Find the STIX id of this technique first
        technique_stix_id = None
        for obj in self._objects:
            if obj.get("type") == "attack-pattern":
                if self._extract_technique_id(obj) == tid:
                    technique_stix_id = obj["id"]
                    break

        if not technique_stix_id:
            return []

        # Collect IDs of mitigations linked via 'mitigates' relationships
        mitigation_ids = set()
        for obj in self._objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
                if obj.get("target_ref") == technique_stix_id:
                    mitigation_ids.add(obj["source_ref"])

        # Resolve to actual course-of-action objects
        mitigations = []
        for obj in self._objects:
            if obj.get("type") == "course-of-action" and obj["id"] in mitigation_ids:
                mitigations.append(obj)

        return mitigations

    def refresh(self):
        """Force re-download of the STIX bundle, ignoring the cache."""
        logger.info("Refreshing MITRE ATT&CK STIX bundle...")
        self._objects = []
        self._loaded = False
        if os.path.exists(Config.MITRE_CACHE_FILE):
            os.remove(Config.MITRE_CACHE_FILE)
        self._ensure_loaded()

    # ── private helpers ───────────────────────────────────────────────────

    def _ensure_loaded(self):
        """Load from cache if available, otherwise download from GitHub."""
        if self._loaded:
            return

        if os.path.exists(Config.MITRE_CACHE_FILE):
            logger.info(f"Loading MITRE ATT&CK from cache: {Config.MITRE_CACHE_FILE}")
            self._load_from_file(Config.MITRE_CACHE_FILE)
        else:
            self._download_and_cache()

        self._loaded = True
        logger.info(f"MITRE ATT&CK loaded: {len(self._objects)} STIX objects")

    def _download_and_cache(self):
        """Download the STIX bundle from GitHub and write it to cache."""
        logger.info(f"Downloading MITRE ATT&CK STIX bundle from {Config.MITRE_STIX_URL}")
        logger.info("This may take a moment (~10MB)...")

        try:
            # Stream with a long timeout — the file is ~10MB
            with httpx.stream("GET", Config.MITRE_STIX_URL, timeout=60.0, follow_redirects=True) as r:
                r.raise_for_status()
                raw = r.read()

            bundle = json.loads(raw)

            # Write cache before parsing so we don't re-download on parse errors
            with open(Config.MITRE_CACHE_FILE, "wb") as f:
                f.write(raw)
            logger.info(f"MITRE cache written to {Config.MITRE_CACHE_FILE}")

            self._objects = bundle.get("objects", [])

        except httpx.RequestError as e:
            logger.error(f"Failed to download MITRE bundle: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse MITRE STIX JSON: {e}")
            raise

    def _load_from_file(self, path: str):
        """Parse the cached STIX JSON file into memory."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            self._objects = bundle.get("objects", [])
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to read MITRE cache file: {e}. Will re-download.")
            os.remove(path)
            self._download_and_cache()

    def _extract_technique_id(self, attack_pattern: dict) -> str | None:
        """Extract the T-ID (e.g. 'T1059' or 'T1059.001') from a STIX object's external references."""
        for ref in attack_pattern.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                # Match T#### or T####.### format
                if re.match(r"^T\d{4}(\.\d{3})?$", ext_id):
                    return ext_id
        return None