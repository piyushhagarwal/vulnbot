"""
NVD REST API client (CVE API v2.0).
Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key: 5 requests per 30 seconds  → 6s sleep between calls
  - With API key:   50 requests per 30 seconds  → 0.6s sleep between calls
"""

import time
import httpx

from src.config import Config
from src.logger import get_logger

logger = get_logger(__name__)

class NVDClient:
    """
    Thin HTTP wrapper around the NVD CVE API v2.0.
    Every public method returns plain dicts, no business logic here.
    All parsing and shaping is done in the tool layer (tools/nvd_tool.py).
    """

    def __init__(self):
        headers = {"User-Agent": "vuln-chatbot/1.0"}
        if Config.NVD_API_KEY:
            headers["apiKey"] = Config.NVD_API_KEY

        # httpx client with a 30s timeout — NVD can be slow under load
        self._client = httpx.Client(
            base_url=Config.NVD_BASE_URL,
            headers=headers,
            timeout=30.0,
        )
        self._last_request_time: float = 0.0

    # ── public methods ────────────────────────────────────────────────────

    def get_cve_by_id(self, cve_id: str) -> dict | None:
        """
        Fetch a single CVE by its ID.

        Args:
            cve_id: e.g. "CVE-2021-44228"

        Returns:
            The raw NVD cve object dict, or None if not found.
        """
        logger.info(f"Fetching CVE: {cve_id}")
        data = self._get(params={"cveId": cve_id.upper()})

        if not data or data.get("totalResults", 0) == 0:
            logger.warning(f"CVE not found: {cve_id}")
            return None

        return data["vulnerabilities"][0]["cve"]

    def search_cves_by_keyword(
        self,
        keyword: str,
        max_results: int = 10,
    ) -> list[dict]:
        """
        Search CVEs by keyword against NVD descriptions.
        Multiple words act as AND (all must appear in the description).

        Args:
            keyword:     Search term(s), e.g. "Apache Log4j"
            max_results: Cap on results returned (NVD max per page is 2000)

        Returns:
            List of raw NVD cve object dicts.
        """
        logger.info(f"Searching CVEs for keyword: '{keyword}' (max {max_results})")

        # NVD encodes spaces automatically via httpx params
        data = self._get(params={
            "keywordSearch":  keyword,
            "resultsPerPage": min(max_results, 2000),
            "startIndex":     0,
            # Exclude rejected CVEs from results
            "noRejected":     "",
        })

        if not data:
            return []

        vulns = data.get("vulnerabilities", [])
        logger.info(f"Found {data.get('totalResults', 0)} total results, returning {len(vulns)}")
        return [v["cve"] for v in vulns]

    def search_cves_by_severity(
        self,
        severity: str,
        max_results: int = 10,
    ) -> list[dict]:
        """
        Search CVEs by CVSSv3 severity level.

        Args:
            severity:    One of: LOW, MEDIUM, HIGH, CRITICAL
            max_results: Cap on results returned

        Returns:
            List of raw NVD cve object dicts.
        """
        severity = severity.upper()
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if severity not in valid:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of: {valid}")

        logger.info(f"Searching CVEs by severity: {severity}")
        data = self._get(params={
            "cvssV3Severity":  severity,
            "resultsPerPage":  min(max_results, 2000),
            "noRejected":      "",
        })

        if not data:
            return []

        return [v["cve"] for v in data.get("vulnerabilities", [])]
    
    def search_cves_by_date_range(
        self,
        pub_start_date: str,
        pub_end_date: str,
        max_results: int = 10,
    ) -> list[dict]:
        """
        Search CVEs published within a date range.
        NVD max range is 120 consecutive days per request.

        Args:
            pub_start_date: ISO-8601 format e.g. "2024-01-01T00:00:00.000"
            pub_end_date:   ISO-8601 format e.g. "2024-03-31T23:59:59.000"
            max_results:    Cap on results returned.

        Returns:
            List of raw NVD cve object dicts.
        """
        logger.info(f"Searching CVEs published between {pub_start_date} and {pub_end_date}")

        data = self._get(params={
            "pubStartDate":   pub_start_date,
            "pubEndDate":     pub_end_date,
            "resultsPerPage": min(max_results, 2000),
            "noRejected":     "",
        })

        if not data:
            return []

        vulns = data.get("vulnerabilities", [])
        logger.info(f"Found {data.get('totalResults', 0)} total, returning {len(vulns)}")
        return [v["cve"] for v in vulns]

    def close(self):
        self._client.close()

    # ── private helpers ───────────────────────────────────────────────────

    def _get(self, params: dict) -> dict | None:
        """
        Execute a rate-limited GET request against the NVD base URL.
        Handles retries on 403 (rate limit hit) with a longer backoff.
        """
        self._respect_rate_limit()

        try:
            response = self._client.get("", params=params)
            self._last_request_time = time.monotonic()

            if response.status_code == 403:
                # Rate limit exceeded — back off and retry once
                logger.warning("NVD rate limit hit (403). Sleeping 30s then retrying...")
                time.sleep(30)
                response = self._client.get("", params=params)
                self._last_request_time = time.monotonic()

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"NVD HTTP error {e.response.status_code}: {e.response.text[:200]}")
            return None
        except httpx.RequestError as e:
            logger.error(f"NVD request failed: {e}")
            return None

    def _respect_rate_limit(self):
        """Sleep if needed to stay within NVD's rate limit window."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < Config.NVD_RATE_LIMIT_DELAY:
            sleep_for = Config.NVD_RATE_LIMIT_DELAY - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_for:.2f}s")
            time.sleep(sleep_for)