"""
High-performance REST client for official NIST NVD API 2.0 with retry,
rate limiting, bidirectional smart scanning, and fallback strategies.
"""

from __future__ import annotations
import os
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any, Callable

from searchcve.models import CVEItem
from searchcve.cache import QueryCache


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        use_cache: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")

        env_timeout = os.environ.get("SEARCHCVE_TIMEOUT")
        if timeout is not None:
            self.timeout = timeout
        elif env_timeout:
            try:
                self.timeout = float(env_timeout)
            except ValueError:
                self.timeout = 15.0
        else:
            self.timeout = 15.0

        self.use_cache = use_cache
        self.cache = QueryCache() if use_cache else None
        self.progress_callback = progress_callback
        self.last_request_time = 0.0

        # Rate limiting: 0.6s with key (~50/30s), 6.0s without key (~5/30s)
        self.min_interval = 0.6 if self.api_key else 6.0

    def _throttle(self) -> None:
        """Throttle requests to respect NIST NVD rate limit guidelines."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def _http_get(self, params: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
        """Executes an HTTP GET to NVD API 2.0 with exponential backoff."""
        clean_params = {k: v for k, v in params.items() if v is not None}
        query_string = urllib.parse.urlencode(clean_params)
        url = f"{self.BASE_URL}?{query_string}"

        if self.use_cache and self.cache:
            cached = self.cache.get(url)
            if cached is not None:
                return cached

        headers = {
            "User-Agent": "SearchCVE-Advanced/2.0 (Security Scanner)",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        backoff = 2.0
        for attempt in range(max_retries):
            self._throttle()
            self.last_request_time = time.time()
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if self.use_cache and self.cache:
                            self.cache.set(url, data)
                        return data
                    elif resp.status in (403, 429):
                        time.sleep(backoff)
                        backoff *= 2
                    else:
                        raise RuntimeError(f"NVD API returned HTTP status {resp.status}")
            except urllib.error.HTTPError as e:
                if e.code in (403, 429) and attempt < max_retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    raise RuntimeError(f"NVD API HTTP Error {e.code}: {e.reason}")
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < max_retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    raise RuntimeError(f"NVD API Network Error: {e}")

        return {}

    def get_cve_by_id(self, cve_id: str) -> Optional[CVEItem]:
        """Direct instant retrieval for exact CVE identifiers."""
        clean_id = cve_id.strip().upper()
        params = {"cveId": clean_id}
        data = self._http_get(params)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return CVEItem.from_nvd_cve(vulns[0].get("cve", {}))
        return None

    def search(
        self,
        keyword: Optional[str] = None,
        year: Optional[int] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        cpe_name: Optional[str] = None,
        exact_match: bool = False,
        limit: Optional[int] = None,
        last_n: Optional[int] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[CVEItem], int]:
        """
        Executes an intelligent query with bidirectional scanning, early breaks, and smart pagination.
        """
        # Handle direct CVE-XXXX-YYYY syntax
        if keyword and keyword.upper().startswith("CVE-") and len(keyword.split()) == 1:
            direct_cve = self.get_cve_by_id(keyword)
            if direct_cve:
                return [direct_cve], 1
            return [], 0

        target_limit = last_n if last_n is not None else limit
        max_allowed = int(os.environ.get("SEARCHCVE_MAX_RESULTS", 1000))
        if target_limit and target_limit > max_allowed:
            target_limit = max_allowed

        base_params: Dict[str, Any] = {}

        if keyword:
            base_params["keywordSearch"] = keyword.strip()
            if exact_match:
                base_params["keywordExactMatch"] = ""

        if cpe_name:
            base_params["cpeName"] = cpe_name.strip()

        if severity:
            sev_clean = severity.upper()
            if sev_clean in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                base_params["cvssV3Severity"] = sev_clean

        # NVD 120-day limit check for date ranges
        use_api_date = False
        if from_date and to_date:
            try:
                d1 = datetime.strptime(from_date, "%Y-%m-%d")
                d2 = datetime.strptime(to_date, "%Y-%m-%d")
                delta_days = (d2 - d1).days
                if 0 <= delta_days <= 120:
                    base_params["pubStartDate"] = f"{from_date}T00:00:00.000"
                    base_params["pubEndDate"] = f"{to_date}T23:59:59.999"
                    use_api_date = True
            except ValueError:
                pass

        # Step 1: Probe to get total results count
        probe_params = dict(base_params)
        probe_params["resultsPerPage"] = 1
        probe_data = self._http_get(probe_params)
        total_results = probe_data.get("totalResults", 0)

        # Fallback query if 0 results on multi-word
        if total_results == 0 and keyword and " " in keyword and not exact_match:
            tokens = keyword.split()
            base_params["keywordSearch"] = tokens[0]
            probe_params = dict(base_params)
            probe_params["resultsPerPage"] = 1
            probe_data = self._http_get(probe_params)
            total_results = probe_data.get("totalResults", 0)

        if total_results == 0:
            return [], 0

        # Step 2: Determine scan direction
        # NVD returns results in ascending date order.
        # If user wants recent items (--last N, year >= 2023, or recent default), scan from the TAIL!
        current_year = datetime.now().year
        want_tail = False
        if last_n is not None:
            want_tail = True
        elif year is not None and year >= (current_year - 4):
            want_tail = True
        elif not year and not from_date and not to_date:
            # Default search: users almost always want recent vulnerabilities first!
            want_tail = True

        items: List[CVEItem] = []
        page_size = 100

        if want_tail:
            # Bidirectional tail scanning (backwards from newest)
            cursor = max(0, total_results - page_size)
            visited_indices = set()

            while len(items) < (target_limit or 100):
                if cursor in visited_indices:
                    break
                visited_indices.add(cursor)

                params = dict(base_params)
                params["resultsPerPage"] = page_size
                params["startIndex"] = cursor

                page_data = self._http_get(params)
                vulns = page_data.get("vulnerabilities", [])
                if not vulns:
                    break

                # Process this page in reverse order (newest first)
                for v in reversed(vulns):
                    cve_obj = CVEItem.from_nvd_cve(v.get("cve", {}))

                    # Local year filter
                    if year is not None:
                        if cve_obj.year and cve_obj.year > year:
                            # Still newer than target year, keep scanning backward
                            continue
                        elif cve_obj.year and cve_obj.year < year:
                            # We've crossed the lower year boundary! Early termination!
                            return items[:target_limit] if target_limit else items, total_results
                        elif cve_obj.year != year:
                            continue

                    # Local date range filter
                    if not use_api_date and (from_date or to_date):
                        cve_pdate = cve_obj.published_date[:10] if cve_obj.published_date else ""
                        if from_date and cve_pdate < from_date:
                            # Crossed lower date boundary, early termination!
                            return items[:target_limit] if target_limit else items, total_results
                        if to_date and cve_pdate > to_date:
                            continue

                    # Exact match check
                    if exact_match and keyword:
                        import re
                        pattern = rf"\b{re.escape(keyword)}\b"
                        if not re.search(pattern, cve_obj.description, re.IGNORECASE):
                            continue

                    items.append(cve_obj)
                    if target_limit and len(items) >= target_limit:
                        return items[:target_limit], total_results

                if cursor == 0:
                    break
                cursor = max(0, cursor - page_size)

        else:
            # Forward scanning (from beginning / oldest)
            cursor = 0
            while len(items) < (target_limit or 100):
                params = dict(base_params)
                params["resultsPerPage"] = page_size
                params["startIndex"] = cursor

                page_data = self._http_get(params)
                vulns = page_data.get("vulnerabilities", [])
                if not vulns:
                    break

                for v in vulns:
                    cve_obj = CVEItem.from_nvd_cve(v.get("cve", {}))

                    if year is not None:
                        if cve_obj.year and cve_obj.year < year:
                            continue
                        elif cve_obj.year and cve_obj.year > year:
                            # Exceeded target year forward, early break!
                            return items[:target_limit] if target_limit else items, total_results
                        elif cve_obj.year != year:
                            continue

                    if not use_api_date and (from_date or to_date):
                        cve_pdate = cve_obj.published_date[:10] if cve_obj.published_date else ""
                        if from_date and cve_pdate < from_date:
                            continue
                        if to_date and cve_pdate > to_date:
                            return items[:target_limit] if target_limit else items, total_results

                    if exact_match and keyword:
                        import re
                        pattern = rf"\b{re.escape(keyword)}\b"
                        if not re.search(pattern, cve_obj.description, re.IGNORECASE):
                            continue

                    items.append(cve_obj)
                    if target_limit and len(items) >= target_limit:
                        return items[:target_limit], total_results

                cursor += len(vulns)
                if cursor >= total_results:
                    break

        return items[:target_limit] if target_limit else items, total_results
