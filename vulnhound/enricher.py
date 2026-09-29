"""
Enrichment module: Enriches CVE items with FIRST EPSS scores, CISA KEV status,
CWE weakness definitions, and exploit / PoC intelligence.
"""

from __future__ import annotations
import os
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor

from vulnhound.models import CVEItem, EPSSData, KEVData, PoCReference


def get_cache_dir() -> Path:
    """Return platform-appropriate cache directory."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        cache_path = Path(base) / "vulnhound"
    else:
        cache_path = Path.home() / ".cache" / "vulnhound"
    cache_path.mkdir(parents=True, exist_ok=True)
    return cache_path


CWE_NAMES: Dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "Improper Restriction of XML External Entity Reference ('XXE')",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


class ThreatEnricher:
    """
    Enriches CVEItems with EPSS data, CISA KEV records, and vulnerability classifications.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"
    KEV_CACHE_TTL = 12 * 3600  # 12 hours

    def __init__(self, timeout: float = 8.0, use_cache: bool = True):
        self.timeout = timeout
        self.use_cache = use_cache
        self._kev_map: Dict[str, KEVData] = {}
        self._kev_loaded: bool = False

    def load_cisa_kev(self, force_refresh: bool = False) -> Dict[str, KEVData]:
        """
        Loads the CISA KEV catalog with local caching for instant O(1) lookups.
        """
        if self._kev_loaded and not force_refresh:
            return self._kev_map

        cache_file = get_cache_dir() / "cisa_kev.json"
        data = None

        if self.use_cache and not force_refresh and cache_file.exists():
            try:
                mtime = cache_file.stat().st_mtime
                if (time.time() - mtime) < self.KEV_CACHE_TTL:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
            except Exception:
                data = None

        if not data:
            try:
                req = urllib.request.Request(
                    self.KEV_URL,
                    headers={"User-Agent": "VulnHound-Advanced/2.0"}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    data = json.loads(raw.decode("utf-8"))
                    if self.use_cache:
                        try:
                            with open(cache_file, "w", encoding="utf-8") as f:
                                f.write(raw.decode("utf-8"))
                        except Exception:
                            pass
            except Exception:
                # If network fails, try stale cache
                if cache_file.exists():
                    try:
                        with open(cache_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                    except Exception:
                        data = None

        if data and "vulnerabilities" in data:
            self._kev_map = {}
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cveID", "").upper()
                if cve_id:
                    self._kev_map[cve_id] = KEVData(
                        date_added=item.get("dateAdded", ""),
                        due_date=item.get("dueDate"),
                        required_action=item.get("requiredAction"),
                        notes=item.get("notes"),
                        known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                    )
            self._kev_loaded = True

        return self._kev_map

    def fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, EPSSData]:
        """
        Fetches EPSS scores for a batch of CVE IDs (up to 100 per request).
        """
        if not cve_ids:
            return {}

        results: Dict[str, EPSSData] = {}
        # Chunk into groups of 80 to stay safely below URL length limits
        chunk_size = 80
        chunks = [cve_ids[i:i + chunk_size] for i in range(0, len(cve_ids), chunk_size)]

        def _fetch_chunk(chunk: List[str]) -> Dict[str, EPSSData]:
            sub_res = {}
            query = ",".join(chunk)
            url = f"{self.EPSS_URL}?cve={query}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VulnHound-Advanced/2.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    for row in res_json.get("data", []):
                        cid = row.get("cve", "").upper()
                        score = float(row.get("epss", 0.0))
                        pct = float(row.get("percentile", 0.0))
                        date = row.get("date")
                        sub_res[cid] = EPSSData(score=score, percentile=pct, date=date)
            except Exception:
                pass
            return sub_res

        with ThreadPoolExecutor(max_workers=min(4, len(chunks) or 1)) as pool:
            futures = [pool.submit(_fetch_chunk, ch) for ch in chunks]
            for fut in futures:
                try:
                    res = fut.result()
                    results.update(res)
                except Exception:
                    pass

        return results

    def enrich_items(self, items: List[CVEItem]) -> None:
        """
        Enriches a list of CVE items with CISA KEV and EPSS data in-place.
        """
        if not items:
            return

        # 1. Enrich KEV
        kev_map = self.load_cisa_kev()
        for item in items:
            item_id = item.id.upper()
            if item_id in kev_map:
                item.kev = kev_map[item_id]

            # Populate CWE names
            for cid in item.cwe_ids:
                if cid in CWE_NAMES:
                    name = CWE_NAMES[cid]
                    if name not in item.cwe_names:
                        item.cwe_names.append(f"{cid}: {name}")

        # 2. Enrich EPSS
        cve_ids = [item.id for item in items]
        epss_map = self.fetch_epss_batch(cve_ids)
        for item in items:
            item_id = item.id.upper()
            if item_id in epss_map:
                item.epss = epss_map[item_id]
