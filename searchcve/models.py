"""
Data models representing Common Vulnerabilities and Exposures (CVE) and enriched threat metadata.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import re


@dataclass
class Metrics:
    base_score: Optional[float] = None
    version: str = "3.1"
    vector_string: Optional[str] = None
    severity: str = "UNKNOWN"
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

    @classmethod
    def from_nvd_metrics(cls, metrics_dict: Dict[str, Any]) -> Optional[Metrics]:
        if not metrics_dict:
            return None

        # Preference order: CVSS v4.0 -> CVSS v3.1 -> CVSS v3.0 -> CVSS v2.0
        for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics_dict.get(key, [])
            if not metric_list:
                continue

            # Pick primary if available, otherwise first item
            primary = next((m for m in metric_list if m.get("type") == "Primary"), metric_list[0])
            cvss_data = primary.get("cvssData", {})

            version = cvss_data.get("version", "3.1")
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                base_score = float(base_score)

            vector_string = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity") or primary.get("baseSeverity") or "UNKNOWN"
            if base_score is not None and severity == "UNKNOWN":
                if base_score >= 9.0:
                    severity = "CRITICAL"
                elif base_score >= 7.0:
                    severity = "HIGH"
                elif base_score >= 4.0:
                    severity = "MEDIUM"
                elif base_score > 0.0:
                    severity = "LOW"
                else:
                    severity = "NONE"

            attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
            attack_complexity = cvss_data.get("attackComplexity") or cvss_data.get("accessComplexity")
            privileges_required = cvss_data.get("privilegesRequired") or cvss_data.get("authentication")
            user_interaction = cvss_data.get("userInteraction")

            return cls(
                base_score=base_score,
                version=version,
                vector_string=vector_string,
                severity=severity.upper(),
                attack_vector=attack_vector.upper() if attack_vector else None,
                attack_complexity=attack_complexity.upper() if attack_complexity else None,
                privileges_required=privileges_required.upper() if privileges_required else None,
                user_interaction=user_interaction.upper() if user_interaction else None,
                exploitability_score=primary.get("exploitabilityScore"),
                impact_score=primary.get("impactScore"),
            )
        return None


@dataclass
class EPSSData:
    score: float
    percentile: float
    date: Optional[str] = None

    @property
    def percentage_str(self) -> str:
        return f"{self.score * 100:.2f}%"

    @property
    def percentile_str(self) -> str:
        return f"{self.percentile * 100:.1f}th"


@dataclass
class KEVData:
    date_added: str
    due_date: Optional[str] = None
    required_action: Optional[str] = None
    notes: Optional[str] = None
    known_ransomware_campaign_use: str = "Unknown"


@dataclass
class PoCReference:
    url: str
    source: str
    poc_type: str  # "Exploit-DB", "GitHub PoC", "PacketStorm", "Metasploit", "Advisory", "Patch"


@dataclass
class CVEItem:
    id: str
    description: str
    published_date: str
    last_modified_date: str
    metrics: Optional[Metrics] = None
    cwe_ids: List[str] = field(default_factory=list)
    cwe_names: List[str] = field(default_factory=list)
    cpe_list: List[str] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    epss: Optional[EPSSData] = None
    kev: Optional[KEVData] = None
    pocs: List[PoCReference] = field(default_factory=list)

    @property
    def cvss_score(self) -> Optional[float]:
        return self.metrics.base_score if self.metrics else None

    @property
    def severity(self) -> str:
        return self.metrics.severity if self.metrics else "UNKNOWN"

    @property
    def is_kev(self) -> bool:
        return self.kev is not None

    @property
    def has_poc(self) -> bool:
        return len(self.pocs) > 0

    @property
    def is_remote(self) -> bool:
        if self.metrics and self.metrics.attack_vector:
            return self.metrics.attack_vector == "NETWORK"
        return False

    @property
    def is_preauth(self) -> bool:
        if self.metrics and self.metrics.privileges_required:
            return self.metrics.privileges_required in ["NONE", "NONE_REQUIRED"]
        return False

    @property
    def year(self) -> Optional[int]:
        # Prioritize publication year
        if self.published_date and len(self.published_date) >= 4:
            try:
                return int(self.published_date[:4])
            except ValueError:
                pass
        # Fallback to CVE ID year
        m = re.match(r"^CVE-(\d{4})-", self.id, re.IGNORECASE)
        if m:
            return int(m.group(1))
        return None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["cvss_score"] = self.cvss_score
        data["severity"] = self.severity
        data["is_kev"] = self.is_kev
        data["has_poc"] = self.has_poc
        data["is_remote"] = self.is_remote
        data["is_preauth"] = self.is_preauth
        return data

    @classmethod
    def from_nvd_cve(cls, cve_dict: Dict[str, Any]) -> CVEItem:
        cve_id = cve_dict.get("id", "")

        # Description
        descriptions = cve_dict.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        pub_date = cve_dict.get("published", "")
        mod_date = cve_dict.get("lastModified", "")

        # Metrics
        metrics = Metrics.from_nvd_metrics(cve_dict.get("metrics", {}))

        # CWE
        cwe_ids = []
        cwe_names = []
        weaknesses = cve_dict.get("weaknesses", [])
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val and val != "NVD-CWE-noinfo" and val != "NVD-CWE-Other":
                    cwe_ids.append(val)

        # Configurations / CPEs
        cpe_list = []
        configs = cve_dict.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe and cpe not in cpe_list:
                        cpe_list.append(cpe)

        # References
        references = cve_dict.get("references", [])

        # Detect PoCs in references
        pocs: List[PoCReference] = []
        seen_urls = set()
        for ref in references:
            url = ref.get("url", "")
            if not url or url in seen_urls:
                continue

            tags = ref.get("tags") or []
            url_lower = url.lower()

            is_poc = False
            poc_type = "PoC"

            if any("exploit" in t.lower() for t in tags):
                is_poc = True
                poc_type = "Verified Exploit"

            if "exploit-db.com" in url_lower:
                is_poc = True
                poc_type = "Exploit-DB"
            elif "github.com" in url_lower and any(k in url_lower for k in ["/poc", "exploit", "cve-", "vulnerability"]):
                is_poc = True
                poc_type = "GitHub PoC"
            elif "packetstormsecurity.com" in url_lower:
                is_poc = True
                poc_type = "PacketStorm"
            elif "rapid7.com/db/modules" in url_lower:
                is_poc = True
                poc_type = "Metasploit"
            elif "0day.today" in url_lower:
                is_poc = True
                poc_type = "0day.today"
            elif "vulncheck.com" in url_lower:
                is_poc = True
                poc_type = "VulnCheck"

            if is_poc:
                seen_urls.add(url)
                pocs.append(PoCReference(url=url, source=ref.get("source", ""), poc_type=poc_type))

        return cls(
            id=cve_id,
            description=desc,
            published_date=pub_date,
            last_modified_date=mod_date,
            metrics=metrics,
            cwe_ids=cwe_ids,
            cwe_names=cwe_names,
            cpe_list=cpe_list,
            references=references,
            pocs=pocs,
        )
