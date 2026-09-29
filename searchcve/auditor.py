"""
Project Dependency & SBOM Security Auditor:
Scans requirements.txt and package.json files for known vulnerabilities via OSV.dev.
"""

from __future__ import annotations
import os
import re
import json
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

from searchcve.formatter import Colors


class DependencyAuditor:
    OSV_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    @staticmethod
    def parse_requirements_txt(content: str) -> List[Tuple[str, Optional[str]]]:
        """Parses Python requirements.txt file and extracts (package, version)."""
        packages: List[Tuple[str, Optional[str]]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Strip comments
            line = line.split("#")[0].strip()

            # Match pinned or bounded versions: pkg==1.0.0, pkg>=1.0.0, pkg~=1.0.0
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-]+)", line)
            if m:
                packages.append((m.group(1), m.group(2)))
            else:
                # Raw package without version
                clean_name = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
                if clean_name:
                    packages.append((clean_name.group(1), None))
        return packages

    @staticmethod
    def parse_package_json(content: str) -> List[Tuple[str, Optional[str]]]:
        """Parses Node.js package.json file and extracts (package, version)."""
        packages: List[Tuple[str, Optional[str]]] = []
        try:
            data = json.loads(content)
            deps = {}
            if "dependencies" in data and isinstance(data["dependencies"], dict):
                deps.update(data["dependencies"])
            if "devDependencies" in data and isinstance(data["devDependencies"], dict):
                deps.update(data["devDependencies"])

            for pkg_name, ver_str in deps.items():
                if isinstance(ver_str, str):
                    # Clean semver prefix: ^1.2.3, ~1.2.3 -> 1.2.3
                    clean_ver = re.sub(r"^[\^~>=<v\s]+", "", ver_str).strip()
                    packages.append((pkg_name, clean_ver if clean_ver else None))
        except Exception:
            pass
        return packages

    def query_osv(self, package: str, version: Optional[str], ecosystem: str) -> List[Dict[str, Any]]:
        """Queries OSV.dev for known vulnerabilities."""
        req_body: Dict[str, Any] = {
            "package": {"name": package, "ecosystem": ecosystem}
        }
        if version:
            req_body["version"] = version

        try:
            raw_data = json.dumps(req_body).encode("utf-8")
            req = urllib.request.Request(
                self.OSV_URL,
                data=raw_data,
                headers={"Content-Type": "application/json", "User-Agent": "SearchCVE-Auditor/2.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    return res_json.get("vulns", [])
        except Exception:
            pass
        return []

    def audit_file(self, file_path: str) -> Dict[str, Any]:
        """Audits a project file and returns aggregated vulnerability results."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        fname = p.name.lower()
        content = p.read_text(encoding="utf-8", errors="replace")

        if fname.endswith(".json") or "package" in fname:
            ecosystem = "npm"
            packages = self.parse_package_json(content)
        else:
            ecosystem = "PyPI"
            packages = self.parse_requirements_txt(content)

        findings: List[Dict[str, Any]] = []

        def _scan(pkg_info: Tuple[str, Optional[str]]):
            pkg, ver = pkg_info
            vulns = self.query_osv(pkg, ver, ecosystem)
            if vulns:
                for v in vulns:
                    # Extract CVE aliases
                    cve_aliases = [a for a in v.get("aliases", []) if a.upper().startswith("CVE-")]
                    primary_id = cve_aliases[0] if cve_aliases else v.get("id", "")
                    
                    # Extract fixed versions if available
                    fixed_versions = []
                    for affected in v.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_versions.append(event["fixed"])

                    findings.append({
                        "package": pkg,
                        "version": ver or "Unspecified",
                        "ecosystem": ecosystem,
                        "id": primary_id,
                        "summary": v.get("summary") or v.get("details", "")[:120],
                        "fixed": fixed_versions[0] if fixed_versions else "See Advisory",
                    })

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_scan, packages))

        return {
            "file": str(p),
            "ecosystem": ecosystem,
            "total_packages": len(packages),
            "vulnerable_count": len(findings),
            "findings": findings,
        }

    @staticmethod
    def format_audit_table(result: Dict[str, Any]) -> str:
        """Renders an audit summary in terminal format."""
        lines = []
        lines.append(f"{Colors.BOLD}{Colors.CYAN}SearchCVE Dependency Audit Report{Colors.RESET}")
        lines.append(f"{Colors.GRAY}{'─' * 80}{Colors.RESET}")
        lines.append(f"Target: {Colors.BOLD}{result['file']}{Colors.RESET} ({result['ecosystem']})")
        lines.append(f"Scanned: {result['total_packages']} packages | Vulnerabilities: {Colors.RED if result['vulnerable_count'] else Colors.GREEN}{result['vulnerable_count']} found{Colors.RESET}\n")

        if not result["findings"]:
            lines.append(f"{Colors.GREEN}✔ No known vulnerabilities detected in scanned dependencies!{Colors.RESET}")
            lines.append(f"{Colors.GRAY}{'─' * 80}{Colors.RESET}")
            return "\n".join(lines)

        header = f" {'PACKAGE':<18} {'VERSION':<10} {'CVE / ADVISORY':<18} {'FIXED IN':<12} {'SUMMARY'}"
        lines.append(f"{Colors.BOLD}{header}{Colors.RESET}")
        lines.append(f"{Colors.GRAY}{'─' * 80}{Colors.RESET}")

        for f in result["findings"]:
            summary = (f["summary"] or "").replace("\n", " ")
            if len(summary) > 35:
                summary = summary[:32] + "..."
            lines.append(
                f" {Colors.BOLD}{f['package']:<18}{Colors.RESET} "
                f"{f['version']:<10} "
                f"{Colors.RED}{f['id']:<18}{Colors.RESET} "
                f"{Colors.GREEN}{f['fixed']:<12}{Colors.RESET} "
                f"{summary}"
            )

        lines.append(f"{Colors.GRAY}{'─' * 80}{Colors.RESET}")
        lines.append(f"{Colors.YELLOW}Recommendation: Update affected packages to their fixed versions.{Colors.RESET}")
        return "\n".join(lines)
