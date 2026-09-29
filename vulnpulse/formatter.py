"""
Terminal UI formatting, ANSI color rendering, SearchSploit-style table layout,
and comprehensive CVE dossier inspector cards.
"""

from __future__ import annotations
import os
import sys
import shutil
import textwrap
from typing import List, Optional

from vulnpulse.models import CVEItem


def _init_windows_vt() -> None:
    """Enable VT100 ANSI sequences on Windows console."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # STD_OUTPUT_HANDLE = -11
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            h_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            kernel32.GetConsoleMode(h_out, ctypes.byref(mode))
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004 | 0x0001)
        except Exception:
            pass


_init_windows_vt()


class Colors:
    """ANSI color codes with NO_COLOR environment variable support."""
    _no_color = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()

    RESET = "" if _no_color else "\033[0m"
    BOLD = "" if _no_color else "\033[1m"
    DIM = "" if _no_color else "\033[2m"
    UNDERLINE = "" if _no_color else "\033[4m"

    RED = "" if _no_color else "\033[91m"
    GREEN = "" if _no_color else "\033[92m"
    YELLOW = "" if _no_color else "\033[93m"
    BLUE = "" if _no_color else "\033[94m"
    MAGENTA = "" if _no_color else "\033[95m"
    CYAN = "" if _no_color else "\033[96m"
    WHITE = "" if _no_color else "\033[97m"
    GRAY = "" if _no_color else "\033[90m"

    BG_RED = "" if _no_color else "\033[41m\033[97m"
    BG_YELLOW = "" if _no_color else "\033[43m\033[30m"
    BG_BLUE = "" if _no_color else "\033[44m\033[97m"
    BG_MAGENTA = "" if _no_color else "\033[45m\033[97m"

    @classmethod
    def disable(cls) -> None:
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


def get_severity_color(severity: str, score: Optional[float] = None) -> str:
    sev = severity.upper()
    if sev == "CRITICAL" or (score is not None and score >= 9.0):
        return Colors.RED + Colors.BOLD
    elif sev == "HIGH" or (score is not None and score >= 7.0):
        return Colors.YELLOW + Colors.BOLD
    elif sev == "MEDIUM" or (score is not None and score >= 4.0):
        return Colors.YELLOW
    elif sev == "LOW" or (score is not None and score > 0.0):
        return Colors.GREEN
    return Colors.GRAY


def format_table(items: List[CVEItem], query_title: str = "") -> str:
    """
    Renders an enhanced SearchSploit-style 5-column table:
    CVSS | EPSS | KEV | PoC | CVE-ID | Description
    """
    term_width = shutil.get_terminal_size((80, 24)).columns
    term_width = max(80, min(term_width, 140))

    lines = []
    lines.append(f"{Colors.BOLD}{Colors.CYAN}VulnPulse Advanced v2.0.0{Colors.RESET}")
    lines.append(f"{Colors.GRAY}{'─' * term_width}{Colors.RESET}")
    if query_title:
        lines.append(f"{Colors.BOLD}Query:{Colors.RESET} {query_title}")
        lines.append("")

    header = (
        f" {Colors.BOLD}{'CVSS':<5} "
        f"{'EPSS':<7} "
        f"{'THREAT':<9} "
        f"{'CVE ID':<16} "
        f"{'Description':<{term_width - 45}}{Colors.RESET}"
    )
    lines.append(header)
    lines.append(f"{Colors.GRAY}{'─' * term_width}{Colors.RESET}")

    desc_width = max(30, term_width - 45)

    for item in items:
        # CVSS column
        score = item.cvss_score
        score_str = f"{score:4.1f}" if score is not None else " N/A"
        color = get_severity_color(item.severity, score)
        cvss_col = f"{color}{score_str:<5}{Colors.RESET}"

        # EPSS column
        if item.epss:
            epss_pct = item.epss.score * 100
            epss_color = Colors.RED if epss_pct >= 50 else (Colors.YELLOW if epss_pct >= 10 else Colors.GRAY)
            epss_col = f"{epss_color}{epss_pct:5.1f}%{Colors.RESET}"
        else:
            epss_col = f"{Colors.GRAY}  -   {Colors.RESET}"

        # Threat badges (KEV / PoC)
        badges = []
        if item.is_kev:
            badges.append(f"{Colors.BG_RED}KEV{Colors.RESET}")
        if item.has_poc:
            badges.append(f"{Colors.MAGENTA}PoC{Colors.RESET}")
        threat_col = " ".join(badges) if badges else f"{Colors.GRAY}-{Colors.RESET}"
        # Visual width compensation for ANSI
        raw_threat_len = (3 if item.is_kev else 0) + (3 if item.has_poc else 0) + (1 if item.is_kev and item.has_poc else 0)
        if raw_threat_len == 0:
            raw_threat_len = 1
        threat_padding = " " * max(0, 9 - raw_threat_len)
        threat_col = f"{threat_col}{threat_padding}"

        # CVE ID column
        cve_col = f"{Colors.BOLD}{item.id:<16}{Colors.RESET}"

        # Description wrap
        wrapped_desc = textwrap.wrap(item.description or "No description provided.", width=desc_width)
        if not wrapped_desc:
            wrapped_desc = [""]

        first_line = f" {cvss_col} {epss_col} {threat_col} {cve_col} {wrapped_desc[0]}"
        lines.append(first_line)

        # Continuation lines for multi-line description
        indent = " " * 44
        for cont in wrapped_desc[1:4]:  # Show up to 4 lines
            lines.append(f"{indent}{cont}")
        if len(wrapped_desc) > 4:
            lines.append(f"{indent}{Colors.GRAY}... [truncated]{Colors.RESET}")
        lines.append("")

    lines.append(f"{Colors.GRAY}{'─' * term_width}{Colors.RESET}")

    kev_count = sum(1 for x in items if x.is_kev)
    poc_count = sum(1 for x in items if x.has_poc)
    critical_count = sum(1 for x in items if x.severity == "CRITICAL")

    summary_parts = [f"Found: {Colors.BOLD}{len(items)}{Colors.RESET} CVEs"]
    if critical_count:
        summary_parts.append(f"{Colors.RED}{critical_count} Critical{Colors.RESET}")
    if kev_count:
        summary_parts.append(f"{Colors.BG_RED} {kev_count} in CISA KEV {Colors.RESET}")
    if poc_count:
        summary_parts.append(f"{Colors.MAGENTA}{poc_count} with Public PoC{Colors.RESET}")

    lines.append(" | ".join(summary_parts))
    return "\n".join(lines)


def format_inspector_card(item: CVEItem) -> str:
    """
    Renders an in-depth vulnerability intelligence report / inspector card for a single CVE.
    """
    term_width = shutil.get_terminal_size((80, 24)).columns
    card_width = min(term_width, 100)

    lines = []
    lines.append(f"{Colors.BOLD}{Colors.CYAN}┌{'─' * (card_width - 2)}┐{Colors.RESET}")
    
    # Title bar
    title = f" CVE DOSSIER: {item.id} "
    lines.append(f"{Colors.BOLD}{Colors.CYAN}│{title.center(card_width - 2)}│{Colors.RESET}")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}├{'─' * (card_width - 2)}┤{Colors.RESET}")

    # Severity & CVSS
    score = item.cvss_score
    score_str = f"{score:.1f}" if score is not None else "N/A"
    sev_color = get_severity_color(item.severity, score)
    cvss_ver = item.metrics.version if item.metrics else "3.1"
    lines.append(
        f"  {Colors.BOLD}CVSS v{cvss_ver} Score:{Colors.RESET} {sev_color}{score_str} ({item.severity}){Colors.RESET}"
    )
    if item.metrics and item.metrics.vector_string:
        lines.append(f"  {Colors.BOLD}Vector String:{Colors.RESET} {item.metrics.vector_string}")

    # Metrics Breakdown
    if item.metrics:
        m = item.metrics
        parts = []
        if m.attack_vector:
            parts.append(f"Vector: {m.attack_vector}")
        if m.attack_complexity:
            parts.append(f"Complexity: {m.attack_complexity}")
        if m.privileges_required:
            parts.append(f"Privileges: {m.privileges_required}")
        if m.user_interaction:
            parts.append(f"User Interaction: {m.user_interaction}")
        if parts:
            lines.append(f"  {Colors.BOLD}CVSS Breakdown:{Colors.RESET} {' | '.join(parts)}")

    # Threat Intelligence (EPSS & KEV)
    lines.append("")
    lines.append(f"  {Colors.BOLD}{Colors.YELLOW}Threat Intelligence & Exploitability:{Colors.RESET}")

    # EPSS
    if item.epss:
        epss_pct = item.epss.score * 100
        epss_color = Colors.RED if epss_pct >= 50 else (Colors.YELLOW if epss_pct >= 10 else Colors.GREEN)
        lines.append(
            f"  • {Colors.BOLD}EPSS Exploit Probability:{Colors.RESET} "
            f"{epss_color}{epss_pct:.2f}%{Colors.RESET} (Percentile: {item.epss.percentile_str})"
        )
    else:
        lines.append(f"  • {Colors.BOLD}EPSS Exploit Probability:{Colors.RESET} Not Available")

    # CISA KEV
    if item.is_kev and item.kev:
        lines.append(
            f"  • {Colors.BG_RED} CISA KNOWN EXPLOITED VULNERABILITY {Colors.RESET}"
        )
        lines.append(f"    - Date Added to KEV: {item.kev.date_added}")
        if item.kev.due_date:
            lines.append(f"    - Remediation Due Date: {item.kev.due_date}")
        lines.append(f"    - Known Ransomware Campaign Use: {item.kev.known_ransomware_campaign_use}")
        if item.kev.required_action:
            lines.append(f"    - Required Action: {item.kev.required_action}")
    else:
        lines.append(f"  • {Colors.BOLD}CISA KEV Status:{Colors.RESET} Not currently listed in CISA KEV catalog")

    # CWE
    if item.cwe_ids or item.cwe_names:
        cwe_display = ", ".join(item.cwe_names) if item.cwe_names else ", ".join(item.cwe_ids)
        lines.append(f"  • {Colors.BOLD}Weakness Type (CWE):{Colors.RESET} {cwe_display}")

    # Dates
    lines.append(f"  • {Colors.BOLD}Published Date:{Colors.RESET} {item.published_date[:10]} | {Colors.BOLD}Last Modified:{Colors.RESET} {item.last_modified_date[:10]}")

    # Description
    lines.append("")
    lines.append(f"  {Colors.BOLD}Description:{Colors.RESET}")
    for dl in textwrap.wrap(item.description or "No description", width=card_width - 6):
        lines.append(f"    {dl}")

    # Exploits & PoCs
    if item.pocs:
        lines.append("")
        lines.append(f"  {Colors.BOLD}{Colors.MAGENTA}Discovered Public Exploits & PoCs ({len(item.pocs)}):{Colors.RESET}")
        for p in item.pocs:
            lines.append(f"    [{Colors.BOLD}{p.poc_type}{Colors.RESET}] {p.url}")

    # Affected CPEs
    if item.cpe_list:
        lines.append("")
        lines.append(f"  {Colors.BOLD}Affected Configurations / CPEs ({len(item.cpe_list)}):{Colors.RESET}")
        for cpe in item.cpe_list[:5]:
            lines.append(f"    - {cpe}")
        if len(item.cpe_list) > 5:
            lines.append(f"    - ... and {len(item.cpe_list) - 5} more configurations")

    # Key References
    if item.references:
        lines.append("")
        lines.append(f"  {Colors.BOLD}References & Advisories:{Colors.RESET}")
        for ref in item.references[:6]:
            url = ref.get("url", "")
            tags = ref.get("tags") or []
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            lines.append(f"    - {url}{Colors.GRAY}{tag_str}{Colors.RESET}")
        if len(item.references) > 6:
            lines.append(f"    - ... and {len(item.references) - 6} more references")

    lines.append(f"{Colors.BOLD}{Colors.CYAN}└{'─' * (card_width - 2)}┘{Colors.RESET}")
    return "\n".join(lines)
