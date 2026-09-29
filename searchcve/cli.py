"""
CLI interface, argument parsing, interactive REPL shell, and command execution.
"""

from __future__ import annotations
import sys
import os

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import argparse
import datetime
import re
import shlex
from typing import List, Optional

from searchcve import __version__
from searchcve.models import CVEItem
from searchcve.client import NVDClient
from searchcve.enricher import ThreatEnricher
from searchcve.formatter import format_table, format_inspector_card, Colors
from searchcve.exporter import to_json, to_csv, to_markdown, to_html
from searchcve.cache import QueryCache


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="searchcve",
        description="SearchCVE Advanced v2.0 - High-Performance Threat-Enriched CVE Intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  searchcve bluetooth --last 5 --year 2025 --sort cvss
  searchcve apache --kev --has-poc
  searchcve openssh --remote --no-auth --severity CRITICAL
  searchcve CVE-2021-44228 --inspect
  searchcve wordpress --html --save report.html
  searchcve --interactive
        """,
    )

    parser.add_argument("query", nargs="?", help="Keyword, phrase, or exact CVE ID (e.g. CVE-2024-45434)")

    # Scope & Pagination
    parser.add_argument("--last", type=int, dest="last_n", metavar="N", help="Show newest N matching CVEs")
    parser.add_argument("--limit", type=int, metavar="N", help="Safety limit on candidate CVEs retrieved")
    parser.add_argument("--year", type=int, help="Filter by publication/identification year (e.g. 2025, 2026)")
    parser.add_argument("--from", dest="from_date", metavar="YYYY-MM-DD", help="Start publication date")
    parser.add_argument("--to", dest="to_date", metavar="YYYY-MM-DD", help="End publication date")

    # Threat & Vulnerability Filters
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by severity level")
    parser.add_argument("--cvss-min", type=float, metavar="SCORE", help="Minimum CVSS base score (0.0 - 10.0)")
    parser.add_argument("--cvss-max", type=float, metavar="SCORE", help="Maximum CVSS base score (0.0 - 10.0)")
    parser.add_argument("--epss-min", type=float, metavar="FLOAT", help="Minimum EPSS exploit probability (0.0 - 1.0)")
    parser.add_argument("--kev", "--exploited", action="store_true", help="Only show CVEs listed in CISA KEV (exploited in wild)")
    parser.add_argument("--has-poc", "--poc", action="store_true", help="Only show CVEs with verified public PoCs / exploits")
    parser.add_argument("--remote", action="store_true", help="Filter for remotely exploitable flaws (Attack Vector: NETWORK)")
    parser.add_argument("--no-auth", action="store_true", help="Filter for unauthenticated flaws (Privileges Required: NONE)")
    parser.add_argument("--cwe", help="Filter by CWE ID (e.g. CWE-79, CWE-89)")
    parser.add_argument("--cpe", help="Filter by Common Platform Enumeration URI")
    parser.add_argument("--exact", action="store_true", help="Exact keyword matching on word boundaries")

    # Sorting
    parser.add_argument(
        "--sort",
        choices=["date", "id", "cvss", "epss"],
        default="date",
        help="Sort results by date, id, cvss, or epss (default: date)",
    )
    parser.add_argument("--order", choices=["asc", "desc"], default="desc", help="Sort order direction (default: desc)")

    # Modes & Deep Inspection
    parser.add_argument("-d", "--inspect", action="store_true", help="Inspect and display full dossier for matching CVE(s)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive search & inspection console")
    parser.add_argument("--audit", metavar="FILE", help="Audit requirements.txt or package.json dependencies for known CVEs")
    parser.add_argument("--serve", action="store_true", help="Launch live cyber threat intelligence web dashboard server")
    parser.add_argument("--port", type=int, default=8080, help="Web dashboard server port (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser on serve")

    # Output Formats
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--csv", action="store_true", help="Export as CSV spreadsheet")
    parser.add_argument("--html", action="store_true", help="Export as interactive HTML threat report")
    parser.add_argument("--markdown", "--md", action="store_true", help="Export as GitHub Flavored Markdown table")
    parser.add_argument("-q", "--quiet", action="store_true", help="Output CVE IDs only (for Unix pipes & scripts)")
    parser.add_argument("--save", nargs="?", const="auto", help="Save output to file (default: auto filename)")

    # Cache & Connectivity
    parser.add_argument("--api-key", help="Official NIST NVD API key")
    parser.add_argument("--timeout", type=float, help="HTTP connection timeout in seconds")
    parser.add_argument("--no-cache", action="store_true", help="Disable local query caching")
    parser.add_argument("--clear-cache", action="store_true", help="Clear all local cache files")
    parser.add_argument("-v", "--version", action="version", version=f"SearchCVE Advanced v{__version__}")

    return parser


def apply_advanced_filters(items: List[CVEItem], args: argparse.Namespace) -> List[CVEItem]:
    filtered = []
    for item in items:
        # CVSS min/max
        if args.cvss_min is not None:
            if item.cvss_score is None or item.cvss_score < args.cvss_min:
                continue
        if args.cvss_max is not None:
            if item.cvss_score is None or item.cvss_score > args.cvss_max:
                continue

        # Severity
        if args.severity:
            if item.severity != args.severity.upper():
                continue

        # EPSS min
        if args.epss_min is not None:
            if not item.epss or item.epss.score < args.epss_min:
                continue

        # KEV flag
        if args.kev:
            if not item.is_kev:
                continue

        # PoC flag
        if args.has_poc:
            if not item.has_poc:
                continue

        # Remote
        if args.remote:
            if not item.is_remote:
                continue

        # No auth
        if args.no_auth:
            if not item.is_preauth:
                continue

        # CWE
        if args.cwe:
            target_cwe = args.cwe.upper()
            if not any(target_cwe in c.upper() for c in item.cwe_ids):
                continue

        filtered.append(item)
    return filtered


def sort_items(items: List[CVEItem], sort_by: str, reverse: bool = True) -> List[CVEItem]:
    if sort_by == "cvss":
        return sorted(items, key=lambda x: (x.cvss_score is not None, x.cvss_score or 0.0), reverse=reverse)
    elif sort_by == "epss":
        return sorted(items, key=lambda x: (x.epss is not None, x.epss.score if x.epss else 0.0), reverse=reverse)
    elif sort_by == "id":
        def _id_key(item: CVEItem):
            m = re.match(r"^CVE-(\d+)-(\d+)", item.id, re.IGNORECASE)
            if m:
                return int(m.group(1)), int(m.group(2))
            return 0, 0
        return sorted(items, key=_id_key, reverse=reverse)
    else:  # "date"
        return sorted(items, key=lambda x: x.published_date or "", reverse=reverse)


def execute_query(args: argparse.Namespace, client: NVDClient, enricher: ThreatEnricher) -> int:
    query = args.query.strip() if args.query else None
    is_direct_cve = bool(query and query.upper().startswith("CVE-") and len(query.split()) == 1)

    if not args.quiet and not args.json:
        q_label = query or args.cpe or f"Year {args.year}"
        print(f"{Colors.GRAY}Searching live security feeds for: {q_label}...{Colors.RESET}")

    items, total = client.search(
        keyword=query,
        year=args.year,
        from_date=args.from_date,
        to_date=args.to_date,
        cpe_name=args.cpe,
        exact_match=args.exact,
        limit=args.limit,
        last_n=args.last_n,
        severity=args.severity,
    )

    if items:
        enricher.enrich_items(items)

    items = apply_advanced_filters(items, args)

    reverse = (args.order == "desc")
    items = sort_items(items, sort_by=args.sort, reverse=reverse)

    if args.quiet:
        for it in items:
            sys.stdout.write(f"{it.id}\n")
        return 0

    output_content = ""
    target_format = "table"

    if args.json:
        output_content = to_json(items)
        target_format = "json"
    elif args.csv:
        output_content = to_csv(items)
        target_format = "csv"
    elif args.html:
        output_content = to_html(items, query_title=query or "")
        target_format = "html"
    elif args.markdown:
        output_content = to_markdown(items, query_title=query or "")
        target_format = "md"
    elif args.inspect or (is_direct_cve and len(items) == 1):
        cards = [format_inspector_card(it) for it in items]
        output_content = "\n\n".join(cards)
        target_format = "inspect"
    else:
        output_content = format_table(items, query_title=query or "")
        target_format = "table"

    save_path = args.save
    if save_path == "auto" or (len(items) > 50 and not save_path and target_format == "table"):
        sanitized_q = re.sub(r"[^\w\-]", "_", query or "results")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "html" if args.html else ("json" if args.json else ("csv" if args.csv else "txt"))
        save_path = f"searchcve_{sanitized_q}_{timestamp}.{ext}"

    if save_path:
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(output_content)
        if not args.json and not args.quiet:
            print(f"{Colors.GREEN}✔ Results saved successfully to: {save_path}{Colors.RESET}")
    else:
        print(output_content)

    return 0


def run_interactive(client: NVDClient, enricher: ThreatEnricher) -> None:
    """Live interactive search console."""
    print(f"{Colors.BOLD}{Colors.CYAN}SearchCVE Interactive Console v{__version__}{Colors.RESET}")
    print("Type keywords, CVE IDs, or 'help' for instructions. Type 'exit' to quit.\n")

    parser = create_parser()

    while True:
        try:
            raw_cmd = input(f"{Colors.BOLD}{Colors.GREEN}searchcve> {Colors.RESET}").strip()
            if not raw_cmd:
                continue
            if raw_cmd.lower() in ["exit", "quit", "q"]:
                print("Exiting.")
                break
            if raw_cmd.lower() in ["help", "?"]:
                print("Commands:")
                print("  <keyword> [options]    Search (e.g. 'bluetooth', 'bluetooth --last 5 --sort cvss')")
                print("  CVE-YYYY-NNNN          Inspect specific CVE directly")
                print("  !clear                 Clear local cache")
                print("  exit / quit            Exit console")
                continue
            if raw_cmd == "!clear":
                cache = QueryCache()
                count = cache.clear()
                print(f"Cleared {count} cached queries.")
                continue

            # Strip leading 'searchcve' if typed inside the prompt
            tokens = shlex.split(raw_cmd)
            if tokens and tokens[0].lower() == "searchcve":
                tokens = tokens[1:]

            if not tokens:
                continue

            # Auto-inspect if direct CVE ID without flags
            if len(tokens) == 1 and tokens[0].upper().startswith("CVE-"):
                tokens.append("--inspect")

            try:
                sub_args = parser.parse_args(tokens)
                execute_query(sub_args, client, enricher)
            except SystemExit:
                pass
            print("")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.clear_cache:
        cache = QueryCache()
        count = cache.clear()
        print(f"Cleared {count} cache entries.")
        return 0

    # Serve Web Dashboard
    if args.serve or (args.query and args.query.lower() == "serve"):
        from searchcve.server import start_server
        start_server(port=args.port, open_browser=not args.no_browser)
        return 0

    # Audit Dependency File
    if args.audit or (args.query and args.query.lower() == "audit"):
        from searchcve.auditor import DependencyAuditor
        target_file = args.audit
        if not target_file and argv and len(argv) >= 2:
            target_file = argv[1]
        if not target_file:
            print(f"{Colors.RED}Please specify a file to audit (e.g. searchcve audit requirements.txt){Colors.RESET}")
            return 1
        auditor = DependencyAuditor(timeout=args.timeout or 8.0)
        try:
            res = auditor.audit_file(target_file)
            print(auditor.format_audit_table(res))
            return 0
        except Exception as e:
            print(f"{Colors.RED}Audit error: {e}{Colors.RESET}")
            return 1

    client = NVDClient(
        api_key=args.api_key,
        timeout=args.timeout,
        use_cache=not args.no_cache,
    )
    enricher = ThreatEnricher(use_cache=not args.no_cache)

    if args.interactive:
        run_interactive(client, enricher)
        return 0

    if not args.query and not args.cpe and not args.year:
        parser.print_help()
        return 0

    return execute_query(args, client, enricher)


if __name__ == "__main__":
    sys.exit(main())
