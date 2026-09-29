"""
Built-in Live Cyber Threat Intelligence Web Dashboard Server.
Zero third-party dependencies - runs on standard library http.server.
"""

from __future__ import annotations
import json
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

from vulnhound.client import NVDClient
from vulnhound.enricher import ThreatEnricher
from vulnhound.formatter import Colors

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHound Threat Intelligence Console</title>
    <style>
        :root {
            --bg-body: #0a0d14;
            --bg-card: #121824;
            --bg-hover: #1b2333;
            --border: #232d3f;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --accent-blue: #388bfd;
            --accent-cyan: #39c5bb;
            --critical: #ff5252;
            --high: #ff9100;
            --medium: #ffd600;
            --low: #00e676;
            --purple: #b388ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg-body); color: var(--text-main); padding: 24px; }
        .navbar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
        .logo { font-size: 22px; font-weight: bold; color: var(--accent-blue); display: flex; align-items: center; gap: 8px; }
        .logo span { color: var(--accent-cyan); }
        .status-badge { background: rgba(57, 197, 187, 0.15); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); border-radius: 20px; font-size: 11px; padding: 4px 10px; font-weight: bold; }
        .search-container { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 24px; }
        .search-row { display: flex; gap: 12px; flex-wrap: wrap; }
        .search-input { flex-grow: 1; min-width: 280px; padding: 12px 16px; background: #070a0e; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 14px; outline: none; }
        .search-input:focus { border-color: var(--accent-blue); }
        .btn-search { padding: 12px 24px; background: var(--accent-blue); border: none; border-radius: 6px; color: #fff; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .btn-search:hover { background: #1f6feb; }
        .filters-row { display: flex; gap: 16px; margin-top: 14px; align-items: center; flex-wrap: wrap; font-size: 13px; color: var(--text-muted); }
        select, input[type="number"] { background: #070a0e; border: 1px solid var(--border); color: #fff; padding: 6px 10px; border-radius: 4px; outline: none; }
        .table-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        th, td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        th { background: #0e131d; color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
        tr:hover { background: var(--bg-hover); }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .badge-critical { background: rgba(255, 82, 82, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge-high { background: rgba(255, 145, 0, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-medium { background: rgba(255, 214, 0, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge-low { background: rgba(0, 230, 118, 0.2); color: var(--low); border: 1px solid var(--low); }
        .badge-kev { background: #d32f2f; color: #fff; }
        .badge-poc { background: rgba(179, 136, 255, 0.2); color: var(--purple); border: 1px solid var(--purple); }
        .cve-id { color: #58a6ff; font-weight: bold; cursor: pointer; text-decoration: none; }
        .cve-id:hover { text-decoration: underline; }
        .loading { text-align: center; padding: 40px; color: var(--text-muted); font-size: 14px; }
        /* Modal */
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); z-index: 100; align-items: center; justify-content: center; padding: 20px; }
        .modal-content { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; max-width: 750px; width: 100%; max-height: 85vh; overflow-y: auto; padding: 24px; position: relative; }
        .modal-close { position: absolute; top: 16px; right: 16px; font-size: 20px; color: var(--text-muted); cursor: pointer; background: none; border: none; }
        .modal-title { font-size: 20px; color: var(--accent-blue); margin-bottom: 12px; }
        .modal-section { margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px; font-size: 13px; line-height: 1.5; }
        .modal-section h4 { color: var(--accent-cyan); margin-bottom: 6px; font-size: 12px; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">🛡️ VulnHound <span>Advanced</span> Console</div>
        <div class="status-badge">⚡ Real-time NIST NVD 2.0 &amp; EPSS Live</div>
    </div>

    <div class="search-container">
        <div class="search-row">
            <input type="text" id="queryInput" class="search-input" placeholder="Search CVE ID, vendor, or keyword (e.g. bluetooth, apache, CVE-2021-44228)..." onkeydown="if(event.key==='Enter') doSearch()">
            <button class="btn-search" onclick="doSearch()">Search Threat Feeds</button>
        </div>
        <div class="filters-row">
            <label>Limit: <input type="number" id="limitInput" value="10" min="1" max="50" style="width: 60px;"></label>
            <label>Year: <input type="number" id="yearInput" placeholder="All" style="width: 75px;"></label>
            <label>Sort By: 
                <select id="sortSelect">
                    <option value="cvss">Highest CVSS Score</option>
                    <option value="epss">Highest EPSS Exploit Probability</option>
                    <option value="date" selected>Newest Publication Date</option>
                </select>
            </label>
        </div>
    </div>

    <div class="table-box">
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>CVSS</th>
                    <th>EPSS %</th>
                    <th>Threats</th>
                    <th>CVE ID</th>
                    <th>Published</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <tr><td colspan="6" class="loading">Enter a query above to start live vulnerability threat hunting.</td></tr>
            </tbody>
        </table>
    </div>

    <div id="modalOverlay" class="modal-overlay" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <button class="modal-close" onclick="closeModal()">&times;</button>
            <h2 id="modalTitle" class="modal-title">CVE-xxxx</h2>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        let cachedItems = [];

        async function doSearch() {
            const q = document.getElementById('queryInput').value.trim();
            if (!q) return;

            const limit = document.getElementById('limitInput').value;
            const year = document.getElementById('yearInput').value;
            const sort = document.getElementById('sortSelect').value;

            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '<tr><td colspan="6" class="loading">Querying NIST NVD &amp; FIRST EPSS live feeds...</td></tr>';

            try {
                let url = `/api/search?q=${encodeURIComponent(q)}&limit=${limit}&sort=${sort}`;
                if (year) url += `&year=${year}`;

                const res = await fetch(url);
                const data = await res.json();
                cachedItems = data;
                renderTable(data);
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" class="loading" style="color:#ff5252">Search failed: ${err}</td></tr>`;
            }
        }

        function renderTable(items) {
            const tbody = document.getElementById('tableBody');
            if (!items || items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="loading">No matching CVEs found.</td></tr>';
                return;
            }

            tbody.innerHTML = items.map((item, idx) => {
                const score = item.cvss_score !== null ? item.cvss_score.toFixed(1) : 'N/A';
                const sev = (item.severity || 'unknown').toLowerCase();
                const epss = item.epss ? (item.epss.score * 100).toFixed(1) + '%' : '-';
                
                const kevBadge = item.is_kev ? '<span class="badge badge-kev">KEV IN-WILD</span>' : '';
                const pocBadge = item.has_poc ? `<span class="badge badge-poc">PoC (${item.pocs.length})</span>` : '';
                const badges = [kevBadge, pocBadge].filter(Boolean).join(' ') || '<span style="color:#666">-</span>';
                const pdate = (item.published_date || '').slice(0, 10);
                const desc = (item.description || '').slice(0, 110) + '...';

                return `
                    <tr>
                        <td><span class="badge badge-${sev}">${score}</span></td>
                        <td><strong>${epss}</strong></td>
                        <td>${badges}</td>
                        <td><a href="javascript:void(0)" class="cve-id" onclick="openModal(${idx})">${item.id}</a></td>
                        <td style="color:#8b949e">${pdate}</td>
                        <td style="color:#c9d1d9">${desc}</td>
                    </tr>
                `;
            }).join('');
        }

        function openModal(idx) {
            const item = cachedItems[idx];
            if (!item) return;

            document.getElementById('modalTitle').innerText = `${item.id} Dossier`;
            const score = item.cvss_score !== null ? item.cvss_score.toFixed(1) : 'N/A';
            const epss = item.epss ? `${(item.epss.score * 100).toFixed(2)}% (Percentile: ${(item.epss.percentile * 100).toFixed(1)}th)` : 'Not available';

            let pocsHtml = '<p style="color:#8b949e">No verified public PoCs recorded.</p>';
            if (item.pocs && item.pocs.length > 0) {
                pocsHtml = item.pocs.map(p => `<div>• <strong>[${p.poc_type}]</strong> <a href="${p.url}" target="_blank" style="color:#58a6ff">${p.url}</a></div>`).join('');
            }

            let kevHtml = '<p style="color:#8b949e">Not listed in CISA KEV catalog.</p>';
            if (item.is_kev && item.kev) {
                kevHtml = `
                    <div style="background:rgba(211,47,47,0.2); padding:10px; border-radius:4px; border:1px solid #d32f2f">
                        <div>🚨 <strong>CISA Known Exploited Vulnerability</strong></div>
                        <div>Date Added: ${item.kev.date_added} | Ransomware Use: ${item.kev.known_ransomware_campaign_use}</div>
                        <div style="margin-top:4px">Action: ${item.kev.required_action || 'Apply official patches immediately.'}</div>
                    </div>
                `;
            }

            document.getElementById('modalBody').innerHTML = `
                <div style="margin-bottom:12px">
                    <span class="badge badge-${(item.severity||'unknown').toLowerCase()}">${score} ${item.severity}</span>
                    <span style="margin-left:12px; color:#8b949e">EPSS: ${epss}</span>
                </div>
                <div class="modal-section">
                    <h4>Description</h4>
                    <p>${item.description || 'No description available.'}</p>
                </div>
                <div class="modal-section">
                    <h4>CISA Threat Intelligence</h4>
                    ${kevHtml}
                </div>
                <div class="modal-section">
                    <h4>Discovered Exploits &amp; PoC Links (${item.pocs.length})</h4>
                    ${pocsHtml}
                </div>
            `;

            document.getElementById('modalOverlay').style.display = 'flex';
        }

        function closeModal() {
            document.getElementById('modalOverlay').style.display = 'none';
        }
    </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    client: Optional[NVDClient] = None
    enricher: Optional[ThreatEnricher] = None

    def log_message(self, format, *args):
        # Mute default HTTP request logging to keep terminal clean
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        elif path == "/api/search":
            q = query_params.get("q", [""])[0]
            limit_val = int(query_params.get("limit", [10])[0])
            sort_val = query_params.get("sort", ["date"])[0]
            year_val = query_params.get("year", [None])[0]
            year_int = int(year_val) if (year_val and year_val.isdigit()) else None

            if self.client and self.enricher:
                items, _ = self.client.search(
                    keyword=q,
                    year=year_int,
                    limit=limit_val,
                )
                if items:
                    self.enricher.enrich_items(items)

                # Sorting
                if sort_val == "cvss":
                    items = sorted(items, key=lambda x: (x.cvss_score is not None, x.cvss_score or 0.0), reverse=True)
                elif sort_val == "epss":
                    items = sorted(items, key=lambda x: (x.epss is not None, x.epss.score if x.epss else 0.0), reverse=True)
                else:
                    items = sorted(items, key=lambda x: x.published_date or "", reverse=True)

                raw_json = json.dumps([it.to_dict() for it in items], ensure_ascii=False)
            else:
                raw_json = "[]"

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(raw_json.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def start_server(port: int = 8080, open_browser: bool = True) -> None:
    """Launches local web dashboard server."""
    client = NVDClient()
    enricher = ThreatEnricher()

    DashboardHandler.client = client
    DashboardHandler.enricher = enricher

    server = HTTPServer(("127.0.0.1", port), DashboardHandler)
    url = f"http://localhost:{port}"

    print(f"{Colors.BOLD}{Colors.CYAN}VulnHound Threat Intelligence Dashboard Server{Colors.RESET}")
    print(f"{Colors.GREEN}✔ Web Console running at: {Colors.BOLD}{url}{Colors.RESET}")
    print(f"{Colors.GRAY}Press Ctrl+C to stop the server.{Colors.RESET}\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server.")
        server.server_close()
