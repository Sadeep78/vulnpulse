# VulnPulse Advanced v2.0 🛡️🔍

> **A Next-Generation, Threat-Enriched Cyber Vulnerability Intelligence CLI & Engine.**  
> Searches the official NIST National Vulnerability Database (NVD) REST API 2.0 in real time and automatically enriches every vulnerability with **FIRST EPSS Exploit Predictions**, **CISA Known Exploited Vulnerabilities (KEV)**, **public Proof-of-Concepts (Exploit-DB, GitHub, PacketStorm)**, and **CWE classifications**.

> [!IMPORTANT]
> ### 🔒 Access & Usage Policy (Owner Permission Required)
> **Copyright © 2026 Sadeep78. All Rights Reserved.**  
> This repository is publicly viewable for showcase and educational reference only. **No unauthorized copying, redistribution, modification, sublicensing, deployment, or commercial usage of this codebase is permitted without explicit prior written permission from the owner ([@Sadeep78](https://github.com/Sadeep78)).**

---

## ⚡ Key Features & Capabilities

- 🔍 **Real-Time Multi-Feed Intelligence**: Live queries against NIST NVD 2.0, FIRST EPSS, CISA KEV, and OSV databases.
- 🎯 **EPSS Exploit Prediction**: Real-time exploit probability percentages (0-100%) and percentile rankings.
- 🚨 **CISA KEV Integration**: Identifies vulnerabilities actively exploited in the wild with ransomware campaign tracking.
- 🔥 **Public PoC & Exploit Discovery**: Automatically identifies verified public exploits and PoCs (Exploit-DB, GitHub, PacketStorm).
- 📦 **Dependency & SBOM Auditor (SCA)**: Scans Python `requirements.txt` and Node.js `package.json` with remediation advice.
- 🌐 **Built-in Web Dashboard Server**: Instant local cyber threat intelligence dashboard (`vulnpulse serve`).
- 🔬 **Deep Vulnerability Dossier**: Comprehensive inspection cards with CVSS v3.1/v4.0 metrics, vectors, and CWE definitions.
- 💬 **Interactive Console**: Live search and inspection REPL shell (`vulnpulse --interactive`).
- 📊 **Multi-Format Export**: Supports SearchSploit-style terminal tables, JSON, CSV, GitHub Markdown, and interactive HTML reports.
- ⚡ **Zero External Dependencies**: Built 100% on Python's standard library with automatic SQLite TTL caching.

---

## 🖥️ Terminal Preview

```
$ vulnpulse bluetooth --last 5 --year 2025 --sort cvss

Searching live security feeds for: bluetooth...
VulnPulse Advanced v2.0.0
────────────────────────────────────────────────────────────────────────────────
Query: bluetooth

 CVSS  EPSS    THREAT    CVE ID           Description                        
────────────────────────────────────────────────────────────────────────────────
  8.8    0.3% -         CVE-2023-54214   In the Linux kernel, the following
                                            vulnerability has been resolved:
                                            Bluetooth: L2CAP: Fix potential
                                            user-after-free...

  8.0    0.3% -         CVE-2023-54164   In the Linux kernel, the following
                                            vulnerability has been resolved:
                                            Bluetooth: ISO: fix iso_conn
                                            related locking and validity issues...

  7.8    0.1% -         CVE-2023-54210   In the Linux kernel, the following
                                            vulnerability has been resolved:
                                            Bluetooth: hci_sync: Avoid use-
                                            after-free in dbg for...
────────────────────────────────────────────────────────────────────────────────
Found: 5 CVEs | 3 High | 1 with Public PoC
```

### Deep Vulnerability Inspection (`--inspect` / `-d`)
```
$ vulnpulse CVE-2021-44228 --inspect

┌──────────────────────────────────────────────────────────────────────────────┐
│                         CVE DOSSIER: CVE-2021-44228                          │
├──────────────────────────────────────────────────────────────────────────────┤
  CVSS v3.1 Score: 10.0 (CRITICAL)
  Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  CVSS Breakdown: Vector: NETWORK | Complexity: LOW | Privileges: NONE | User Interaction: NONE

  Threat Intelligence & Exploitability:
  • EPSS Exploit Probability: 100.00% (Percentile: 100.0th)
  •  CISA KNOWN EXPLOITED VULNERABILITY 
    - Date Added to KEV: 2021-12-10
    - Remediation Due Date: 2021-12-24
    - Known Ransomware Campaign Use: Known
  • Weakness Type (CWE): CWE-502: Deserialization of Untrusted Data
  • Published Date: 2021-12-10 | Last Modified: 2026-08-11

  Discovered Public Exploits & PoCs (20):
    [PacketStorm] http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html
    [GitHub PoC] https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228
    [Verified Exploit] http://seclists.org/fulldisclosure/2022/Dec/2
...
```

---

## 🚀 Installation

### Option 1: Direct Local Installation (Recommended)
```bash
git clone https://github.com/your-username/vulnpulse.git
cd vulnpulse
pip install .
```

### Option 2: Development Mode (Editable)
```bash
pip install -e ".[dev]"
```

### Option 3: Run Directly without Installing (Zero Install)
VulnPulse Advanced requires **no external packages**! You can run it immediately with Python:
```bash
python vulnpulse.py --help
```

---

## 📖 Command Reference

### Usage Syntax
```text
vulnpulse [query] [options]
```

### General & Scope Flags
| Option | Description |
| :--- | :--- |
| `query` | Keyword, product name, or exact CVE ID (e.g. `CVE-2024-45434`) |
| `--last N` | Show the newest `N` matching CVEs |
| `--limit N` | Maximum candidate CVEs to retrieve |
| `--year YEAR` | Filter by publication year (e.g. `2025`, `2026`) |
| `--from DATE` | Start publication date (`YYYY-MM-DD`) |
| `--to DATE` | End publication date (`YYYY-MM-DD`) |
| `--exact` | Match keywords strictly on word boundaries |

### Threat Intelligence & Severity Filters
| Option | Description |
| :--- | :--- |
| `--kev`, `--exploited` | **Only show CVEs actively exploited in the wild (CISA KEV)** |
| `--has-poc`, `--poc` | **Only show CVEs with verified public PoCs / exploits** |
| `--epss-min FLOAT` | Minimum EPSS exploit probability (e.g. `0.3` for ≥ 30%) |
| `--severity LEVEL` | Filter by `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `--cvss-min SCORE` | Minimum CVSS base score (e.g. `8.0`) |
| `--cvss-max SCORE` | Maximum CVSS base score (e.g. `10.0`) |
| `--remote` | Remote vulnerabilities (`Attack Vector: NETWORK`) |
| `--no-auth` | Pre-authentication vulnerabilities (`Privileges Required: NONE`) |
| `--cwe CWE_ID` | Filter by CWE weakness identifier (e.g. `CWE-79`, `CWE-89`) |
| `--cpe CPE_NAME` | Filter by CPE criteria string |

### Modes, Auditing & Web Dashboard
| Option | Description |
| :--- | :--- |
| `-d`, `--inspect` | Show full in-depth dossier for matching CVE(s) |
| `-i`, `--interactive` | Launch live interactive REPL search shell |
| `--audit FILE` | **Audit `requirements.txt` or `package.json` dependencies for known CVEs** |
| `--serve` | **Launch built-in live Cyber Threat Intelligence Web Dashboard server** |
| `--port PORT` | Port for web server (Default: `8080`) |
| `--no-browser` | Don't auto-launch browser when starting server |

### Output & Automation
| Option | Description |
| :--- | :--- |
| `--json` | Output machine-readable JSON for `jq` and pipelines |
| `--csv` | Export as CSV spreadsheet |
| `--html` | Generate self-contained dark-mode interactive HTML report |
| `--markdown`, `--md` | Export as GitHub Flavored Markdown table |
| `-q`, `--quiet` | Output CVE IDs only (one per line) for bash loops |
| `--save [FILE]` | Save output to disk (auto-names if no filename given) |

### Performance & Cache
| Option | Description |
| :--- | :--- |
| `--no-cache` | Bypass local query cache |
| `--clear-cache` | Clear all local SQLite cached records |
| `--api-key KEY` | Pass NIST NVD API key directly |
| `--timeout SEC` | Custom HTTP timeout (Default: 15s) |

---

## 💡 Practical Real-World Examples

### 1. Actively Exploited In-The-Wild Vulnerabilities (CISA KEV)
Find actively exploited vulnerabilities related to Microsoft Exchange or Apache:
```bash
vulnpulse exchange --kev
vulnpulse apache --kev --has-poc
```

### 2. High-Risk Remote Code Execution (Network + Pre-Auth + Critical)
Filter strictly for zero-click remote exploits:
```bash
vulnpulse openssh --remote --no-auth --severity CRITICAL
```

### 3. Highest Exploit Probability (EPSS ≥ 50%)
Filter for vulnerabilities with FIRST EPSS exploit probability $\ge 50\%$:
```bash
vulnpulse wordpress --epss-min 0.50 --sort epss
```

### 4. Interactive Live Shell
Launch interactive console to quickly search, browse, and inspect without re-typing commands:
```bash
vulnpulse --interactive
```

### 5. Generate Sleek Threat Report (HTML Dashboard)
Creates a beautiful dark-mode HTML dossier ready to share with clients or leadership:
```bash
vulnpulse "cisco" --last 20 --html --save cisco_audit.html
```

### 6. Scripting & Tool Chaining
Pipe CVE IDs directly into Nuclei, cURL, or other tools:
```bash
vulnpulse apache --last 10 --kev --quiet | while read -r cve; do
    echo "[!] Checking exploit target for $cve..."
done
```

### 7. Dependency & Project Security Audit (SCA)
Scan your Python `requirements.txt` or Node.js `package.json` for known CVEs:
```bash
vulnpulse audit requirements.txt
vulnpulse audit package.json
```

### 8. Built-in Live Web Dashboard Server
Launch a local cyber threat intelligence dashboard in your browser on `http://localhost:8080`:
```bash
vulnpulse serve
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NVD_API_KEY` | `None` | NIST NVD API key (boosts rate limits 10x from 5 req/30s to 50 req/30s) |
| `VULNPULSE_TIMEOUT` | `15.0` | Network request timeout in seconds |
| `VULNPULSE_MAX_RESULTS` | `1000` | Safety ceiling for maximum items retrieved |
| `NO_COLOR` | `None` | Set to any non-empty value to disable ANSI colors |

> 🔑 **Get a Free NVD API Key**:  
> Request an instant free API key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).  
> Then add it to your environment:
> ```bash
> export NVD_API_KEY="your-api-key"
> ```

---

## 🧪 Running Unit Tests

Run the full automated test suite:
```bash
python -m unittest discover tests -v
```

---

## 📄 License & Access Policy

**Copyright © 2026 Sadeep78. All Rights Reserved.**

This repository and its source code are strictly proprietary.
- **Strictly No Unauthorized Usage**: You may not copy, fork, distribute, modify, deploy, or commercially use this software without explicit written permission from the project owner.
- **Requesting Access / Permissions**: If you wish to use, collaborate, or deploy VulnPulse, please contact the author directly via GitHub: **[@Sadeep78](https://github.com/Sadeep78)**.
