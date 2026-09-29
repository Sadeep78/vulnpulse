"""
VulnPulse Advanced - High-Performance Threat-Enriched CVE Intelligence CLI & Library.
"""

import sys

# Ensure UTF-8 console output across all platforms (especially Windows cp1252)
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

__version__ = "2.0.0"
__author__ = "Sadeep78"
__license__ = "Proprietary"
