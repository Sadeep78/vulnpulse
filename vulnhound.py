#!/usr/bin/env python3
"""
VulnHound Advanced - Root executable entrypoint.
"""

import sys
from vulnhound.cli import main

if __name__ == "__main__":
    sys.exit(main())
