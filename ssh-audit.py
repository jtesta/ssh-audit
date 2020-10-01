#!/usr/bin/env python3
"""src/ssh_audit/ssh_audit.py wrapper for backwards compatibility"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ssh_audit.ssh_audit import main  # noqa: E402

main()
