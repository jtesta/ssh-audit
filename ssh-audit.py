#!/usr/bin/env python3
"""src/ssh_audit/ssh_audit.py wrapper for backwards compatibility"""

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ssh_audit.ssh_audit import main
from ssh_audit import exitcodes

exit_code = exitcodes.GOOD

try:
    exit_code = main()
except Exception:
    exit_code = exitcodes.UNKNOWN_ERROR
    print(traceback.format_exc())

sys.exit(exit_code)
