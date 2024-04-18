#!/usr/bin/env python3
"""src/ssh_audit/ssh_audit.py wrapper for backwards compatibility"""

import multiprocessing
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ssh_audit.ssh_audit import main  # noqa: E402
from ssh_audit import exitcodes  # noqa: E402

if __name__ == "__main__":
    multiprocessing.freeze_support()  # Needed for PyInstaller (Windows) builds.

    exit_code = exitcodes.GOOD
    try:
        exit_code = main()
    except Exception:
        exit_code = exitcodes.UNKNOWN_ERROR
        print(traceback.format_exc())

    sys.exit(exit_code)
