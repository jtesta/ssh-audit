import sys
import traceback

from ssh_audit.ssh_audit import main
from ssh_audit import exitcodes


exit_code = exitcodes.GOOD

try:
    exit_code = main()
except Exception:
    exit_code = exitcodes.UNKNOWN_ERROR
    print(traceback.format_exc())

sys.exit(exit_code)
