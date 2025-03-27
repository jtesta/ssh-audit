#!/usr/bin/env python3

import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ssh_audit.lambda_function import lambda_handler as handler


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    return handler(event, context)
