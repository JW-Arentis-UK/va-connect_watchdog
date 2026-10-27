#!/usr/bin/python3 -I
"""Installed root-owned entry point; import only the root-owned appliance package."""
import sys
import os
from pathlib import Path

runtime = Path("/opt/va-connect-watchdog-v3/.venv/bin/python")
if runtime.exists() and Path(sys.prefix).resolve() != runtime.parent.parent.resolve():
    os.execv(str(runtime), [str(runtime), "-I", __file__])
sys.path.insert(0, "/opt/va-connect-watchdog-v3/v3")
from va_watchdog.privileged_actions import main

raise SystemExit(main())
