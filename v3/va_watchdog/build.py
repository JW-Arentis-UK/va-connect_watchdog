"""Release build identifier shared by the web views and installer."""

import json
from pathlib import Path


BUILD_FILE = Path(__file__).resolve().parents[1] / "build.json"


def build_number() -> str:
    try:
        payload = json.loads(BUILD_FILE.read_text(encoding="utf-8"))
        return str(payload.get("build_number") or "local-dev")
    except (OSError, ValueError, TypeError):
        return "local-dev"
