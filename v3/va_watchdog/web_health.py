"""Keep web-process liveness separate from fresh gateway readiness."""
import json
from datetime import datetime, timezone
from pathlib import Path


def health_response(cfg):
    try:
        status = json.loads(Path(cfg["status_path"]).read_text(encoding="utf-8"))
        if not isinstance(status, dict):
            raise ValueError("Invalid status")
        stamp = datetime.fromisoformat(str(status.get("time", "")).replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        fresh = 0 <= age <= max(30, int(cfg.get("poll_interval_seconds", 5)) * 4)
    except (OSError, KeyError, ValueError, TypeError):
        status, age, fresh = {}, None, False
    ready = fresh and status.get("state") == "healthy" and not status.get("critical_failed")
    return {"ok": True, "scope": "web_liveness", "ready": bool(ready),
            "state": status.get("state", "unknown"), "status_time": status.get("time"),
            "score": status.get("score"),
            "status_age_seconds": round(age, 1) if age is not None else None,
            "status_fresh": fresh, "critical_failed": bool(status.get("critical_failed"))}
