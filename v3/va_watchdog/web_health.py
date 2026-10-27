"""Keep web-process liveness separate from fresh gateway readiness."""
import json
from pathlib import Path

from .status_freshness import freshness


def health_response(cfg):
    try:
        status = json.loads(Path(cfg["status_path"]).read_text(encoding="utf-8"))
        if not isinstance(status, dict):
            raise ValueError("Invalid status")
    except (OSError, KeyError, ValueError, TypeError):
        status = {}
    observed = freshness(cfg, status)
    fresh = observed["status_fresh"]
    ready = fresh and status.get("state") == "healthy" and not status.get("critical_failed")
    return {"ok": True, "scope": "web_liveness", "ready": bool(ready),
            "state": status.get("state", "unknown") if fresh else "unknown", "status_time": status.get("time"),
            "recorded_state": status.get("state", "unknown"),
            "score": status.get("score"),
            **observed, "critical_failed": bool(status.get("critical_failed"))}
