from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class CheckResult:
    name: str
    state: str
    message: str = ""
    value: Any = None
    critical: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def worst_state(states):
    order = ["healthy", "warning", "degraded", "critical", "unknown"]
    rank = {s: i for i, s in enumerate(order)}
    if not states:
        return "unknown"
    return max(states, key=lambda s: rank.get(s, 99))

def score_from_checks(checks):
    score = 100
    for c in checks:
        if c.state == "warning":
            score -= 5
        elif c.state == "degraded":
            score -= 15
        elif c.state == "critical":
            score -= 35
        elif c.state == "unknown":
            score -= 10
    return max(0, min(100, score))
