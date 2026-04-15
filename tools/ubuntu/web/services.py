from __future__ import annotations

from typing import Any

from ..shared.config import V2Config
from ..shared.storage import list_incidents, load_device_status, load_events, load_state


def health_payload(config: V2Config) -> dict[str, Any]:
    state = load_state(config)
    device_status = load_device_status(config)
    incidents = list_incidents(config)
    return {
        "ok": True,
        "device_id": config.device_id,
        "storage": {
            "data_dir": str(config.data_dir),
            "events": len(load_events(config)),
            "incidents": len(incidents),
        },
        "state": state,
        "device_status": device_status,
        "open_incident_id": state.get("open_incident_id"),
    }


def gateways_payload(config: V2Config) -> dict[str, Any]:
    device_status = load_device_status(config)
    incidents = list_incidents(config)
    return {
        "gateways": [
            {
                "device_status": device_status,
                "incidents": incidents,
            }
        ]
    }
