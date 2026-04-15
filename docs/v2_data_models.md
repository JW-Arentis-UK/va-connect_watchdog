# VA-Connect Monitoring v2 Data Models

This document defines the shared source of truth for v2.

The goal is simple:

- one incident model
- one device status model
- one event/log structure
- one normalization location

No feature-specific model variants should be added unless they are truly essential.

## Core Rules

1. The watchdog creates incidents and events.
2. Events are linked to incidents through `incident_id`.
3. The web layer reads incidents and status data.
4. The web layer does not re-derive incidents from scattered files.
5. Normalization happens in one place only: a shared normalization layer used by both watchdog and web code before records are written or read.

## Normalization Location

Normalization must live in one shared module only, such as:

- `shared/normalization.py`

That module is responsible for:

- validating required fields
- filling defaults for optional fields
- coercing timestamps into one format
- ensuring consistent status values
- rejecting malformed records early

No route handler, no UI helper, and no export script should re-invent normalization rules.

## 1) Incident Model

### Purpose

An incident is the canonical record for a meaningful fault, recovery event, or reboot-related event that needs review later.

### Exact Fields

| Field | Type | Required | Description |
|---|---|---:|---|
| `incident_id` | string | yes | Stable unique identifier for the incident. |
| `timestamp` | string | yes | When the incident was first recorded, in ISO 8601 UTC format. |
| `boot_id` | string | yes | Boot session identifier for correlation across logs and snapshots. |
| `device_id` | string | yes | Stable identifier for the encoder or gateway that experienced the incident. |
| `type` | string | yes | Short incident category from a controlled set. |
| `status` | string | yes | Current lifecycle state, such as `open`, `monitoring`, or `resolved`. |
| `severity` | string | yes | Impact level for the incident. |
| `cause` | string | yes | Human-readable cause summary or best current classification. |
| `evidence` | array of objects | yes | Evidence items supporting the incident. |
| `actions_taken` | array of strings | yes | Ordered list of actions the watchdog or operator took. |
| `resolved_at` | string or null | no | ISO 8601 UTC time when the incident was resolved, or `null` if still open. |

### Field Rules

#### `incident_id`

- Must be unique within the v2 incident store.
- Must be stable for the full life of the incident.
- Should be short but readable.

#### `timestamp`

- Must be ISO 8601 UTC.
- Must be the time the incident was created, not the time the UI viewed it.

#### `boot_id`

- Must identify the boot session that was active when the incident was recorded.
- Should match the boot ID used in related events and snapshots.

#### `device_id`

- Must identify the specific VA-Connect unit.
- Should not change when the web service restarts.

#### `type`

- Must be one of a small controlled set.
- Keep the list narrow and practical.
- Recommended values:
  - `wan_down`
  - `lan_down`
  - `app_crash`
  - `service_failure`
  - `unexpected_reboot`
  - `watchdog_reboot`
  - `manual_recovery`
  - `unknown`

#### `status`

- Must describe the incident lifecycle, not the device health.
- Recommended values:
  - `open`
  - `monitoring`
  - `resolved`

#### `severity`

- Must describe how serious the incident is.
- Recommended values:
  - `info`
  - `warning`
  - `critical`

#### `cause`

- Must be a human-readable summary.
- Should be short enough to scan in a table, but specific enough to be useful.

#### `evidence`

- Must be an array, even when there is only one item.
- Each item should be a small object with evidence text, structured data, and a reference to the source.
- Recommended evidence item shape:
  - `source`
  - `message`
  - `data`
  - `timestamp`

#### `actions_taken`

- Must be an array of strings.
- Keep it in chronological order.
- Include both watchdog actions and manual actions if known.

#### `resolved_at`

- Use `null` while unresolved.
- Fill it when the incident is closed or clearly recovered.

### Required vs Optional

- Required: `incident_id`, `timestamp`, `device_id`, `type`, `status`, `cause`, `evidence`, `actions_taken`
- Optional: `resolved_at`

### Full JSON Example

```json
{
  "incident_id": "inc_20260415_081233_poc451vtc",
  "timestamp": "2026-04-15T08:12:33Z",
  "boot_id": "2c7a0d8d-0df0-4f3f-b5cb-d5a0b0d9f5e1",
  "device_id": "POC-451VTC",
  "type": "unexpected_reboot",
  "status": "resolved",
  "severity": "critical",
  "cause": "Device rebooted without a watchdog-requested reboot and recovered after restart.",
  "evidence": [
    {
      "source": "event",
      "timestamp": "2026-04-15T08:12:30Z",
      "message": "unexpected_reboot_detected",
      "data": {
        "previous_boot_id": "1f9f5f6f-4c76-4e5d-bf59-4b6d6d6f3d20",
        "current_boot_id": "2c7a0d8d-0df0-4f3f-b5cb-d5a0b0d9f5e1"
      }
    },
    {
      "source": "snapshot",
      "timestamp": "2026-04-15T08:12:35Z",
      "message": "previous-boot journal captured for review",
      "data": {
        "snapshot_path": "/var/log/va-connect-site-watchdog/snapshots/inc_20260415_081233_poc451vtc"
      }
    }
  ],
  "actions_taken": [
    "Captured previous-boot snapshot",
    "Recorded reboot incident",
    "Marked incident resolved after boot recovery"
  ],
  "resolved_at": "2026-04-15T08:18:10Z"
}
```

### Who Creates It

- The site watchdog creates incidents.
- The web layer does not create new incident truth.
- The web layer may display or export incidents, but it should not infer them from unrelated files.

### Who Reads It

- Web UI
- Export tools
- Reporting tools
- Manual review tools

## 2) Device Status Model

### Purpose

The device status model is the latest operational snapshot for one device.

### Exact Fields

| Field | Type | Required | Description |
|---|---|---:|---|
| `device_id` | string | yes | Stable device identifier. |
| `overall_status` | string | yes | Current summary state. |
| `last_seen` | string | yes | ISO 8601 UTC time the device was last confirmed healthy or observed. |
| `checks` | object | yes | Current check results grouped into a single object. |
| `health` | object | yes | Aggregated health summary and derived facts. |

### Field Rules

#### `device_id`

- Same value used in incidents.
- Must be stable across restarts.

#### `overall_status`

- Must be a small controlled value set.
- Recommended values:
  - `healthy`
  - `degraded`
  - `faulted`
  - `unknown`

#### `last_seen`

- Must be ISO 8601 UTC.
- Represents the latest meaningful observation time.

#### `checks`

- Must be one object that contains the current state of the important checks.
- Keep the sub-keys stable and boring.
- Recommended sub-keys:
  - `app`
  - `wan`
  - `lan`
  - `services`
  - `snapshot`
  - `boot`

Each individual check must include:

- `ok`
- `last_checked`
- `detail`

For list-based checks like `services`, each item in the list must also include those three fields.

#### `health`

- Must summarize the device, not duplicate every raw check.
- Recommended sub-keys:
  - `fault_active`
  - `last_incident_id`
  - `last_incident_type`
  - `last_healthy_at`
  - `notes`

### Required vs Optional

- Required: `device_id`, `overall_status`, `last_seen`, `checks`, `health`
- Optional: none

### Full JSON Example

```json
{
  "device_id": "POC-451VTC",
  "overall_status": "degraded",
  "last_seen": "2026-04-15T08:12:33Z",
  "checks": {
    "app": {
      "ok": true,
      "last_checked": "2026-04-15T08:12:33Z",
      "detail": "VA-Connect is running"
    },
    "wan": {
      "ok": false,
      "last_checked": "2026-04-15T08:12:33Z",
      "detail": "1.1.1.1 timed out"
    },
    "lan": {
      "ok": true,
      "last_checked": "2026-04-15T08:12:33Z",
      "detail": "192.168.1.1:80 reachable"
    },
    "services": [
      {
        "name": "teamviewerd.service",
        "ok": true,
        "last_checked": "2026-04-15T08:12:33Z",
        "detail": "active"
      }
    ],
    "snapshot": {
      "ok": true,
      "last_checked": "2026-04-15T08:12:33Z",
      "detail": "previous-boot snapshot available"
    },
    "boot": {
      "ok": true,
      "last_checked": "2026-04-15T08:12:33Z",
      "detail": "boot id unchanged"
    }
  },
  "health": {
    "fault_active": true,
    "last_incident_id": "inc_20260415_081233_poc451vtc",
    "last_incident_type": "unexpected_reboot",
    "last_healthy_at": "2026-04-15T08:05:01Z",
    "notes": "WAN failure is currently the primary issue."
  }
}
```

### Who Creates It

- The watchdog service creates and updates it.
- The web layer may read it and display it.
- The web layer should not invent its own parallel status model.

### Who Reads It

- Web UI
- Alerts
- Operator tools
- Health summaries

## 3) Event / Log Structure

### Purpose

An event is the smallest durable record of something that happened.

### Exact Fields

| Field | Type | Required | Description |
|---|---|---:|---|
| `timestamp` | string | yes | ISO 8601 UTC time of the event. |
| `component` | string | yes | Source component that wrote the event. |
| `level` | string | yes | Log level. |
| `message` | string | yes | Short human-readable message. |
| `incident_id` | string or null | no | Related incident ID, or `null` if not tied to one. |
| `boot_id` | string or null | no | Boot session identifier, or `null` if unavailable. |
| `context` | object or null | no | Structured debugging data for the event. |

### Field Rules

#### `timestamp`

- Must be ISO 8601 UTC.

#### `component`

- Must identify the writer.
- Recommended values:
  - `process_watchdog`
  - `site_watchdog`
  - `web`
  - `export`

#### `level`

- Must be one of:
  - `debug`
  - `info`
  - `warning`
  - `error`

#### `message`

- Must be short and readable.
- Should state what happened, not just what function ran.

#### `incident_id`

- Use the incident ID when the event belongs to an incident.
- Use `null` for ordinary background chatter that is not tied to an incident.

#### `boot_id`

- Use the active boot ID when the event is tied to a specific boot session.
- Use `null` only if a boot ID is not available.

#### `context`

- Use this for small structured debugging details.
- Keep it compact and relevant.
- Examples:
  - failed host names
  - return codes
  - snapshot paths
  - check details
  - action names

### Required vs Optional

- Required: `timestamp`, `component`, `level`, `message`
- Optional: `incident_id`, `boot_id`, `context`

### Full JSON Example

```json
{
  "timestamp": "2026-04-15T08:12:33Z",
  "component": "site_watchdog",
  "level": "warning",
  "message": "WAN check failed for 1.1.1.1",
  "incident_id": "inc_20260415_081233_poc451vtc",
  "boot_id": "2c7a0d8d-0df0-4f3f-b5cb-d5a0b0d9f5e1",
  "context": {
    "host": "1.1.1.1",
    "timeout_seconds": 3,
    "return_code": 1
  }
}
```

### Who Creates It

- The watchdog creates events.
- The web layer may log UI actions or exports as events if needed, but it should not create alternate incident records.

### Who Reads It

- Web UI
- Incident summary logic
- Export tools
- Troubleshooting scripts

## Model Relationships

### Watchdog creates incidents

- The watchdog observes a fault.
- It writes an incident record using the incident model.
- The incident gets a stable `incident_id`.

### Events link to incidents

- Every event related to a fault should carry the same `incident_id`.
- This makes the event stream searchable and traceable.
- Events without an incident may still exist, but they should stay clearly separate from incident-specific evidence.

### Web reads incidents only

- The web layer should read incidents and status snapshots.
- It should not rebuild incident truth from:
  - journal fragments
  - snapshot directories
  - state side files
  - ad hoc heuristics
- The web layer may display derived views, but those views must come from the canonical incident and status records.

## Usage Rules

### Do

- Use the same `device_id` everywhere.
- Use UTC timestamps everywhere.
- Keep `type` and `status` values small and controlled.
- Write incidents once, then update them carefully.
- Keep evidence items tied to source material.
- Prefer one record per event and one record per incident.

### Do Not

- Do not put UI-only text into the canonical incident record.
- Do not create feature-specific incident shapes.
- Do not let the web layer re-classify incidents from raw logs.
- Do not store the same fact in several competing fields.
- Do not invent new status vocabularies per feature.

## Read and Write Responsibilities

### Creates

- `incident`
  - Created by the watchdog
- `device_status`
  - Created and updated by the watchdog
- `event`
  - Created by the watchdog, with optional web action logging

### Reads

- `incident`
  - Read by the web UI, exports, and reports
- `device_status`
  - Read by the web UI and health summaries
- `event`
  - Read by the web UI, reports, and troubleshooting tools

## Final Constraint

If a field does not help with monitoring, diagnosis, or recovery, it should not be added to the core model yet.

The whole point of v2 is to make the data small, stable, and easy to trust.
