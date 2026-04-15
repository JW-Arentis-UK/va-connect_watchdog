# VA-Connect Monitoring v2 Core

This is the minimal v2 scaffold.

It keeps only the core pieces needed to monitor a device, record incidents, and expose the current state through a small FastAPI app.

## What is included

- shared models for incidents, device status, and events
- one normalization layer
- one storage layer
- one basic process watchdog stub
- one basic site watchdog loop
- one FastAPI app with:
  - `GET /health`
  - `GET /gateways`
- one read-only build metadata file stamped by GitHub Actions

## What it does not include

- UI complexity
- export tooling
- update systems
- device-specific probes
- advanced recovery logic

## Data Flow

```text
check fails -> event -> incident -> stored -> API returns it
```

More specifically:

1. The site watchdog runs basic checks.
2. If a check fails, the watchdog builds an incident ID.
3. The watchdog writes an event linked to that incident ID.
4. The watchdog writes the incident record to storage.
5. The watchdog updates the current device status.
6. The API reads the stored incident and device status records.
7. `/gateways` returns the stored view directly.

## Files

### Shared core

- `tools/ubuntu/shared/models.py`
  - canonical v2 data models
- `tools/ubuntu/shared/normalization.py`
  - the only place where records are cleaned and validated before write
- `tools/ubuntu/shared/storage.py`
  - JSON and JSONL read/write helpers
- `tools/ubuntu/shared/config.py`
  - environment and file-based config loading
- `tools/ubuntu/shared/paths.py`
  - data directory and file path helpers
- `tools/ubuntu/shared/time.py`
  - UTC timestamp and boot ID helpers
- `tools/ubuntu/shared/logging.py`
  - logging setup

### Runtime

- `tools/ubuntu/runtime/process_watchdog.py`
  - stub process watchdog check
- `tools/ubuntu/runtime/site_watchdog.py`
  - basic site monitoring loop

### Web

- `tools/ubuntu/web/app.py`
  - FastAPI application setup
- `tools/ubuntu/web/routes.py`
  - thin routes only
- `tools/ubuntu/web/services.py`
  - API-side logic that reads storage and prepares responses

## Storage Layout

The default data directory is `.v2-data/` in the repository root.

The main files are:

- `build-info.json`
  - read-only build metadata stamped by GitHub Actions
- `.v2-data/state.json`
- `.v2-data/device_status.json`
- `.v2-data/events.jsonl`
- `.v2-data/incidents.jsonl`
- `.v2-data/logs/v2.log`

For a real Ubuntu deployment, set `VA_CONNECT_V2_DATA_DIR` to a system path such as `/var/lib/va-connect-v2`.

The dashboard and API also read `build-info.json` from the repo root. The gateway never writes it; GitHub Actions updates it before the gateway pulls the repo.

## How the core works

### 1. Basic checks

The site watchdog runs two basic checks:

- app process check
- WAN ping check

It also records the current boot ID.

### 2. Failure handling

If a check fails:

- the watchdog creates a stable `incident_id`
- the watchdog writes a linked event record
- the watchdog writes the incident record
- the watchdog updates the current device status

If the device recovers:

- the watchdog marks the open incident as resolved
- the watchdog writes a follow-up event
- the watchdog stores the updated incident
- the watchdog updates the device status to healthy

### 3. API reads

The API never rebuilds incidents from scattered files.

It simply reads:

- the current device status
- the canonical incident list
- the event log count when needed

## Example Flow

Example failure path:

1. `site_watchdog.py` runs and sees the app process is missing.
2. It creates an incident:
   - `type = app_crash`
   - `severity = critical`
   - `status = open`
3. It writes an event with:
   - `incident_id`
   - `boot_id`
   - a short message
   - structured debugging context
4. It stores the incident and the current device status.
5. `GET /gateways` reads the stored data and returns the incident exactly as written.

Example API shape:

```json
{
  "gateways": [
    {
      "device_status": {
        "device_id": "POC-451VTC",
        "overall_status": "faulted",
        "last_seen": "2026-04-15T08:12:33Z",
        "checks": {
          "app": {
            "ok": false,
            "last_checked": "2026-04-15T08:12:33Z",
            "detail": "process missing for match 'va-connect'"
          }
        },
        "health": {
          "fault_active": true,
          "last_incident_id": "inc_20260415_081233_poc451vtc_ab12cd",
          "last_incident_type": "app_crash",
          "last_healthy_at": "2026-04-15T08:05:01Z",
          "notes": "App process is not running."
        }
      },
      "incidents": [
        {
          "incident_id": "inc_20260415_081233_poc451vtc_ab12cd",
          "timestamp": "2026-04-15T08:12:33Z",
          "boot_id": "2c7a0d8d-0df0-4f3f-b5cb-d5a0b0d9f5e1",
          "device_id": "POC-451VTC",
          "type": "app_crash",
          "status": "open",
          "severity": "critical",
          "cause": "app process is not running",
          "evidence": [
            {
              "source": "check",
              "timestamp": "2026-04-15T08:12:33Z",
              "message": "app process missing",
              "data": {
                "check": "app",
                "detail": "process missing for match 'va-connect'"
              }
            }
          ],
          "actions_taken": [
            "Incident created by site watchdog"
          ],
          "resolved_at": null
        }
      ]
    }
  ]
}
```

## Running it

### Watchdog loop

```bash
python -m tools.ubuntu.runtime.site_watchdog
```

### FastAPI app

```bash
uvicorn tools.ubuntu.web.app:app --reload --port 8787
```

### Local test URLs

- http://127.0.0.1:8787/health
- http://127.0.0.1:8787/gateways
- http://127.0.0.1:8787/debug/last-incident

### Windows quick start

From the project root, run:

```bat
run_v2.bat
```

That opens one window for the API and one window for the watchdog, and keeps both open so you can watch the logs.

If `.venv` exists, the batch file activates it in each window. If `requirements.txt` appears later, the batch file will try to install it before launching.

### Optional data directory override

```bash
set VA_CONNECT_V2_DATA_DIR=C:\temp\va-connect-v2
```

or on Ubuntu:

```bash
export VA_CONNECT_V2_DATA_DIR=/var/lib/va-connect-v2
```

## Design rules

- one place for models
- one place for normalization
- thin routes only
- services contain logic
- no duplicated helpers

That is the whole point of this scaffold: keep v2 obvious, stable, and easy to debug.
