# Data Flow

Status: Draft for approval

## Overview

```mermaid
flowchart TD
    proc["Linux /proc and /sys"]
    systemd["systemd state"]
    journal["journald cursor"]
    network["Essential network target"]
    core["Core collectors and scheduler"]
    ring["In-memory pre-trigger ring"]
    triggers["Trigger engine"]
    heartbeat["Atomic heartbeat state"]
    status["Atomic operator status"]
    history["Bounded normal history"]
    events["Deduplicated events"]
    feeder["Hardware feeder"]
    worker["Black Box worker"]
    incidents["Incident evidence store"]
    web["Web and read-only API"]

    proc --> core
    systemd --> core
    journal --> core
    network --> core
    core --> ring
    core --> triggers
    core --> heartbeat
    core --> status
    core --> history
    core --> events
    heartbeat --> feeder
    feeder --> status
    triggers --> worker
    ring --> incidents
    worker --> incidents
    status --> web
    history --> web
    events --> web
    incidents --> web
```

## Live Decision Data

Live decisions use atomic snapshots with schema versions:

| File | Writer | Reader | Purpose |
|---|---|---|---|
| `heartbeat-state.json` | Core | Feeder | Current-boot liveness using monotonic uptime |
| `feed-status.json` | Feeder | Core/Web | Feed state, timestamps, count, errors |
| `status.json` | Core | Web/API | Operator status and current evidence quality |
| `incident-active.json` | Core | Core/Worker/Web | Active incident identity and lifecycle state |
| `blackbox-status.json` | Worker | Core/Web | Worker progress and collector health |
| `control/feed.json` | Setup/trip action | Feeder | Expiring explicit control request |

Each snapshot contains a schema version, boot ID, sequence, UTC timestamp, and monotonic timestamp where relevant.

## Append-Only Evidence

| Data | Normal frequency | Retention purpose |
|---|---:|---|
| Heartbeat forensic history | bounded low-detail cadence | Establish final liveness before reboot |
| Events | state transitions only | Operator and incident timeline |
| Normal history | 60 seconds | Long-term context and pre-incident baselines |
| Reboot evidence | per boot transition | Explain reset mechanism and preceding findings |
| Incident samples | 2-5 seconds during incident | Detailed diagnosis |
| Incident kernel stream | Cursor-driven during incident | Preserve decisive OS evidence |

JSONL files are never used as control channels. Partial final lines are ignored safely by readers.

## Configuration Flow

```mermaid
sequenceDiagram
    participant Engineer
    participant Setup
    participant Validator
    participant Config as Versioned config
    participant Core
    participant Feeder

    Engineer->>Setup: Request explicit change
    Setup->>Validator: Validate complete candidate config
    Validator-->>Setup: Valid or rejected with reasons
    Setup->>Config: Backup and atomic replace
    Setup->>Core: Controlled reload/restart
    Setup->>Feeder: Restart only if feeder settings changed
    Setup-->>Engineer: Audit result and effective values
```

Runtime state never silently rewrites policy configuration.

## Evidence Export Flow

Support bundle generation reads immutable snapshots and copies bounded tails or complete incident files. It must:

- Avoid blocking Core.
- Exclude CCTV recordings.
- Exclude credentials and secrets.
- Include configuration with sensitive fields redacted.
- Include a manifest of present and missing evidence.
- Record bundle generation as an audit event.

## Backpressure

- Atomic snapshots overwrite old state and therefore remain bounded.
- Append-only writers enforce maximum line size.
- Incident queues are bounded.
- A slow disk causes evidence degradation events rather than unbounded memory growth.
- Core retains liveness priority over status, history, and event writes.
- When evidence storage is exhausted, Core keeps heartbeat and minimal status operational.

