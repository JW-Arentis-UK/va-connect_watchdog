# Runtime Process Diagram

Status: Draft for approval

## Normal Operation

```mermaid
flowchart LR
    systemd["systemd"]
    feeder["va-watchdog-feed\nminimal hardware feeder"]
    core["va-watchdog-core\nheartbeat and lightweight supervision"]
    web["va-watchdog-web\nread-mostly operator interface"]
    device["/dev/watchdog0"]
    heartbeat["heartbeat-state.json\natomic live contract"]
    status["status and bounded history"]
    browser["Engineer or operator browser"]

    systemd --> feeder
    systemd --> core
    systemd --> web
    feeder --> device
    core --> heartbeat
    heartbeat --> feeder
    feeder --> status
    core --> status
    status --> web
    browser --> web
```

Normal process count: three.

## Incident Operation

```mermaid
flowchart LR
    core["Core supervisor"]
    trigger["Confirmed trigger"]
    systemd["systemd transient activation"]
    worker["Black Box worker"]
    ring["In-memory pre-trigger ring"]
    incident["Incident directory"]
    web["Web interface"]

    core --> trigger
    trigger --> systemd
    systemd --> worker
    core --> ring
    ring --> incident
    worker --> incident
    incident --> web
```

Incident process count: four. The worker exits after post-event finalisation.

## Setup or Diagnostics Action

```mermaid
sequenceDiagram
    participant Engineer
    participant Web
    participant Helper as Privileged helper
    participant OS as Operating system
    participant Audit as Audit event/result

    Engineer->>Web: Authenticated action request
    Web->>Engineer: Show exact effect and confirmation
    Engineer->>Web: Confirm action
    Web->>Helper: Allow-listed action and validated parameters
    Helper->>OS: Perform one bounded operation
    Helper->>Audit: Write result and changed files
    Helper-->>Web: Bounded structured result
    Web-->>Engineer: Display outcome
```

The helper is short-lived. It is not a fourth permanent service.

## Process Isolation Requirements

| Process | Restart policy | Failure isolation |
|---|---|---|
| Feeder | `on-failure` with short delay | Core, Web, and Black Box cannot own device |
| Core | `always` with bounded restart delay | Feeder grace prevents immediate reset during restart |
| Web | `on-failure` | No effect on heartbeat or feeding |
| Black Box | Incident-scoped retry policy | No effect on normal supervision |
| Helper | No automatic retry | Partial changes require explicit rollback result |

