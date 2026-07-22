# Module Responsibilities

Status: Draft for approval

## Target Package Layout

The target is 16-20 production Python modules and approximately 4,500-6,000 production lines, excluding tests. Module names are descriptive targets and may be adjusted during detailed planning without changing responsibility boundaries.

## Core Modules

| Module | Responsibility | Must not do |
|---|---|---|
| `core_main.py` | Process startup, scheduler ownership, component supervision | Collect detailed diagnostics, serve HTTP, execute setup |
| `heartbeat.py` | Atomic heartbeat state and bounded forensic heartbeat history | Wait for collectors or use UTC for live freshness |
| `scheduler.py` | Deadlines, collector timing, stale results, monotonic sequencing | Execute unbounded work |
| `normal_collectors.py` | Direct `/proc` and `/sys` lightweight samples | Run SMART, journals, `top`, or broad shell pipelines |
| `service_state.py` | Configured service state and `/proc` resource deltas | Restart services implicitly |
| `storage_state.py` | Root/recording identity, mount, writable, read-only, capacity | Partition, format, relabel, or edit `fstab` |
| `network_state.py` | Link and counter state plus essential bounded reachability | Speed tests or broad network inventory |
| `trigger_engine.py` | Duration, hysteresis, cooldown, trigger correlation | Run evidence collectors |
| `incident_manager.py` | Incident IDs, lifecycle, manifests, worker activation | Collect detailed evidence itself |
| `events.py` | Deduplicated transitions and incident correlation | Emit unchanged faults repeatedly |
| `history.py` | Concise normal history and incident markers | Store full diagnostic snapshots |
| `reboot_evidence.py` | Boot transition and previous-boot classification | Claim causes without evidence |
| `retention.py` | Bounded normal and incident data retention | Touch CCTV recordings or open incidents |

Closely related small modules may be merged where that reduces code and keeps tests clear.

## Feeder Modules

| Module | Responsibility | Must not do |
|---|---|---|
| `feed_main.py` | Feed process lifecycle and status | Health monitoring, HTTP, diagnostics |
| `watchdog_device.py` | Device open, timeout, feed, close, magic-close and nowayout handling | Decide system health |
| `feed_policy.py` | Grace, heartbeat freshness, trip, explicit fatal control | Interpret ordinary health warnings as fatal |

The feeder package should remain small enough to audit independently.

## Black Box Modules

| Module | Responsibility | Must not do |
|---|---|---|
| `blackbox_main.py` | Worker lifecycle, profile selection, deadlines, finalisation | Publish the core heartbeat |
| `blackbox_collectors.py` | Detailed CPU, thread, memory, I/O, network, service, kernel evidence | Modify gateway configuration |
| `incident_store.py` | Incident paths, append-only evidence, atomic indexes, manifest | Purge open incidents |
| `incident_report.py` | Timeline, findings, missing evidence, confidence | Diagnose beyond available evidence |

Collector families may be split only when they remain behind the same worker interface.

## Web and Administration Modules

| Module | Responsibility | Must not do |
|---|---|---|
| `web_main.py` | HTTP lifecycle, routing, authentication, response limits | Own watchdog device or heartbeat |
| `web_views.py` | Single server-rendered appliance UI | Duplicate a second dashboard implementation |
| `api.py` | Stable read-only status, events, incidents, history, version | Expose arbitrary commands |
| `actions.py` | Validate and submit allow-listed helper actions | Perform privileged work inside Web |
| `setup_helper.py` | Short-lived installation, update, disk, journald, and hardware actions | Run continuously |
| `support_bundle.py` | Bounded evidence export and redaction manifest | Include secrets or CCTV content |

If the target line budget requires fewer modules, `web_main.py`, `web_views.py`, and `api.py` may be combined while retaining one renderer and one route implementation.

## Shared Modules

| Module | Responsibility |
|---|---|
| `config.py` | Versioned schema, defaults, validation, atomic save, migration |
| `models.py` | Small typed records and state enums |
| `atomic_io.py` | Atomic snapshots, bounded append, locking, safe reads |
| `timebase.py` | UTC evidence time, monotonic live time, boot ID |

Avoid a large generic utility module. Shared code must have a clear owner and at least two real consumers.

## Existing Feature Placement

| Existing feature | Target owner |
|---|---|
| Dedicated hardware feed | Feeder |
| Heartbeat and feed state | Core/Feeder contract |
| CPU/RAM/temp normal health | Normal collectors |
| Configured service state | Service state |
| Recording mount health | Storage state |
| Kernel fault cursor | Core event detector |
| Periodic detailed blackbox | Replace with Black Box worker |
| Reboot classification | Reboot evidence |
| Event and normal history | Events/History |
| Watchdog installation | Setup helper |
| Storage provisioning | Setup helper |
| Updates | Setup helper |
| Speed test | Diagnostics action |
| Support bundle | Support bundle |
| Raw status/config | Diagnostics/Web |
| Legacy client dashboard | Remove after compatibility validation |
| General critical-health reboot | Remove |
| Placeholder controls | Remove |

## Dependency Rules

- Feeder depends only on shared atomic I/O, time, feeder configuration, and device code.
- Core may depend on lightweight collectors and incident coordination.
- Core must not import Web, Setup, or detailed Black Box collectors.
- Black Box may read Core snapshots but must not write the Core heartbeat.
- Web may read Core and incident data but cannot import feeder device code.
- Setup may use shared configuration validation but cannot run in Core.
- Diagnostics may read all public evidence contracts but cannot mutate Core state except through an approved action contract.

