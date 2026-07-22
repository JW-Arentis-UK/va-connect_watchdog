# Simplification Plan

Status: Draft for approval

## Objective

Reduce the current 27 modules and approximately 10,213 production Python lines to a target of 16-20 modules and 4,500-6,000 lines without losing liveness protection or high-value evidence.

## Keep In Continuous Core

| Feature | Reason |
|---|---|
| Independent hardware feed | Primary whole-system recovery mechanism |
| Monotonic heartbeat and startup grace | Safe main-supervisor liveness contract |
| Lightweight CPU, memory, pressure, temperature | Detect broad degradation and preserve lead-up context |
| Core service state/resources | Detect gateway function loss and runaway behaviour |
| Root/recording mount and writable state | Protect OS evidence and CCTV operation |
| Interface/link/error deltas | Detect local communication and driver degradation |
| Kernel fault cursor | Captures decisive evidence with limited repeated work |
| Events, concise history, reboot evidence | Essential post-incident timeline |
| Trigger and incident management | Activates evidence capture at the right time |

## Replace

| Current feature | Replacement |
|---|---|
| Serial five-second health loop | Deadline scheduler with heartbeat isolation and cached collector results |
| Shell `top` CPU calculation | Direct `/proc/stat` deltas |
| Always-on detailed blackbox | Triggered worker with pre-trigger ring and incident directories |
| Percentage-first health score | State plus explicit reasons; retain API score temporarily only |
| General recovery/reboot engine | systemd process restart, hardware liveness reset, explicit approved service policies |
| Dual dashboard renderers | One server-rendered appliance interface |
| Broad root web process | Unprivileged read-mostly Web plus short-lived helper |
| Overlapping storage models | System storage, recording storage, evidence storage |
| In-memory event dedup only | Persisted transition state and incident correlation |

## Move To Setup

- Install/uninstall.
- iTCO driver and hardware watchdog preparation.
- Legacy watchdog cleanup.
- Journald persistence enablement.
- Recording disk setup, labels, directories, ownership, and `fstab`.
- Service mount guards.
- Update execution and channel selection.
- Configuration editing and validation.

## Move To Diagnostics

- Internet speed tests.
- Manual ping/TCP tests.
- Full hardware and block-device inventory.
- Raw journal and raw status views.
- Manual SMART collection.
- Service journals and process trees.
- Support bundle generation.
- Manual service restart and gateway reboot.

## Move To Black Box

- Top processes and threads.
- High-frequency per-core CPU.
- Interrupts, scheduler activity, and context switches.
- Detailed PSI and memory paging.
- Block I/O details and SMART fault profile.
- Full network counters, routes, neighbours, and sockets.
- Detailed service process trees and journals.
- High-frequency kernel evidence.

## Remove

- General health-triggered automatic reboot.
- Legacy client dashboard after target-browser validation.
- Placeholder controls and roadmap items in production pages.
- Duplicate update, watchdog, storage, and service render paths.
- Repeated unchanged warning events.
- Periodic detailed snapshots with only a five-hour rolling window.
- Graphs that do not show meaningful time or incident context.
- Duplicate live-collection APIs.

## Compatibility Policy

Removal happens only after:

- Existing public API fields are inventoried.
- Required consumers are identified.
- A compatibility response or documented migration exists.
- The Teltonika/Videosoft forwarding browser is tested.
- Gateway update and rollback paths are verified.

`/api/status`, `/api/healthz`, version reporting, events export, incident export, and support bundles remain supported interfaces.

## Code Budget

| Component | Target production lines |
|---|---:|
| Feeder and device policy | 300-500 |
| Core scheduler and normal collectors | 1,200-1,700 |
| Trigger and incident management | 500-800 |
| Black Box worker and collectors | 800-1,200 |
| Web, API, and views | 1,200-1,800 |
| Setup, support, config, shared I/O | 800-1,200 |

Budgets are guardrails. Exceeding one requires an architecture review, not artificial compression.

