# Final Architecture Specification

Status: Draft for approval  
Architecture name: VA-Connect Watchdog appliance architecture  

## 1. Objective

The watchdog shall keep an unattended gateway recoverable and preserve enough evidence to explain rare system failures. Reliability and forensic value take priority over feature count.

The target design has four responsibility areas:

| Area | Execution model | Purpose |
|---|---|---|
| Core | Continuous | Liveness, lightweight supervision, trigger evaluation, incident coordination |
| Black Box | Incident only | High-detail evidence collection and incident reporting |
| Setup | Engineer initiated | Installation, configuration, updates, disks, hardware setup |
| Diagnostics | Engineer initiated | Manual probes, raw inspection, tests, support bundles |

Features that do not fit one area should be removed or redesigned.

## 2. Runtime Processes

### 2.1 Hardware feeder

Systemd unit: `va-watchdog-feed.service`  
Normal process count: one  
Privilege: only the privilege required to own the configured watchdog device  

Responsibilities:

- Acquire the single-owner device lock.
- Open and configure `/dev/watchdog0`.
- Feed at the configured interval.
- Read atomic heartbeat and control state.
- Enforce startup grace and stale-heartbeat policy.
- Support explicit trip testing and clean shutdown policy.
- Persist bounded feed state and errors.

It must not collect health, inspect services, access the network, read journals, host HTTP, or execute updates.

### 2.2 Core supervisor

Systemd unit: `va-watchdog-core.service`  
Normal process count: one  
Privilege: unprivileged where practical, with read access to required `/proc`, `/sys`, status, and systemd information  

Responsibilities:

- Publish the monotonic heartbeat on schedule.
- Collect lightweight normal-mode metrics.
- Measure collector runtime and sampling delay.
- Produce current operator status.
- Append concise operational history.
- Record deduplicated state transitions.
- Evaluate Black Box triggers with duration and hysteresis.
- Own the incident state machine.
- Request Black Box worker start and stop.
- Create startup and reboot evidence.
- Enforce evidence retention.

The heartbeat scheduler must be independent from collector completion. Slow or failed collection must reduce data quality, not stop liveness publication.

### 2.3 Web interface

Systemd unit: `va-watchdog-web.service`  
Normal process count: one  
Privilege: unprivileged and read-only for normal status data  

Responsibilities:

- Present Overview, Events, Incidents, History, Setup, and Diagnostics.
- Read immutable snapshots and bounded history files.
- Export incidents and support bundles.
- Submit authenticated Setup or Diagnostics requests to a narrow helper interface.

The web process must not own the hardware watchdog, write the core heartbeat, or execute arbitrary shell commands.

### 2.4 Black Box worker

Systemd unit or transient unit: `va-watchdog-blackbox@<incident-id>.service`  
Normal process count: zero  
Incident process count: one  

Responsibilities:

- Accept a validated incident manifest.
- Persist the pre-trigger ring supplied by Core.
- Run high-detail collectors with strict timeouts.
- Record collector duration, errors, and missing tools.
- Continue through the post-event window.
- Produce incident summary and evidence indexes.
- Exit cleanly after finalisation.

Only one active Black Box worker is allowed. Additional triggers are attached to the active incident.

### 2.5 Privileged action helper

Execution model: short-lived Setup or Diagnostics process, not continuously running.

Responsibilities:

- Validate a narrowly defined action.
- Require action-specific confirmation.
- Apply only the requested change.
- Write an audit result.
- Return a bounded result to the caller.

It handles watchdog installation, journald enablement, storage setup, service guards, updates, and approved manual recovery actions.

## 3. Normal-Mode Collection

Normal mode must collect only data needed to establish liveness, detect degradation, or provide pre-incident context.

| Collector | Reason for continuous operation | Preferred source | Nominal interval | Subprocess allowed |
|---|---|---|---:|---|
| Heartbeat | Feeder liveness decision | monotonic clock, boot ID | 5 seconds | No |
| Sampling delay | Detect scheduler or core stalls | monotonic clock | 5 seconds | No |
| Overall and per-core CPU | Detect system or single-core saturation | `/proc/stat` deltas | 5 seconds | No |
| Memory availability | Detect exhaustion | `/proc/meminfo` | 5 seconds | No |
| Pressure | Detect CPU, memory, and I/O contention | `/proc/pressure/*` | 5 seconds | No |
| Boot and uptime | Identify reboot/discontinuity | `/proc` | 5 seconds | No |
| Core services | Detect stopped/restarting gateway functions | cached systemd properties or bounded query | 10-15 seconds | Bounded only |
| Service resources | Identify runaway configured services | `/proc/<pid>` deltas | 10-15 seconds | No |
| Recording mount | Detect loss/read-only/write failure | mount data and bounded write probe | 30 seconds | No |
| Root storage | Prevent loss of evidence/OS function | `statvfs` | 30 seconds | No |
| Interface counters | Detect link/reset/error changes | `/sys/class/net` | 10-30 seconds | No |
| Essential reachability | Detect communication failure | bounded local target probe | 30 seconds | Bounded only |
| Temperature | Detect thermal degradation | `/sys/class/thermal`, hwmon | 30 seconds | No |
| Kernel fault cursor | Detect decisive kernel evidence | journal cursor/checkpoint | 15-30 seconds | Bounded only |
| SMART summary | Detect drive degradation | `smartctl` | startup and 6-12 hours | Yes, outside critical path |

Each collector result includes start monotonic time, duration, outcome, age, and error. The core loop consumes the most recent result and never waits beyond a collector deadline.

## 4. Black Box Collection

Black Box mode is triggered by sustained or decisive abnormalities. It records:

- High-frequency overall and per-core CPU.
- CPU run queue, context switches, interrupts, and soft interrupts.
- Top processes and threads with parent process and resource rates.
- Memory detail, swap, page faults, and pressure.
- Block I/O rates, queue pressure, latency indicators, and filesystem state.
- Interface counters, errors, drops, routes, neighbours, and essential reachability.
- Configured service process trees and recent journals.
- Kernel messages collected from a cursor.
- SMART and device information when storage is implicated.
- Core and feeder timing, errors, and missed deadlines.

Black Box mode must not delay Core or Feeder. Failure of one collector produces a missing-evidence record and does not terminate the incident.

## 5. Incident State Machine

States:

- `normal`: no confirmed abnormal condition.
- `suspect`: one or more conditions are pending duration confirmation.
- `capturing`: an incident is open and detailed collection is active.
- `post_event`: triggers have recovered, but evidence capture continues.
- `finalising`: worker output and summary are being closed.

Multiple simultaneous findings belong to one incident. A cooldown prevents rapid close/reopen cycles.

## 6. Communication Contracts

Communication uses bounded files and systemd activation rather than a shared in-process web/core implementation.

| Producer | Consumer | Contract |
|---|---|---|
| Core | Feeder | Atomically replaced `heartbeat-state.json` with boot ID and monotonic heartbeat |
| Setup/trip action | Feeder | Atomically replaced, validated control state with expiry and action ID |
| Feeder | Core/Web | Atomically replaced feed status snapshot |
| Core | Web | Atomically replaced operator status snapshot |
| Core | Black Box | Immutable incident manifest plus transient service start |
| Black Box | Core/Web | Append-only incident evidence and atomic worker status |
| Core | Web | Append-only events/history plus atomic indexes |
| Web | Helper | Narrow authenticated action request; no arbitrary command input |

Files read for live decisions must be atomic snapshots. JSONL is for forensic history, not live control decisions.

## 7. Configuration Ownership

One versioned configuration document owns operator policy. Runtime-generated state never modifies configuration implicitly.

Configuration sections:

- `core`: intervals, essential services, normal collectors.
- `feeder`: device, interval, timeout, stale threshold, grace, magic close policy.
- `triggers`: durations, hysteresis, cooldown, enabled trigger classes.
- `blackbox`: sampling, pre/post windows, collector profiles, incident retention.
- `storage`: root and recording-storage identity and policy.
- `network`: interfaces and essential reachability targets.
- `web`: bind address, port, authentication policy.
- `setup`: update channel and approved administrative options.

Only Setup writes configuration. Writes require validation, backup, atomic replacement, audit event, and a controlled reload or restart.

## 8. Performance Budgets

Targets apply to a four-core Intel Atom gateway under normal operation.

| Resource | Target | Hard review threshold |
|---|---:|---:|
| Core average machine CPU | below 0.5% | 1.0% |
| Feeder average machine CPU | below 0.1% | 0.25% |
| Combined resident memory | below 75 MB | 100 MB |
| Normal fast sample p95 | below 100 ms | 250 ms |
| Normal fast sample maximum | below 500 ms | 1 second |
| Heartbeat publication jitter p99 | below 1 second | 2 seconds |
| Normal persistent data writes | below 10 MB/day | 20 MB/day |
| Normal subprocess concurrency | zero preferred | one bounded slow collector |
| Active incident CPU | below 3% average | 5% average |
| Active incident memory | below 150 MB total | 200 MB |

Performance must be measured on the target gateway, not inferred from a development PC.

## 9. Failure Behaviour

| Failure | Required behaviour |
|---|---|
| Normal collector hangs | Deadline expires; result marked stale; heartbeat continues; incident trigger may activate |
| Slow external command | Command is terminated; failure recorded; no heartbeat impact |
| Core crashes | systemd restarts Core; Feeder continues during allowed grace, then applies stale policy |
| Web crashes | systemd restarts Web; Core and Feeder remain unaffected |
| Black Box worker crashes | systemd records failure; Core keeps incident open and may retry once; normal supervision continues |
| Feeder crashes | systemd restarts it; device-close/nowayout policy determines protection; event and state record required |
| Disk full | Retention protects reserved evidence capacity; Core remains operational with reduced history |
| Journald unavailable | Evidence notes unavailability; Core continues |
| Network unavailable | Local monitoring and hardware feeding continue |
| Clock changes | Live decisions use monotonic time; evidence records UTC and monotonic time |
| Configuration invalid | Last known valid configuration remains active; error displayed and audited |

## 10. Recovery Policy

Recovery is deliberately narrow:

- systemd restarts failed watchdog processes.
- The hardware watchdog resets the gateway only after confirmed liveness failure or deliberate testing.
- Ordinary CPU, storage, network, and service health conditions do not stop feeding.
- Automatic service restart is disabled by default and requires service-specific approval.
- General critical-health automatic reboot is removed.
- Manual reboot and service restart remain explicit authenticated Diagnostics actions.

## 11. Data Retention

- Current snapshots are atomic and replaceable.
- Normal history is concise, one-minute, and age/size bounded.
- The in-memory pre-trigger ring retains 10-15 minutes of five-second samples.
- Open incidents are never purged.
- Closed incidents are bounded by age, count, and total bytes.
- Reboot evidence is attached to the matching open incident where possible.
- Retention never touches CCTV recordings.
- Evidence storage exhaustion creates a prominent operational fault.

## 12. Security and Safety

- Web runs unprivileged.
- Read-only endpoints dominate normal operation.
- State-changing actions require authentication, confirmation, allow-listed arguments, and audit events.
- Destructive disk operations are Setup-only and retain existing system-disk protections.
- No HTTP input is interpolated into a shell command.
- Secrets are not written to support bundles.
- Exported bundles include a manifest and redaction report.

## 13. Architecture Change Control

A new continuous collector is rejected unless its proposal documents:

- Continuous operational reason.
- Why incident-only collection is insufficient.
- CPU and memory measurements.
- Disk-write estimate.
- Timeout and cancellation behaviour.
- Heartbeat isolation.
- Failure mode.
- Test coverage.
- Retention impact.

Architecture changes require updating this document before implementation.

