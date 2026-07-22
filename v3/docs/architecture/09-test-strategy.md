# Test Strategy

Status: Draft for approval

## Objectives

Testing must prove that the watchdog remains alive, does not create instability, preserves useful evidence, and fails safely when optional tools or components are unavailable.

## Test Layers

### Unit Tests

Cover pure policy and parsing behaviour:

- Monotonic heartbeat freshness.
- Startup grace.
- Trigger duration, hysteresis, recovery, and cooldown.
- CPU and per-core `/proc/stat` deltas.
- Memory, PSI, network, and service counter parsing.
- Collector deadline and stale-result handling.
- Event deduplication.
- Incident state transitions.
- Reboot classification and confidence.
- Retention calculations.
- Configuration validation and migration.
- Partial JSONL and corrupt snapshot handling.

### Component Tests

Run processes with temporary data and fake system interfaces:

- Core scheduler with slow, failed, and hung collectors.
- Feeder with a fake watchdog device.
- Black Box worker with missing tools and timed-out commands.
- Web against frozen status/incident fixtures.
- Setup helper against disposable configuration and disk images.

### Contract Tests

Verify versioned contracts:

- Heartbeat state.
- Feed status.
- Operator status.
- Active incident marker.
- Incident manifest and final index.
- Events and history rows.
- Public API responses.
- Support-bundle manifest.

Known current API/configuration fixtures must remain readable during migration.

### System Tests

Use systemd or an equivalent isolated process harness:

- Start, stop, restart, and crash each service independently.
- Restart Core while Feeder remains active.
- Restart Feeder while Core remains active.
- Crash Web during active monitoring.
- Crash Black Box worker during an incident.
- Prevent duplicate feeder ownership.
- Exercise normal shutdown, reboot, abrupt kill, and power-loss recovery where safe.

### Target-Hardware Tests

Run on POC-451VTC or representative hardware:

- Detect and configure iTCO watchdog.
- Verify timeout and feed interval.
- Test magic-close and nowayout behaviour.
- Execute deliberate trip test with remote recovery plan.
- Confirm startup grace permits remote access.
- Measure resource budgets.
- Validate persistent journal and reboot evidence.

## Fault Injection Matrix

| Fault | Expected result |
|---|---|
| Collector sleeps indefinitely | Collector deadline; heartbeat/feed continue; timing incident recorded |
| CPU saturated | Sustained trigger; pre-buffer preserved; CPU profile captured |
| One core pinned | Per-core trigger; process/thread evidence captured |
| Memory exhausted | Pressure trigger; swap/OOM evidence captured; Core remains responsive where OS permits |
| I/O blocked | I/O trigger; collector timeouts; heartbeat remains independent |
| Recording mount removed | Operational fault and incident; no automatic unmount/reformat/reboot |
| Filesystem read-only | Decisive incident; evidence redirected where possible |
| Interface down | Network incident; local watchdog remains operational |
| Service crash loop | One incident with restart timeline, not event flooding |
| Kernel OOM/lockup test message | Kernel trigger and classified event |
| UTC clock jumps | No live freshness error because monotonic time is used |
| Heartbeat stops | Feeder stops feeding after grace/policy and hardware reset occurs in controlled test |
| Web request hangs | Core and Feeder timing unaffected |
| Evidence limit reached | Bounded degradation and prominent missing-evidence record |

## Performance Tests

Measure on target hardware:

- Per-process CPU and RSS over a 24-hour normal soak.
- Heartbeat jitter distribution.
- Fast collector p50, p95, p99, and maximum runtime.
- Disk bytes written per day.
- Subprocess count and duration.
- Incident worker CPU, memory, and I/O under each profile.
- Core behaviour under CPU, memory, and I/O stress.

Budgets from the architecture specification are release gates.

## Soak Tests

- Minimum 72-hour development soak after process separation.
- Minimum 14-day POC soak before field rollout.
- Observation-mode trigger logging before automatic Black Box activation.
- No unbounded file growth, process growth, thread growth, or event flooding.

## Update and Rollback Tests

- Clean installation.
- Upgrade from current V3 configuration.
- Failed download/fetch.
- Invalid configuration migration.
- Service restart failure.
- Rollback to last validated build.
- Reboot after update.
- Update while an incident is active must be blocked or explicitly deferred.

## Evidence Quality Tests

For each simulated incident, verify:

- Expected pre-trigger coverage exists.
- Trigger and recovery timestamps are monotonic and UTC-correlated.
- Collector failures are visible.
- Reboot evidence attaches to the correct incident.
- Reset mechanism and probable preceding fault remain separate.
- Support bundle can be generated remotely.
- An engineer can understand the timeline without raw-code knowledge.

## Coverage Expectations

- Safety policy modules: at least 90% statement and branch coverage.
- Core scheduler, feeder policy, incident state, config migration: at least 85% branch coverage.
- UI rendering: fixture and route coverage focused on behaviour rather than cosmetic markup.
- Every production bug receives a regression test.

