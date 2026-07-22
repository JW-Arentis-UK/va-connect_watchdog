# POC Performance Baseline

Status: Collection tool ready; gateway capture pending

## Purpose

Capture the current V3 cost and timing before refactoring. The result becomes the comparison point for every later stage.

## Tool

Run [stage0_baseline.sh](../../../scripts/stage0_baseline.sh) on the POC gateway. It is read-only and uses raw process/system counters wherever possible.

Default collection is 15 minutes at five-second intervals:

```bash
cd /opt/va-connect-watchdog-v3
sudo bash ./v3/scripts/stage0_baseline.sh
```

For a more representative one-hour capture:

```bash
sudo bash ./v3/scripts/stage0_baseline.sh 3600 5
```

The final output is a `.tar.gz` bundle in `/tmp`. Download that bundle before cleaning or updating the gateway.

## Data Collected

- Kernel, hardware, boot ID, uptime, branch, and commit.
- Current watchdog configuration with common credential fields redacted, plus file metadata.
- Main and feeder unit definitions and systemd properties.
- Raw `/proc/stat`, `/proc/loadavg`, `/proc/meminfo`, and PSI snapshots.
- Main and feeder PID CPU, RSS, thread count, and elapsed time.
- Core systemd CPU/memory/task accounting.
- Heartbeat and hardware-feed state snapshots.
- Watchdog data-directory size at start and finish.
- File-size inventory for watchdog evidence.
- Current status and health endpoints where locally available.
- Recent watchdog service journals.

It does not run SMART, speed tests, broad pings, or destructive actions.

## Measurements To Calculate

| Measurement | Current baseline | Target |
|---|---:|---:|
| Main watchdog average machine CPU | Pending | below 0.5% Core after refactor |
| Hardware feeder average machine CPU | Pending | below 0.1% |
| Main RSS p95 | Pending | contributes to below 75 MB combined |
| Feeder RSS p95 | Pending | minimal and stable |
| Main task/thread maximum | Pending | bounded |
| Heartbeat interval p50/p95/p99/max | Pending | p99 jitter below 1 second |
| Status sample interval p50/p95/p99/max | Pending | no critical-path delay |
| Data-directory growth per day estimate | Pending | below 10 MB/day normal writes |
| Event rows per hour | Pending | transitions only; no flooding |
| Subprocess activity | Pending | minimal in target normal mode |

## Baseline Conditions

Record alongside the bundle:

- Gateway name and model.
- CPU and RAM.
- Number of configured cameras/streams.
- Recording service state.
- Recording disk state and utilisation.
- Hardware watchdog enabled/disabled.
- Whether an incident or fault was active.
- Local date/time and collection duration.

## Acceptance

Stage 0 baseline is complete when:

- A bundle has been collected on POC-451VTC.
- CPU, memory, timing, task, and disk-growth values are summarised in this document.
- Any unexplained spikes are noted.
- The raw bundle is stored outside the gateway.
- The refactor performance targets are confirmed or revised with reasons.
