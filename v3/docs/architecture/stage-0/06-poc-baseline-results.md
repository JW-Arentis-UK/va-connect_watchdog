# POC-451VTC Baseline Results

Status: One-hour baseline reviewed; feeder and write-I/O follow-up pending  
Capture: `va-watchdog-stage0-POC-451VTC-20260722T110705Z.tar.gz`  
Capture window: 2026-07-22 11:07:05Z to 12:07:05Z  
Gateway: POC-451VTC, Intel Atom x6425E, four physical/logical cores, 7.6 GB RAM  

## Capture Quality

- 720 raw samples were collected over 3,594.95 seconds.
- The main watchdog PID remained unchanged.
- The health sequence had no gaps.
- No watchdog events were generated during the capture.
- Main and feeder journal queries returned no entries.
- The hardware feeder was inactive, so feeder resource and timing budgets could not be measured.
- Net data growth was measured, but the original collector did not record process I/O counters. Application write volume is therefore estimated from the observed files and current code.

Evidence confidence: Medium.

## CPU

| Measurement | Mean | p95 | p99 | Maximum |
|---|---:|---:|---:|---:|
| Whole gateway CPU | 3.18% | 4.17% | 4.77% | 5.55% |
| Core 0 | 3.07% | 4.37% | 5.12% | 6.00% |
| Core 1 | 3.59% | 4.96% | 5.59% | 6.99% |
| Core 2 | 3.01% | 4.55% | 5.11% | 5.57% |
| Core 3 | 3.03% | 4.38% | 5.11% | 6.55% |
| Watchdog cgroup, one-core scale | 3.33% | 5.89% | 7.51% | 8.12% |
| Watchdog cgroup, machine scale | 0.83% | 1.47% | 1.88% | 2.03% |

The watchdog cgroup consumed approximately 26% of the gateway CPU used during this otherwise quiet hour. The dashboard process figure ended around 0.6-0.8% on a one-core scale, but that excludes child commands. Systemd cgroup accounting includes commands such as `top`, `systemctl`, journal tools, storage probes, and Black Box collectors, making it the more representative cost.

Architecture implication: the target below 0.5% machine CPU requires moving shell-heavy work out of normal mode and replacing shell CPU collection with `/proc/stat` deltas.

## Memory

| Measurement | Result |
|---|---:|
| Main process RSS at start | 39.15 MB |
| Mean RSS | 59.54 MB |
| p95 RSS | 62.35 MB |
| Maximum RSS | 63.52 MB |
| RSS at end | 61.62 MB |
| Minimum system available memory | 6,303.85 MB |

Most growth occurred during the first 15-20 minutes after the main service had started. RSS then remained around 60-63 MB, but the final 30-minute trend was still approximately +1.66 MB/hour. A longer soak is required before declaring this warm-up rather than gradual retention.

Architecture implication: splitting Web from Core may increase total process overhead unless shared state and page rendering are kept small. Core and Web must be measured separately after extraction.

## Timing

| Measurement | Mean | p95 | p99 | Maximum |
|---|---:|---:|---:|---:|
| Baseline tool sample interval | 5.000 s | 5.060 s | 5.068 s | 5.070 s |
| Main heartbeat interval | 5.375 s | 5.620 s | 5.630 s | 5.640 s |

The heartbeat was stable and had no sequence gaps. The current loop sleeps for five seconds after collection, so approximately 0.38 seconds of collection time is added to the intended interval. This is safe in the captured healthy hour but means slow collectors directly extend heartbeat age.

Architecture implication: heartbeat publication must move to an independent deadline, not remain at the end of serial collection.

## Pressure

| Measurement | Mean avg10 | p95 avg10 | Maximum avg10 |
|---|---:|---:|---:|
| CPU PSI some | 0.0000 | 0.0000 | 0.0100 |
| Memory PSI some | 0.0000 | 0.0000 | 0.0000 |
| I/O PSI some | 0.0766 | 0.2705 | 3.9800 |
| I/O PSI full | 0.0760 | 0.2705 | 3.9800 |

No sustained CPU or memory pressure was present. Brief I/O pressure occurred but was not sustained.

## Data Growth And Write Amplification

| File | Net change in one hour |
|---|---:|
| `heartbeat.jsonl` | +168,687 bytes |
| `history.jsonl` | +99,739 bytes |
| `blackbox.jsonl` | +11,014 bytes |
| Events | No change |
| Whole watchdog directory | +279,221 bytes |

Net growth extrapolates to approximately 6.7 MB/day, within the proposed 10 MB/day retained-data target. Net growth does not represent bytes written to storage.

Current code rewrites:

- The complete 2.0-2.1 MB history file every minute.
- The complete approximately 3.5 MB Black Box file every minute once its row limit is reached.
- The approximately 12 KB status snapshot twice per approximately 5.4-second cycle.

The resulting application-write estimate is approximately 335 MB/hour or 7.9 GB/day before filesystem journal and metadata amplification. Actual process and block-device write counters were not captured in this first bundle.

Architecture implication: periodic detailed Black Box capture and full-file-per-sample trimming are priority removals. Retention should rotate segments or compact infrequently outside the heartbeat path.

## Hardware Watchdog Protection

The capture found:

- `/dev/watchdog0` reported present.
- Hardware feed was enabled in configuration.
- `va-watchdog-feed.service` was `inactive (dead)`.
- Feed count was zero.
- Last feed timestamp was empty.
- No feeder journal entries were available.

The gateway therefore had a watchdog device but no active independent hardware feeding during this capture. This is an operational protection gap and prevents completion of the feeder performance baseline.

## Services And Health

- `esg.service`, `bridge.service`, `esg-config.service`, and `sysops.service` were active with no recorded restarts.
- Runtime migration added `sysops.service` although the stored configuration listed the original three services.
- Recording storage was mounted, writable, correctly labelled, and effectively empty.
- Overall status remained Warning because recording SMART was unavailable and hardware feeding was inactive.
- No events were added during the hour.

## Deployment Hygiene

The gateway reported:

```text
codex/v3-gateway-ready...origin/codex/v3-gateway-ready [ahead 23]
```

The running commit was `8443ba0`, but the local deployment branch was 23 commits ahead of its configured upstream. This makes ordinary `git pull` and rollback behaviour harder to predict.

Architecture implication: Stage 0 branch/tag policy must be applied before refactor deployment. Gateways should run an exact validated tag or commit rather than a locally divergent branch.

## Required Follow-Up

1. Inspect why `va-watchdog-feed.service` is inactive before starting it.
2. Complete a controlled feeder enable/start and verify device ownership and feed state.
3. Run the updated 15-minute baseline with process/cgroup I/O counters after the feeder is active.
4. Confirm persistent journald status and why service journal queries returned no entries.
5. Normalise the gateway deployment branch during a controlled release step.
6. Retain the current CPU, memory, heartbeat, and write estimates as the pre-refactor comparison.

The updated capture can now be started from `Diagnostics > Stage 0 System Baseline` for either 15 minutes or one hour. Progress survives a Web page or main-service restart because the collector runs in a transient systemd unit. The latest completed `.tar.gz` bundle can be downloaded from the same panel; no remote filesystem transfer is required.
