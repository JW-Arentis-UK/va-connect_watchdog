# Ellingers Production Comparison And Retest

Status: Corrected 15-minute and one-hour recording comparisons reviewed

Ellingers capture: `va-watchdog-stage0-POC-451VTC-20260722T140011Z.tar.gz`

Non-recording test capture: `va-watchdog-stage0-POC-451VTC-20260722T140043Z.tar.gz`

## Corrected Finding

The Ellingers gateway was the `140011Z` capture. It was actively recording. The `140043Z` gateway was the non-recording reference.

| Measurement | Ellingers recording | Test unit not recording |
|---|---:|---:|
| Mean gateway CPU | 24.3% | 3.7% |
| Maximum gateway CPU | 38.0% | 5.6% |
| Maximum individual core | 42.4% | 7.0% |
| Mean I/O PSI some | 3.3% | 0.04% |
| Maximum I/O PSI some | 62.2% | 2.0% |
| Maximum heartbeat gap | 15.42s | 5.63s |
| ESG process CPU at end | 77.5% one-core / 19.4% machine | 0.2% |
| Events during capture | 58 | 1 |

Ellingers did not have global CPU or memory exhaustion. Its strongest abnormal signal was intermittent I/O pressure accompanied by delayed serial health cycles. The 15.42-second delay exceeded the old 15-second feeder stale threshold.

Neither capture had an installed `va-watchdog-feed.service`. Ellingers also had hardware feeding disabled and `/dev/watchdog0` absent. Hardware recovery must not be enabled merely to run this comparison.

## Pre-Retest Changes

- A dedicated lightweight thread publishes process heartbeat every five seconds.
- Health sequence and last successful health sample remain separate fields.
- Systemd watchdog notification remains tied to successful health-loop completion, so a genuinely stuck collector loop is still restarted by systemd.
- Service resource events use total-machine CPU rather than Linux one-core process CPU.
- Warning, critical, and recovery transitions require sustained confirmation and recovery hysteresis.
- History retention compacts at most hourly and only rewrites when rows are removed.
- Legacy Black Box retention compacts in batches instead of rewriting after every appended row.
- Stage 0 samples physical-disk `/proc/diskstats`, selected `/proc/vmstat` counters, kernel messages, warning-level journal entries, and effective journald configuration.
- The heartbeat evidence tail is increased to 2,000 rows so a complete one-hour run is retained.

## One-Hour Retest Protocol

1. Update both gateways to the same commit and restart `va-watchdog.service`.
2. Leave hardware feeding disabled for this comparison unless the independent feeder has separately passed its installation and trip-test procedure.
3. Configure the test gateway to record a representative camera workload.
4. Confirm both recording destinations are mounted and writable.
5. Confirm `/api/healthz` responds and the Diagnostics Stage 0 readiness checks pass.
6. Start a one-hour Stage 0 baseline on both gateways as close together as practical.
7. Avoid updates, manual service restarts, speed tests, and configuration changes during the capture.
8. Download both completed bundles from Diagnostics.
9. Compare heartbeat timing, health-sequence timing, disk service time, weighted queue time, I/O PSI, dirty/writeback pages, ESG CPU, memory, kernel warnings, and watchdog write volume.

## Acceptance Questions

- Does independent heartbeat remain close to five seconds while health collection is delayed?
- Which physical disk accumulates service time during each I/O PSI spike?
- Do dirty or writeback pages rise before the delay?
- Does ESG total-machine CPU remain below the sustained warning threshold?
- Does event volume remain bounded without losing meaningful sustained transitions?
- Does the reduced compaction policy materially lower watchdog process writes?
- Are kernel, filesystem, SATA, or block-I/O warnings recorded during the same window?

## One-Hour Recording Retest Results

Ellingers capture: `va-watchdog-stage0-POC-451VTC-20260722T150226Z.tar.gz`

Recording test-unit capture: `va-watchdog-stage0-POC-451VTC-20260722T150240Z.tar.gz`

Both captures ran for 3,595 seconds and contained 720 Stage 0 samples. The test unit was recording during this comparison; its recording disk wrote 4.06 GiB during the hour.

| Measurement | Ellingers recording | Test unit recording |
|---|---:|---:|
| Mean gateway CPU | 25.4% | 23.9% |
| 95th percentile gateway CPU | 30.4% | 25.2% |
| Maximum gateway CPU | 35.0% | 74.9% transient |
| Maximum individual core | 42.5% | 82.2% transient |
| Mean I/O PSI some | 0.71% | 0.11% |
| Maximum I/O PSI some | 53.72% | 3.73% |
| Maximum I/O PSI full | 39.08% | 2.63% |
| Recording-disk writes | 7.30 GiB | 4.06 GiB |
| Recording-disk average queue | 0.082 | 0.026 |
| Recording-disk maximum five-second weighted queue | 27.23 | 0.20 |
| Recording-disk average request latency | 21.23 ms | 11.90 ms |
| Independent heartbeat mean / maximum gap | 5.00s / 5.01s | 5.00s / 5.01s |
| Health-loop mean / maximum gap | 5.52s / 10.72s | 5.37s / 7.33s |
| Health-loop gaps above 10 seconds | 2 | 0 |
| Available memory mean | 6,019 MiB | 6,126 MiB |
| Watchdog cgroup CPU, one-core scale | 5.18% | 4.93% |
| Watchdog retained-data growth | 1.08 MiB | 1.21 MiB |

### Findings

1. The independent heartbeat publisher met its five-second timing target on both gateways. No heartbeat interval exceeded 5.01 seconds.
2. Ellingers still showed intermittent recording-disk pressure. The largest event occurred at approximately `2026-07-22T15:58:11Z`: I/O PSI `some` reached 53.72%, I/O PSI `full` reached 39.08%, the five-second weighted disk queue reached 27.23, and the health loop took 10.72 seconds. Lesser correlated bursts occurred around 15:17, 15:42 and 15:56 UTC.
3. The test unit recorded continuously without comparable disk pressure. Its maximum five-second weighted queue was 0.20 and its longest health-loop interval was 7.33 seconds.
4. Neither gateway showed sustained CPU saturation, a pinned core, memory pressure, swap activity of operational significance, a service restart, an OOM event, a lockup, a filesystem error, or a block-I/O error during the capture.
5. Ellingers' recording filesystem remained at its Videosoft-managed floor of approximately 1.9 GiB free. The test recording filesystem remained effectively empty. The difference in filesystem occupancy and recording throughput means this is a useful operational comparison, but not a perfectly matched storage test.
6. Ellingers produced 2,163 warning-priority journal records during the hour, almost entirely a repeating Videosoft tunnel connect/read-error/close cycle. The test unit produced 1,404 warning records, including 1,397 from the same tunnel cycle. Ellingers' persistent journal occupied 4.0 GiB versus 96 MiB on the test unit. This is not evidence of the system hang by itself, but the repeated tunnel warnings and journal growth should be investigated or rate-limited.
7. The Stage 0 capture itself remained low impact: the main watchdog process used approximately 1.1-1.3% of one CPU core, the complete watchdog cgroup averaged approximately 5% of one core while the diagnostic sampler was active, and retained watchdog data grew by only 1.1-1.3 MiB.

### Stage 0 Decision

The production comparison confirms that recording-related disk latency is the strongest observed difference on Ellingers. It does not prove that storage caused the historical complete freezes, because no freeze or kernel fault occurred during this hour.

The heartbeat and physical-disk additions are accepted. Stage 0 remains open only for the independent hardware-feeder baseline and the outstanding architecture/safety approvals. Both captures reported that `va-watchdog-feed.service` was not installed. Ellingers also had `/dev/watchdog0` absent and hardware feeding disabled; the test unit had `/dev/watchdog0` present and feed configuration enabled, but no feeder process owned or fed it.
