# Ellingers Production Comparison And Retest

Status: Corrected 15-minute comparison reviewed; one-hour retest pending

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
