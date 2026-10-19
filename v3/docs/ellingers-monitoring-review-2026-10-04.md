# Ellingers watchdog review — 4 October 2026

## Decision

Keep the evidence that distinguishes a host freeze, application failure, network
outage and deliberate recovery. Simplify the display immediately. Consolidate
recovery and logging in a separate, tested migration. The number of menus and
the volume of routine logs are not a measure of diagnostic coverage.

The new `/lite` view is deployed alongside the existing dashboard. It reads saved
results, adds no probes or log streams, and changes no recovery configuration.
Its shortlist controls record review preferences only. The full UI remains
available. The earlier lite files under `tools/ubuntu/web/` belong to the legacy
application; this option is integrated into the V3 application running on port 9110.

## Evidence reviewed

Reviewed the live gateway's effective configuration, saved status and check
results, systemd service states, storage footprints, hardware-feed evidence and
this morning's reboot evidence. Inspected the V3 collectors, recorder, heartbeat,
recovery, history, events, retention and web implementation, plus the legacy
watchdog's checks, recovery and logging. Browsed the running dashboard and tested
the lite view against live data. This was a read-only audit of monitoring behaviour,
not a simulated crash or a long-duration performance benchmark.

The gateway is POC-451VTC, Ubuntu 22.04.5. Times in the investigation are BST.
This morning's reboot command was logged at 00:12:08 after about five minutes
without LAN/internet connectivity. The host shut down cleanly. This explains that
restart; it does not explain every historical freeze or the underlying network fault.

### Live footprint (approximately 17:55 BST)

| Store | Observed size | Interpretation |
|---|---:|---|
| Legacy event log | 524.9 MiB | Largest watchdog file; repeated full heartbeat/check payloads |
| Entire legacy log directory | 532.9 MiB / 938 files | Events plus snapshots, metrics and tool logs |
| Entire V3 data directory | 88.7 MiB / 321 files | Close to its configured 100 MiB budget |
| V3 history | 69.8 MiB | Main V3 space consumer; structured per-minute payloads |
| V3 event log | 7.1 MiB | State transitions and other events |
| V3 heartbeat history | 2.7 MiB | A bounded recent liveness trail |
| Current compressed blackbox buffer | 0.32 MiB | 450 samples covering 15 minutes; useful and relatively small |
| System journal | 552 MiB reported | Separate from both watchdog data budgets |

These are footprint snapshots, not growth-rate measurements. The V3 directory
also contains an older `blackbox.jsonl` (~2.5 MiB); verify provenance before cleanup.
No evidence was deleted during this review.

## What is measured and what to keep

Intervals below are configured collector/cache intervals; slow collectors and
the loop's final sleep mean they are not hard sampling guarantees.

| Family | Current measurement / capture | Current cadence | Recommendation |
|---|---|---|---|
| System health | CPU utilization, hottest thermal sensor, RAM, root filesystem space | V3 hardware 5s; storage 30s | Keep; show a compact summary, retain numeric trends |
| Videosoft services | `esg`, `bridge`, `sysops`, `esg-config`; active state and resource use | 15s | Keep service state and resource spikes; do not equate “active” with recording progress |
| Recording storage | Dedicated mount, writable status, free space, temperature/SMART-related evidence | Storage 30s; SMART cached for 6h in source | Keep actual recording mount and free reserve; remove duplicate/misleading disk cards |
| Generic disk/write checks | Root and configured recording path; write test defaults to `/tmp` | 30s | Keep root write evidence, label its target; it does not prove the CCTV filesystem accepts recordings |
| Connectivity | V3 internet targets, optional local targets; older monitor's router TCP check and internet pings | 30s | Keep LAN/router and WAN separately; record failures and recoveries |
| Mobile router | Availability, radio strength/quality, cell/interface changes | 60s | Keep outage context; collapse frequent cell-change events; engineering fields in details |
| Monitor resources | Watchdog CPU/RAM, sustained thresholds | 5s | Keep for observer overhead; long-term summary can be much smaller |
| Process heartbeat | Independent process liveness and last completed health sample | 5s; 3,600 rows / 5 MiB limits configured | Keep both liveness and progress; frequent history can share a bounded incident buffer later |
| Hardware feeder | Feed decisions, counts, errors, heartbeat age, health-progress age, boot ID | Feed 10s; timer 30s; stale heartbeat 15s / health progress 90s | Keep independent; show one clear protection status |
| Blackbox | CPU, RAM/pressure, disk I/O, free space, temperature, EDAC/kernel counters, Videosoft process metrics, heartbeat, router snapshot | 2s; 15-minute buffer; 10s checkpoints | Keep while crashes remain unexplained; this is more valuable than repeated ordinary heartbeat events |
| Kernel/reboot evidence | Kernel fault signatures, previous boot journal, pstore, boot IDs, `last -x`, requested reason, feeder state | Kernel scan about 30s; archive at boot transition | Keep; never infer a manual power cycle solely from absent software evidence |
| Incident archives | Previous boot blackbox, heartbeat, history, event tail, pstore and reboot report | On boot; 10 incidents / 25 MiB configured | Keep, with protected retention and visible missing-evidence warnings |
| Long-term history | Temperature, CPU/RAM, storage, service resources and state, router and recovery fields | 60s; 30 days / 50,000 rows configured | Reduce fields first; use 5-minute rollups beyond a short detailed window |
| Legacy snapshots | Process lists, memory/disk state, route/address, journal excerpts, SMART and other commands | Fault changes / pre-reboot with cooldown | Preserve existing incidents; migrate the useful snapshot into V3, then retire duplicate capture |
| Crossing/people counts | Camera metadata, counters, reports | Separate camera feature | Separate from crash monitoring; no evidence it is required to diagnose host freezes |
| Setup and engineering tools | Driver tests, deliberate trips, memory/speed tests, inventory, disk setup, updates, exports | Mostly manual/on demand | Keep behind engineering access; do not make these routine operator choices |

## Recovery ownership

There are currently five active watchdog-related services:

1. Legacy `va-connect-site-watchdog`: app/service checks, network restart and host
   reboot after persistent failure. Reboot is enabled, initially after 300s with
   backoff up to 3,600s. It requested this morning's reboot.
2. Legacy web service: another website and action surface.
3. V3 `va-watchdog`: collection, evidence and optional software recovery. Its
   software recovery is **disabled** on this gateway.
4. V3 `va-watchdog-feed`: independent hardware timer feed, gated by heartbeat and
   health-loop progress. Hardware protection is **enabled**.
5. V3 web service: separate web process, supervised by systemd.

Systemd also supervises V3 main and web liveness with 30-second watchdog settings.
These are complementary protections, not all duplicates:

| Failure | Intended response |
|---|---|
| Web process stops responding | Restart the web service; keep monitoring and feeding independent |
| Main monitor exits/hangs | Systemd recovery first; independent feeder observes heartbeat/progress |
| Host/kernel stops scheduling | Hardware timer can reset the host |
| Videosoft service fails | One bounded application-recovery policy |
| Router/WAN becomes unavailable | Record and distinguish local/remote failure; one agreed network-recovery policy |

Target: retain the V3 monitor, feeder and separate web service. Migrate necessary
legacy LAN checks and recovery policy into one owner, then retire the legacy
monitor and its website. Do not simply disable the old monitor today: V3 software
recovery is currently off, and that would remove the network/application recovery
which operated this morning. Do not merely enable both policies simultaneously.

## Findings that matter more than extra metrics

**1. Duplicate recovery/reporting obscures causality.** V3 could report a clean
restart without knowing the old watchdog initiated it. The deployed attribution
fix now connects the successful reboot action to the failed checks. Future
actions should all persist the same boot-scoped reason before taking action.

**2. Two “recording disk” answers refer to different filesystems.** Live generic
`recordings_disk` reported `/home/vsuser/recordings` at 21.3% used (matching root),
while dedicated recording storage reported 94.8% used and about 5.2 GiB free.
The lite view uses the dedicated check. Validate the actual Videosoft output
path and mount identity before consolidating the underlying checks.

**3. Fresh status does not guarantee fresh individual checks.** In
`health._cached_checks`, collector exceptions return previously cached results
without an age limit or an error annotation. A green check can survive repeated
collector failures. Add per-collector collected-at, error and stale limits before
trusting “healthy” as a complete end-to-end verdict. Lite detects stale overall
status/feed, but does not repair this collector limitation.

**4. Retention needs protected categories.** The global retention candidate list
includes active heartbeat, reboot-reason and feeder evidence files. Under budget
pressure it can remove old non-JSONL files, not just trim historical logs. Separate
live control/evidence state from disposable history. Protect active liveness and
latest-incident records, and rotate history/event segments rather than repeatedly
reading/rebuilding whole files. Current generic event reads also load the entire
event log for a small recent result; the lite endpoint reads at most 128 KiB.

**5. The legacy heartbeat stream dominates disk usage.** Source appends routine
heartbeats and full startup configuration; its snapshot retention does not bound
that event file. Startup config also contains credentials, so it should be
whitelisted/redacted at the producer. Preserve incident evidence before rotating
existing logs. The new lite API never returns raw configuration or event data.

**6. Process metrics are not recording-progress proof.** A running `esg` process,
healthy TCP port and writable disk do not prove video is advancing. Add one cheap,
bounded application-level progress signal: last successful recording write/segment,
camera stream progress, or an existing Videosoft health counter. Avoid repeated
recursive recording-tree scans.

**7. Network failures need more precise evidence, not faster pings.** This morning
the NIC stayed up with an address and route, but router and cameras were unreachable.
At the next transition, capture interface error/drop counters, default route and
neighbour/ARP state, router uptime/reconnect reason and LAN versus WAN reachability.
Correlate router/switch logs by timestamp. These additions are proposed, not deployed.

**8. A hard freeze can leave an evidence gap.** Ten-second blackbox checkpoints can
leave recent samples unwritten; actual survivability depends on storage and failure
mode. Local evidence cannot by itself always distinguish power loss from a hard
kernel/firmware hang. If repeated incidents remain inconclusive, use an independent
router/power log or a tested remote kernel-console capture rather than adding more
dashboard panels. These are options for a later controlled investigation.

## Proposed logging policy (not applied)

- One event stream: state transitions, recovery decisions/results and collector
  failures. Aggregate repeated informational changes, retaining counts and times.
- One before-crash ring: keep 2s / 15min / 10s checkpoints for this investigation.
  Benchmark any slower cadence before changing it; this buffer is currently small.
- Compact trends: 60s numeric summaries for 48h, then 5-minute rollups to 30 days.
  Proposed limits, not a promise of implemented retention.
- One incident bundle per boot/failure, including raw supporting evidence and an
  explicit confidence level. Reserve its own budget and protect the latest incident.
- Live heartbeat/feed/control files: exclude from generic log eviction. Keep the
  boot ID and timestamps required to attribute a shutdown.
- Journal: retain previous-boot kernel and relevant service evidence with a defined
  disk budget; don't blindly delete it to shrink watchdog data.
- Legacy logs: archive useful incidents, redact config at source, rotate/bound the
  file during migration, then stop creating duplicate heartbeat streams.

## Lite layout and validation

The page answers: Are checks current? Is Videosoft running? Is the network reachable?
Is actual recording storage healthy? Is hardware protection feeding? Why did the
last restart happen, and is before-crash capture current?

Five cards, one restart explanation and one short timeline replace the sidebar.
Repeated adjacent events are grouped in the lite display. A review table exposes
keep / details only / reduce / separate / retire-after-migration preferences and
downloads a shortlist. No preference changes gateway configuration. Advanced
controls are linked separately. A connection failure or stale sample is explicit;
missing measurements are not turned into green checks.

The endpoint uses bounded event reads and saved JSON; it executes no collectors,
shell commands, camera calls or recovery actions. The first live request was ~4 KiB
and completed in ~5ms locally on the gateway; the HTML was ~13 KiB. This is one
measurement, not a sustained-load benchmark.

Validation: targeted unit tests cover stale/missing status, actual recording-storage
selection, old hardware-feed timestamps, event grouping, malformed/large logs,
credential-field exclusion, preserved reboot reasons, read-only behaviour and
separate recovery ownership. Existing navigation tests pass. Browser testing checks
live rendering, collapsed details, preferences surviving refresh and shortlist export.

Deployment changes only the web view and its read-only endpoint. The full UI remains
the default. Web source backup:
`/var/backups/va-watchdog/lite-review-20261004/web.py`.
No crash test, host reboot, logging purge or recovery-policy change was performed.

## Suggested next implementation order

1. Review the lite shortlist and agree the five-card operator view.
2. Fix per-check freshness, protect liveness/incident files from retention and stop
   writing configuration secrets to the legacy event stream.
3. Unify recording-path checks; add a bounded Videosoft progress signal and
   transition-triggered network evidence.
4. Define and test one recovery state machine with explicit causes, cooldowns,
   retry limits and boot-scoped persistent reasons. Migrate the legacy behaviour.
5. Retire the legacy services, then replace duplicate logs with compact trends
   and bounded incident storage. Compare measured overhead before/after.

## Source map

- `v3/va_watchdog/health.py`, `hardware.py`, `storage.py`, `services.py`, `network.py`,
  `mobile_router.py`, `process_monitor.py`: measurements and caches.
- `watchdog.py`, `heartbeat.py`, `watchdog_feed.py`, `recovery.py`: supervision and recovery.
- `blackbox.py`, `incident_archive.py`, `reboot_evidence.py`, `crash_evidence.py`:
  capture and reboot attribution.
- `history.py`, `events.py`, `retention.py`: persistence, repeated payloads and eviction.
- `web.py`, `web_service.py`, `lite.py`, `lite.html`: full and lite presentation.
- `tools/ubuntu/va_connect_site_watchdog.py`: legacy recovery, heartbeat log and snapshots.
