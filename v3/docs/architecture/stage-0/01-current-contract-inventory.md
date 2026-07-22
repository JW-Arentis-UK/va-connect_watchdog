# Current Contract Inventory

Status: Frozen migration inventory  
Source branch: `codex/gui-refresh`  
Source commit reviewed: `252ac5a`  

This inventory records the current V3 surface. It does not promise that every route or setting survives the refactor. It prevents accidental removal before compatibility is assessed.

## HTTP Pages

| Area | Routes | Migration classification |
|---|---|---|
| Operations | `/`, `/events` | Keep capability; simplify implementation |
| Engineering | `/hardware`, `/storage`, `/network`, `/services`, `/watchdog`, `/history`, `/settings`, `/diagnostics` | Consolidate into History, Setup, and Diagnostics |
| Recovery | `/recovery`, `/updates` | Move actions to Setup/Diagnostics |
| Compatibility | `/index*`, `/basic*` | Removal candidate after forwarding-browser validation |

## Stable Read Contracts

These capabilities require compatibility during the refactor. A schema version may be added, but existing fields should remain available through an adapter until consumers are confirmed.

| Method | Route | Current purpose | Target owner |
|---|---|---|---|
| GET | `/api/status` | Complete current health snapshot | Core read API |
| GET | `/api/healthz` | Lightweight process/health response | Core read API |
| GET | `/api/version` | Build, branch, commit, paths | Web/Core read API |
| GET | `/api/events` | Recent/filterable events | Events API |
| GET | `/api/events/export` | JSON event export | Events API |
| GET | `/api/events/export.csv` | CSV event export | Events API |
| GET | `/api/history` | Normal history | History API |
| GET | `/api/history/export.csv` | CSV history export | History API |
| GET | `/api/diagnostics/support-bundle.zip` | Download evidence | Diagnostics export |

## Transitional Read Contracts

These currently support dashboard implementation or administrative detail. They may be consolidated behind the final pages.

| Route | Current purpose | Proposed treatment |
|---|---|---|
| `/api/update-status` | Update state | Move to Setup |
| `/api/config-summary` | Safe configuration summary | Replace with versioned Setup summary |
| `/api/system-info` | Live system detail | Split Overview summary and Diagnostics detail |
| `/api/network-info` | Network detail | Move detailed data to Diagnostics/Black Box |
| `/api/settings-summary` | Dashboard settings | Replace with Setup configuration contract |
| `/api/retention` | Data usage and policy | Keep capability in Setup |
| `/api/update-log` | Update output | Move to Setup audit result |
| `/api/diagnostics` | Broad live diagnostics | Replace with bounded Diagnostics resources |
| `/api/blackbox` | Periodic blackbox rows | Replace with incident APIs |
| `/api/hardware-info` | Broad hardware details | Move to Diagnostics |
| `/api/services-info` | Service details | Keep concise state; move deep detail to Diagnostics |
| `/api/storage-info` | Storage details and limits | Keep concise state; move setup/detail appropriately |
| `/api/recording-storage-candidates` | Disk candidates | Setup-only helper result |
| `/api/install-status` | Repository/install status | Setup/Diagnostics |

## Current State-Changing Routes

No current mutation route is automatically accepted as a future public API. Every one must move behind authentication, allow-listed parameters, explicit confirmation, and audit.

### Setup Actions

- `/journal-enable`
- `/update-now` and compatibility `/api/update`
- `/settings-save` and compatibility `/api/settings`
- `/recording-storage-confirm`
- `/recording-storage-blank-confirm`
- `/recording-storage-apply`
- `/recording-storage-blank-apply`
- `/recording-storage-monitor-only`
- `/recording-storage-guard-apply`
- `/recovery-install-now`
- `/itco-watchdog-install-now`
- `/hardware-watchdog-prepare-now`
- `/watchdog-legacy-disable-now`
- `/hardware-watchdog-enable-now`
- `/hardware-watchdog-disable-now`
- `/watchdog-grace-config-set`
- `/watchdog-timeout-set`

### Diagnostics and Explicit Recovery Actions

- `/network-speed-test`
- `/watchdog-hardware-probe-now`
- `/service-restart-now`
- `/watchdog-test-arm`
- `/watchdog-test-run`
- `/watchdog-trip-arm`
- `/watchdog-trip-now`
- `/watchdog-grace-delay`
- `/watchdog-arm-now`

### Data Management Actions

- `/api/events/purge`
- `/storage-purge-old`
- `/storage-purge-all`
- compatibility `/api/purge?mode=...`

Confirmation pages such as `/update-confirm`, `/journal-enable-confirm`, `/watchdog-trip-confirm`, and storage/watchdog confirmation routes are presentation routes, not independent action contracts.

## `/api/status` Top-Level Shape

Current top-level fields include:

- `time`
- `state`
- `score`
- `critical_failed`
- `checks`
- `startup_summary`
- `recording_storage`
- `watchdog_process`
- `hardware_watchdog_feed`
- `recovery`
- `boot_change`
- `reboot_evidence`
- `kernel_faults`
- `blackbox`
- `heartbeat`

Each item in `checks` currently uses:

- `name`
- `state`
- `message`
- `value`
- `critical`

Compatibility policy:

- Preserve the current fields through a migration adapter.
- Add a schema version before changing semantics.
- Do not use `score` as a reboot or feeder decision.
- Introduce explicit gateway-health and protection-state fields rather than overloading `state`.
- Inventory external consumers before removing any field.

## Current Configuration Contract

Active location: `/etc/va-watchdog/config.json`  
Fallback location: `./config.json`  
Default merge behaviour: nested dictionary merge over built-in defaults.

| Section | Current responsibility | Target treatment |
|---|---|---|
| Root paths and intervals | Polling and state locations | Migrate to versioned Core/data configuration |
| `blackbox` | Periodic detailed snapshots | Replace with trigger/incident configuration |
| `web` | Bind host and port | Keep under Web ownership |
| `hardware_watchdog` | Feed and grace policy | Keep under Feeder ownership |
| `process_monitor` | Watchdog process resource alerts | Replace with normal service/core self-health policy |
| `service_resource_limits` | Shared service CPU/RAM thresholds | Improve to sustained per-service policy |
| `thresholds` | Hardware/storage thresholds | Split by collector owner |
| `services` | Four Videosoft services and restart flags | Keep service list; remove implicit generic restart authority |
| `storage` | Root/generic recordings paths | Consolidate with explicit storage identities |
| `recording_storage` | CCTV mount, label, permissions, limits | Split runtime state from Setup policy |
| `recovery` | Service restart and general reboot | Remove general health reboot; allow approved service policies only |
| `update` | Git update state and branch | Move to Setup |
| `network` | Internet/local targets and remote services | Keep essential target; move details to Diagnostics |
| `retention` | Total and per-file history limits | Keep and extend to incidents |

The current config has no explicit schema version. Adding one is required before migration.

## Current Persistent State

Default data directory: `/var/lib/va-watchdog`

| File | Current use | Target treatment |
|---|---|---|
| `status.json` | Current health snapshot | Keep, version, atomic |
| `events.jsonl` | Event transitions | Keep, deduplicate persistently, correlate incidents |
| `history.jsonl` | One-minute operational history | Keep concise |
| `heartbeat-state.json` | Feeder live decision | Keep as strict atomic contract |
| `heartbeat.jsonl` | Forensic heartbeat history | Keep bounded |
| `reboot-evidence.jsonl` | Per-boot evidence | Keep and attach to incidents |
| `kernel-fault-state.json` | Journal cursor/dedup state | Keep under Core |
| `hardware-watchdog-feed.json` | Feeder state | Keep and version |
| `hardware-watchdog.lock` | Device owner lock | Keep |
| `hardware-watchdog-control.json` | Feed control | Keep but version and expire requests |
| `watchdog-trip-test.json` | Trip-test state | Keep under Setup/Feeder contract |
| `blackbox.jsonl` | Periodic detailed snapshots | Replace with incident directories |
| `blackbox-state.json` | Boot/blackbox state | Split into boot state and incident state |
| `last-reboot-reason.json` | Recovery-request reason | Replace with reboot evidence/action audit |
| `update-state.json`, `update.log` | Web update state | Move to Setup audit area |

## Current Service Contract

| Unit | Current command | Current role | Target |
|---|---|---|---|
| `va-watchdog-feed.service` | `python3 -m va_watchdog.watchdog_feed` | Hardware feeder | Retain and minimise |
| `va-watchdog.service` | `python3 -m va_watchdog.watchdog` | Core, Web, health, history, recovery, blackbox | Split into Core and Web |

The current main service runs as root, uses `Type=notify`, has `WatchdogSec=30`, `MemoryMax=256M`, and `TasksMax=64`.

## Known External Dependencies

- systemd and `/proc`/`/sys` Linux interfaces.
- Python 3 standard library.
- Optional `smartctl`, `journalctl`, `wdctl`, `lsblk`, `findmnt`, `ip`, `ping`, and system utilities.
- Git and network access for updates.
- Teltonika/Videosoft forwarding browser behaviour.

Optional tools must remain optional in the target architecture.

