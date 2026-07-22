# Risk Assessment

Status: Draft for approval

## Risk Scale

- Likelihood: Low, Medium, High.
- Impact: Low, Medium, High, Critical.
- Priority reflects combined likelihood and impact.

## Architecture Risks

| Risk | Likelihood | Impact | Mitigation | Validation |
|---|---|---|---|---|
| Slow collector delays heartbeat | High | Critical | Independent heartbeat scheduler; cached results; deadlines; no slow work in Core path | Inject hung collectors and verify uninterrupted feed |
| Feeder disarms or resets unexpectedly on close | Medium | Critical | Explicit magic-close/nowayout policy; device tests; single owner | Normal stop, crash, restart, shutdown, nowayout matrix |
| Core/Feeder ownership race | Medium | Critical | File lock plus device ownership check; legacy daemon rejection | Start duplicate feeders concurrently |
| False stale-heartbeat reset | Medium | Critical | Monotonic time; startup grace; threshold budget; jitter tests | CPU/I/O stress and clock changes |
| Feeder continues forever while Core is logically dead | Medium | High | Heartbeat sequence/freshness; controlled stale policy | Freeze Core without killing process |
| Web or helper compromises root | Medium | Critical | Unprivileged Web; narrow action schema; no shell interpolation; authentication | Security review and malformed action tests |
| Incident capture increases system pressure | Medium | High | Resource caps; bounded frequency; lower priority; collector deadlines | Trigger under CPU/memory/I/O stress |
| Evidence disk fills | Medium | High | Reserved budget; atomic indexes; retention; open-incident protection | Fill evidence filesystem during incident |
| Incident misses lead-up evidence | Medium | High | Always-present in-memory ring and immediate flush | Trigger test and compare pre-trigger duration |
| Power loss loses final evidence | Medium | High | Bounded flush policy; atomic manifests; persistent journal | Power-cut simulation where safe |
| Previous-boot journal unavailable | Medium | Medium | Explicit evidence gap; heartbeat/reboot records; journald Setup action | Test volatile and persistent journal modes |
| Trigger thresholds flood incidents | High | Medium | Sustained duration, hysteresis, cooldown, baseline field trial | Long observation-mode trial |
| Trigger thresholds miss a freeze | Medium | High | Sampling-delay and kernel triggers; configurable profiles; incident review feedback | Simulated degradation scenarios |
| Configuration migration breaks deployed gateway | Medium | High | Versioned schema; backup; compatibility adapter; rollback | Upgrade fixtures from all known configs |
| UI removal breaks forwarding browser | Medium | High | Target-browser validation before deleting compatibility UI | Test forwarded URLs and refresh behaviour |
| API removal breaks external software | Low/Unknown | High | Contract inventory and deprecation adapter | API golden-response tests |
| Storage setup damages wrong disk | Low | Critical | Setup-only helper; root-parent exclusion; explicit device/serial confirmation | Destructive tests only on disposable virtual disks |
| Automatic service recovery causes loops | Medium | High | Disabled default; per-service policy; cooldown and attempt limits | Repeated failure simulation |
| Unsupported reset classification | Medium | Medium | Separate mechanism/fault/confidence; evidence list | Classification fixture tests |

## Refactor Risks

| Risk | Mitigation |
|---|---|
| Big-bang rewrite introduces hidden regressions | Incremental boundary extraction with compatibility adapters |
| Old and new paths coexist too long | Time-box adapters and assign removal exit criteria |
| Line-count target encourages dense code | Treat budgets as review signals, not acceptance criteria |
| Tests mirror implementation instead of behaviour | Contract, fault-injection, and system-level tests |
| New Black Box features grow continuously | Collector admission checklist and architecture change control |
| Root permissions remain embedded in Web | Process-separation stage cannot complete until Web is unprivileged |

## Safety Decisions Requiring Approval

| Decision | Proposed policy | Status |
|---|---|---|
| Feeder stale threshold | Configured below hardware timeout with validated scheduling margin | Pending |
| Feeder normal-stop behaviour | Explicit device policy based on magic-close and nowayout detection | Pending |
| Automatic health reboot | Remove | Pending |
| Automatic service restart | Disabled by default; allow-listed only | Pending |
| Incident maximum duration/size | Bounded and configurable | Pending |
| Evidence reserved capacity | Separate limit within watchdog data budget | Pending |
| Web authentication method | Required for all state changes | Pending |

