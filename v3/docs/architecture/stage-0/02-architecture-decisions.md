# Architecture Decisions and Approvals

Status: Awaiting formal approval

This record separates accepted direction from safety decisions that still require an explicit decision.

## Direction Established By The Design Brief

| ID | Decision | Status |
|---|---|---|
| AD-001 | The watchdog is an appliance resilience and forensic system, not a general monitoring platform. | Proposed for approval |
| AD-002 | Responsibilities are divided into Core, Black Box, Setup, and Diagnostics. | Proposed for approval |
| AD-003 | Feeder, Core, and Web are independent permanent services. | Proposed for approval |
| AD-004 | Black Box runs only for an active incident. | Proposed for approval |
| AD-005 | Core retains a bounded in-memory pre-trigger ring. | Proposed for approval |
| AD-006 | Heartbeat publication is independent from collector completion. | Proposed for approval |
| AD-007 | Expensive or subprocess-heavy collectors leave normal five-second supervision. | Proposed for approval |
| AD-008 | Web is unprivileged and read-mostly; privileged actions use a short-lived helper. | Proposed for approval |
| AD-009 | The refactor is incremental with compatibility adapters, not a big-bang rewrite. | Proposed for approval |
| AD-010 | Production target is 16-20 modules and approximately 4,500-6,000 Python lines. | Proposed for approval |

## Safety Decisions

| ID | Proposed policy | Reason | Status |
|---|---|---|---|
| SD-001 | Ordinary service, storage, network, CPU, or memory faults never stop hardware feeding. | Avoid reboot loops and loss of remote access. | Pending approval |
| SD-002 | Remove general health-triggered automatic reboot. | Hardware liveness, not health score, should control whole-system reset. | Pending approval |
| SD-003 | Automatic service restart is disabled by default and allow-listed per service. | Prevent uncontrolled restart loops. | Pending approval |
| SD-004 | Live stale detection uses monotonic time; UTC is evidence only. | Avoid RTC/NTP-induced resets. | Pending approval |
| SD-005 | Startup grace continues feeding and only delays stale enforcement. | Maintain protection while permitting startup. | Pending approval |
| SD-006 | Feeder stale threshold remains configurable and safely below hardware timeout. | Balance false resets and genuine recovery. | Pending measured validation |
| SD-007 | Feeder close behaviour is explicitly validated for magic-close and nowayout. | Device close may disarm or trigger hardware depending on driver policy. | Pending hardware validation |
| SD-008 | Only one active incident is permitted; additional triggers join it. | Bound process and evidence growth. | Pending approval |
| SD-009 | Open incidents cannot be purged automatically. | Preserve incomplete failure evidence. | Pending approval |
| SD-010 | Updates are blocked or deferred while an incident is active. | Prevent evidence loss and ambiguous reboot causes. | Pending approval |

## Initial Operational Defaults For Validation

These are trial values, not final field policy:

| Setting | Trial value |
|---|---:|
| Core heartbeat | 5 seconds |
| Hardware feed interval | 10 seconds |
| Hardware timeout | 30 seconds |
| Stale heartbeat threshold | 15 seconds |
| Startup grace | 300 seconds |
| Pre-trigger ring | 15 minutes |
| Incident detailed sample | 2-5 seconds |
| Post-event capture | 10 minutes |
| Normal persistent history | 60 seconds |

Final values require POC timing measurements and controlled watchdog tests.

## Approval

| Role | Name | Decision | Date | Notes |
|---|---|---|---|---|
| Product/operations |  | Pending |  |  |
| Engineering |  | Pending |  |  |
| Field validation |  | Pending |  |  |

