# Definition of Done

Status: Draft for approval

The simplification refactor is complete only when every required item below is satisfied.

## Architecture

- [ ] Architecture pack is approved and approval record completed.
- [ ] Core, Feeder, Web, Black Box, Setup, and Diagnostics boundaries match the specification.
- [ ] Dependency rules are documented and checked in review.
- [ ] No production feature exists without a named owner.
- [ ] No duplicate dashboard or collector implementation remains.

## Runtime Isolation

- [ ] Feeder is independently supervised and is the single watchdog-device owner.
- [ ] Core heartbeat publication cannot be delayed by collectors.
- [ ] Web runs separately and unprivileged.
- [ ] Black Box has no permanent process in normal mode.
- [ ] Setup and Diagnostics helpers are short-lived and allow-listed.
- [ ] Failure of Web, Black Box, Setup, or an optional collector cannot stop feeding.

## Core Behaviour

- [ ] Normal collectors use `/proc`, `/sys`, or bounded local reads where practical.
- [ ] Every collector reports runtime, success/failure, and data age.
- [ ] Every subprocess has a timeout and cancellation result.
- [ ] Ordinary health warnings and critical checks do not stop feeding.
- [ ] General health-triggered automatic reboot is removed.
- [ ] Service recovery is disabled by default and policy-controlled.
- [ ] Current status clearly distinguishes gateway health from hardware protection.

## Black Box

- [ ] Trigger engine supports duration, hysteresis, recovery, and cooldown.
- [ ] Pre-trigger ring preserves the agreed lead-up window.
- [ ] One active incident accepts multiple contributing triggers.
- [ ] Detailed worker starts and exits independently.
- [ ] Post-event evidence is captured for the agreed window.
- [ ] Reboot evidence attaches to an interrupted incident.
- [ ] Incident finalisation produces a manifest, timeline, evidence inventory, and confidence.
- [ ] Incident data is bounded by size, age, and count without purging open incidents.

## Setup and Diagnostics

- [ ] Watchdog installation and legacy cleanup are Setup actions.
- [ ] Journald persistence is an explicit Setup action.
- [ ] Recording storage preparation is outside normal supervision.
- [ ] Updates are outside Core and have a validated rollback path.
- [ ] Manual probes and speed tests cannot affect health state.
- [ ] All state-changing web actions require authentication, confirmation, and audit.
- [ ] No user-provided value is interpolated into a shell command.

## Interface and Compatibility

- [ ] One dashboard renderer remains.
- [ ] Target forwarded browser is validated on 1024x768 and mobile access.
- [ ] Overview is operator-focused and does not expose raw JSON.
- [ ] Incidents page presents trigger, timeline, evidence, reboot outcome, and download.
- [ ] Diagnostics contains raw engineering information.
- [ ] Required API contracts remain compatible or have an approved migration.
- [ ] Theme and disclosure state behave consistently across refreshes where specified.

## Reliability

- [ ] Normal stop, Core restart, Feeder restart, duplicate Feeder, shutdown, reboot, magic-close, and nowayout cases pass.
- [ ] UTC clock changes do not affect liveness decisions.
- [ ] Partial writes and corrupt optional files do not stop Core or Feeder.
- [ ] Disk-full behaviour preserves heartbeat and minimal status.
- [ ] Missing `journalctl`, `smartctl`, network, or persistent journal does not stop supervision.
- [ ] A controlled hardware trip test has passed on representative hardware.
- [ ] Remote access remains possible throughout startup grace.

## Performance

- [ ] Feeder average machine CPU is below 0.1% target or approved exception.
- [ ] Core average machine CPU is below 0.5% target or approved exception.
- [ ] Combined normal RSS is below 75 MB target or approved exception.
- [ ] Fast sample p95 is below 100 ms and maximum below one second.
- [ ] Heartbeat publication jitter p99 is below one second.
- [ ] Normal persistent writes are below 10 MB/day target.
- [ ] Incident worker remains within approved CPU, memory, and disk budgets.
- [ ] Measurements are recorded from target gateway hardware.

## Testing

- [ ] Unit, component, contract, system, fault-injection, and hardware tests pass.
- [ ] Safety policy modules meet agreed branch coverage.
- [ ] 72-hour development soak passes.
- [ ] 14-day POC observation/soak passes before field rollout.
- [ ] Every simulated incident preserves the agreed pre- and post-event evidence.
- [ ] Support bundle contains required evidence and a missing-evidence inventory.
- [ ] Clean install, upgrade, failed update, and rollback tests pass.

## Size and Maintainability

- [ ] Production module count is within the 16-20 target or exceptions are approved.
- [ ] Production Python is within the 4,500-6,000 line target or exceptions are approved.
- [ ] Web implementation is within the 1,200-1,800 line target or exception is approved.
- [ ] No placeholder feature is shown in production UI.
- [ ] Dead code, temporary adapters, and legacy renderer are removed.
- [ ] Public modules and operational procedures are documented.
- [ ] Architecture documentation matches the implemented system.

## Release Approval

- [ ] POC evidence reviewed by engineering.
- [ ] Rollback build and commands are documented.
- [ ] Field deployment order and monitoring period are agreed.
- [ ] No unrelated feature is bundled into the architecture release.
- [ ] Final sign-off is recorded below.

| Role | Name | Decision | Date |
|---|---|---|---|
| Product/operations |  | Pending |  |
| Engineering |  | Pending |  |
| Field validation |  | Pending |  |

