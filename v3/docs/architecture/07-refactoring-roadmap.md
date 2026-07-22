# Refactoring Roadmap

Status: Draft for approval

The refactor must be incremental. A gateway must remain installable, observable, and recoverable at every merged stage.

## Stage 0: Architecture Freeze

Deliverables:

- Approve this architecture pack.
- Record current API and configuration contracts.
- Capture current CPU, memory, disk-write, and timing baseline on POC-451VTC.
- Define rollback and branch strategy.
- Add architecture conformance checks to reviews.

Exit criteria: approval table complete and no unresolved safety decision affecting process boundaries.

## Stage 1: Characterisation and Safety Net

Deliverables:

- Expand tests around current feeder, heartbeat, events, storage, recovery, and API compatibility.
- Add fixture-based tests for existing gateway status/configuration.
- Add an end-to-end local systemd test harness or equivalent process harness.
- Record golden support-bundle contents.

No behaviour removal occurs in this stage.

## Stage 2: Fast Collector Foundation

Deliverables:

- Introduce direct `/proc` and `/sys` normal collectors.
- Record collector runtime and stale results.
- Separate heartbeat scheduling from collection.
- Keep existing status output through an adapter.
- Move SMART and other slow checks to a slow schedule.

Exit criteria: heartbeat remains within budget while every slow collector is deliberately timed out.

## Stage 3: Process Separation

Deliverables:

- Split Core and Web into separate systemd units.
- Run Web unprivileged.
- Define atomic status and action contracts.
- Verify Web failure has no Core/Feeder impact.
- Retain current UI behaviour through a temporary compatibility adapter.

## Stage 4: Single Interface and Setup Boundary

Deliverables:

- Select and validate one server-rendered UI.
- Remove duplicate renderer and routes.
- Move updates, disk preparation, journald, and watchdog setup into the helper.
- Remove placeholders.
- Consolidate pages into Overview, Events, Incidents, History, Setup, Diagnostics.

Exit criteria: forwarded access works on the target browser and all state-changing actions are audited.

## Stage 5: Incident Engine

Deliverables:

- Add trigger state machine, hysteresis, and cooldown.
- Add bounded in-memory pre-trigger ring.
- Add incident manifests and active marker.
- Add temporary Black Box worker.
- Add post-event capture and reboot attachment.

Initially run the trigger engine in observation mode without launching detailed capture, then enable capture after threshold review.

## Stage 6: Remove Legacy Complexity

Deliverables:

- Remove periodic blackbox.
- Remove compatibility renderer and duplicate APIs.
- Remove general health-triggered reboot.
- Remove overlapping storage/history models.
- Delete unused placeholders and dead modules.
- Migrate retained configuration to the versioned schema.

## Stage 7: Field Validation

Deliverables:

- Run prolonged normal-mode soak test.
- Run CPU, memory, I/O, network, service, kernel, and timing incident simulations.
- Run hardware watchdog trip and recovery tests.
- Validate evidence across abrupt power loss and watchdog reboot.
- Confirm resource budgets on at least two representative gateways.
- Validate remote update and rollback.

## Release Strategy

- Refactor on a dedicated branch.
- Use small reviewable commits by boundary, not one complete rewrite.
- Preserve the last validated build as rollback.
- Deploy first to the POC gateway.
- Require a soak period before wider field deployment.
- Never combine a major architecture migration with unrelated feature additions.

