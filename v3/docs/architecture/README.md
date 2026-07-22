# VA-Connect Watchdog Target Architecture

Status: Draft for architecture approval  
Date: 2026-07-22  
Scope: Target architecture for the simplification refactor  

No production refactoring should begin until this document set has been reviewed and approved.

## Purpose

The VA-Connect Watchdog exists to:

1. Keep the gateway alive.
2. Detect abnormal gateway behaviour.
3. Preserve evidence before, during, and after an incident.
4. Make post-incident diagnosis straightforward.

It is an appliance resilience and forensic system. It is not intended to become a general system monitoring platform.

## Documents

1. [Final architecture specification](01-final-architecture-specification.md)
2. [Module responsibilities](02-module-responsibilities.md)
3. [Runtime process diagram](03-runtime-process-diagram.md)
4. [Incident lifecycle](04-incident-lifecycle.md)
5. [Data flow](05-data-flow.md)
6. [Simplification plan](06-simplification-plan.md)
7. [Refactoring roadmap](07-refactoring-roadmap.md)
8. [Risk assessment](08-risk-assessment.md)
9. [Test strategy](09-test-strategy.md)
10. [Definition of Done](10-definition-of-done.md)

Stage execution records:

- [Stage 0: Architecture Freeze](stage-0/README.md)

## Architecture Rules

- Hardware feeding is independent from health collection, web serving, updates, and diagnostics.
- Heartbeat production never waits for a slow collector.
- Normal mode uses direct kernel interfaces and bounded local reads wherever practical.
- Expensive evidence collection runs only in Black Box mode or through a manual diagnostic action.
- Every subprocess has a strict timeout and runs outside the heartbeat-critical path.
- Ordinary health faults do not stop hardware watchdog feeding or automatically reboot the gateway.
- Every incident preserves a bounded lead-up buffer and a post-event recording period.
- Setup actions are explicit, confirmed, audited, and separate from continuous supervision.
- The web interface is read-mostly and cannot affect hardware feeding or core sampling.
- New continuous collectors require a written cost and failure analysis.

## Approval Record

Record the agreed outcome here before implementation starts.

| Item | Decision | Reviewer | Date |
|---|---|---|---|
| Architecture specification | Pending |  |  |
| Process boundaries | Pending |  |  |
| Incident lifecycle | Pending |  |  |
| Performance budgets | Pending |  |  |
| Simplification removals | Pending |  |  |
| Refactoring roadmap | Pending |  |  |
| Definition of Done | Pending |  |  |
