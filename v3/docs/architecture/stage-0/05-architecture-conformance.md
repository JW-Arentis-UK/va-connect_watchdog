# Architecture Conformance Review

Status: Review standard active for architecture work

## Review Inputs

- Target architecture specification.
- Module responsibility document.
- Current contract inventory.
- Architecture size report produced by `architecture_report.py`.
- Pull-request architecture checklist.

## Continuous Collector Admission

A change adding or expanding continuous collection must answer:

| Question | Required evidence |
|---|---|
| Why must it run continuously? | Operational/liveness reason |
| Why is incident-only insufficient? | Failure scenario and missing evidence |
| What CPU does it consume? | Target-gateway measurement |
| What memory does it consume? | RSS/allocation measurement |
| What does it write? | Bytes/day estimate and retention owner |
| What if it hangs? | Deadline, cancellation, stale result |
| Can it delay heartbeat? | Proven isolation path |
| Can it run independently? | Process/thread scheduling decision |
| How is it tested? | Unit, timeout, failure, and system tests |

An unanswered item blocks approval.

## Boundary Checks

- Feeder imports no Web, Setup, Black Box, network, storage, service, or journal collector.
- Core imports no Web renderer, privileged Setup implementation, or detailed Black Box collector.
- Web does not open the watchdog device or publish the heartbeat.
- Black Box does not alter configuration or publish Core liveness.
- Setup is not started continuously.
- Diagnostics results do not alter health unless an explicit separate policy consumes them.

## Budget Checks

Run:

```bash
python3 v3/scripts/architecture_report.py
```

During migration the report is informational because the legacy tree exceeds target budgets. At final enforcement run:

```bash
python3 v3/scripts/architecture_report.py --enforce
```

Targets:

- 16-20 production Python modules.
- 4,500-6,000 production Python lines.
- 1,200-1,800 Web implementation lines.
- Three permanent systemd services.
- No legacy renderer marker or production placeholder controls.

Exceeding a target requires an approved architecture exception with measured benefit.

## Review Outcome

Each architecture-affecting pull request is classified:

- `Conforms`: follows boundaries and budgets.
- `Temporary adapter`: required migration bridge with removal stage and tests.
- `Exception requested`: justified deviation awaiting approval.
- `Rejected`: adds unsupported continuous cost, coupling, or duplication.

