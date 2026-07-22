## Change Summary

Describe the operational problem and the smallest change that solves it.

## Responsibility Area

- [ ] Core
- [ ] Hardware Feeder
- [ ] Black Box
- [ ] Setup
- [ ] Diagnostics
- [ ] Web/read-only API
- [ ] Documentation/test only

## Architecture Conformance

- [ ] The change has one clear owner and does not duplicate an existing collector or view.
- [ ] Hardware feeding remains independent from health, Web, Setup, and Diagnostics.
- [ ] Heartbeat publication cannot wait for this change.
- [ ] Every subprocess has a strict timeout and bounded output.
- [ ] Failure of this component cannot stop Core or Feeder unless it is the approved liveness policy.
- [ ] Persistent writes are bounded by retention.
- [ ] Public API or configuration changes are versioned and documented.
- [ ] Privileged actions are allow-listed, confirmed, authenticated, and audited.
- [ ] Temporary compatibility code has a named removal stage.

## Continuous Collector Justification

Complete this section when normal continuous collection changes. Otherwise write `Not applicable`.

- Why must it run continuously?
- Why can it not run only during an incident?
- Measured target-gateway CPU:
- Measured memory:
- Estimated disk writes per day:
- Timeout and cancellation behaviour:
- Behaviour if it hangs:
- Proof it cannot delay heartbeat:

## Verification

- [ ] Unit/component tests added or updated.
- [ ] Failure and timeout behaviour tested.
- [ ] Architecture report reviewed.
- [ ] POC validation required and documented.
- [ ] Rollback impact documented.

## Risk and Rollback

State the most serious failure mode and the exact rollback unit.

