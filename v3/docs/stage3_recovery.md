# Stage 3 Recovery Behavior

This stage defines what the watchdog should do when the system is not healthy.

## Current policy

- hardware watchdog missing: warning only
- noncritical service failures: warning unless explicitly configured to restart
- critical service failures: can restart if recovery is enabled
- persistent critical failures: can request a reboot if `allow_reboot` is enabled

## Safety rules

- recovery is disabled by default
- rebooting is disabled by default
- noncritical service restarts are disabled by default
- the watchdog records why a reboot was considered before it asks for one

## What the dashboard should show

- whether recovery is disabled, watching, active, or requested a reboot
- what actions were attempted
- what critical checks are still failing

