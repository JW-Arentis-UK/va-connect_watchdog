# VA-Connect Watchdog V3 Plan

This is the working plan for the v3 line.

## Goals

- Keep the watchdog stable on the gateway.
- Keep the install path GitHub-friendly.
- Make health and missing-hardware states visible.
- Add useful checks before adding more recovery behavior.

## Stage 1. Persistence and boot validation

Goal: prove the service survives a reboot and comes back cleanly.

What we want to confirm:

- `va-watchdog` is enabled
- the service starts automatically after boot
- the web UI comes back on port `9110`
- the status page still shows the expected health state
- logs are written across the reboot

## Stage 2. Make startup state clearer

Goal: show a short summary of what is enabled, missing, and healthy.

What to add:

- startup summary events
- clearer hardware watchdog wording
- clearer service and storage messaging

## Stage 3. Recovery behavior

Goal: decide which failures only warn and which failures should recover.

What to decide:

- restart versus warning behavior
- any reboot conditions
- service-specific recovery rules

## Stage 4. Dashboard refinement

Goal: make the main status page easier to scan at a glance.

What to improve:

- explicit panels for hardware, services, storage, and recovery
- clearer source labels
- better failure summaries

## Stage 5. Install hardening

Goal: make the gateway install and update flow harder to break.

What to add:

- clean uninstall steps
- one-line update path from GitHub
- clear versioned release references

## Stage 6. Release hygiene

Goal: make v3 easy to share and update safely.

What to add:

- a clean release branch or tag
- a short operator guide
- a stable install URL

