# Moor Lane Incident Evidence Test Plan

This is the next working test plan for Moor Lane and similar VA-Connect encoder units.

## Priority Goal

We need better proof of what happens before a unit becomes non-functional and requires relay recovery.

At the moment we often only know that the unit stopped functioning and later came back after a hard reboot. The goal of this plan is to turn each unplanned outage into something provable, reviewable, and comparable across units.

## Work Order

### 1. Improve Pre-Failure Evidence Capture

Record and surface these timestamps in incident data:

- `last_app_ok_at`
- `last_lan_ok_at`
- `last_wan_ok_at`
- `last_ui_response_at` if practical

Required outcomes:

- Add a clear "last known healthy" line to each incident summary.
- Include the latest successful app, LAN, WAN, and UI timestamps in each incident pack.
- Automatically capture the last 5 to 10 minutes of relevant journal slices into each incident pack.

### 2. Add Runtime NIC Link-Flap Detection

Track `enp1s0` link down and up events during normal runtime.

Required outcomes:

- Keep boot-recovery link noise separate from runtime instability.
- Only flag link flaps as suspicious after the unit has been up long enough to be considered settled, for example 10 or more minutes after boot.
- Show link-flap counts in incident data and the UI.
- Include runtime link-flap evidence in incident packs.

### 3. Improve Crash Persistence And Post-Mortem Clues

We need better evidence to distinguish kernel panic, hard hang, power loss, and manual recovery.

Required outcomes:

- Ensure persistent journald is enabled.
- Capture any usable `pstore` content automatically.
- If practical, assess whether `kdump` or similar crash persistence tooling is suitable.
- Make incident summaries clearly separate:
  - kernel panic evidence
  - hard hang with no clean shutdown
  - power loss or repower suspicion
  - manual or relay recovery suspicion

### 4. Check And Surface Storage Risk Properly

Root disk pressure is already a live risk and should be treated as such.

Current concern:

- root disk is effectively full at around 99.89 percent

Required outcomes:

- Improve UI and incident reporting for root disk pressure.
- Review and surface a fuller SMART interpretation for `/dev/sdb`, not just a short summary.
- If practical, include a clearer disk-health verdict in incidents and in the operator view.

### 5. Fix Watchdog/Web Instability First

The watchdog web UI must not add noise during incident work.

Known failure that must stay fixed:

- `va-connect-watchdog-web.service` crash loop caused by:
  - `SyntaxError: f-string expression part cannot include a backslash`
  - file: `/opt/va-connect-watchdog/va_connect_watchdog_web.py`

Required outcomes:

- Keep the UI reliable during incident review.
- Treat web-side rendering or export regressions as high priority because they block evidence review.

### 6. Validate The Network Path As An A/B Test

If operations allow, test cable, port, or RUT path changes for the encoder.

Purpose:

- determine whether runtime `enp1s0` instability disappears on a cleaner physical path
- if incidents continue with a clean physical path, increase suspicion on platform or system freeze rather than simple network path issues

### 7. Controlled Platform Comparison Later

Only do this after evidence capture improvements are in place.

Purpose:

- compare behaviour against a more conservative kernel or platform baseline
- ensure any result can be compared cleanly with stronger evidence capture already in place

## Interpretation Guidance

Short post-reboot network instability may just be recovery noise and should not automatically be treated as the root cause.

The bigger issue is the unit becoming non-functional and only recovering via GSM relay reboot.

Reporting should reflect that accurately unless stronger proof exists.

## Preferred Incident Wording

Use this wording when evidence is limited:

> Unit became non-functional and required hard reboot via GSM relay to recover.

Avoid over-claiming kernel lockup, panic, or power fault unless the evidence supports it.

## Expected Output From This Plan

Each unplanned outage should end up with:

- a clear incident row in the UI
- a last-known-healthy summary
- packable evidence for the minutes before failure
- runtime link-flap context separated from boot recovery noise
- clearer storage and crash-persistence evidence
- wording that is accurate enough for reporting across multiple units
