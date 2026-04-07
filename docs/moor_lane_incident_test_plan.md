# Moor Lane Incident Evidence Test Plan

This is the next working test plan for Moor Lane and similar VA-Connect encoder units.

## Priority Goal

We need better proof of what happens before a unit becomes non-functional and requires relay recovery.

At the moment we often only know that the unit stopped functioning and later came back after a hard reboot. The goal of this plan is to turn each unplanned outage into something provable, reviewable, and comparable across units.

## Work Order

### 1. Add Independent Truth Sources

We need one or two evidence sources outside the main app and watchdog path so we can tell whether the whole box stopped, only the network path failed, or only the app stack stalled.

Required outcomes:

- Add an external heartbeat:
  - unit reports or pings something off-box every 60 seconds
  - this should be reviewable in incident packs and summaries
- Add a very small local OS heartbeat:
  - lightweight root timer or service
  - updates a timestamp file every 30 to 60 seconds
  - independent from the main watchdog and web UI
- After recovery, compare heartbeat timestamps with app and watchdog evidence to distinguish:
  - full OS freeze
  - network-path outage
  - app or service stall
  - watchdog or web UI stall

### 2. Improve Pre-Failure Evidence Capture

Record and surface these timestamps in incident data:

- `last_app_ok_at`
- `last_lan_ok_at`
- `last_wan_ok_at`
- `last_ui_response_at` if practical

Required outcomes:

- Add a clear "last known healthy" line to each incident summary.
- Include the latest successful app, LAN, WAN, and UI timestamps in each incident pack.
- Automatically capture the last 5 to 10 minutes of relevant journal slices into each incident pack.
- Add lightweight periodic `vsapp` runtime sampling:
  - process present
  - CPU
  - memory
  - thread count
  - open file count if practical
- Include the last `vsapp` runtime sample before an outage in the incident pack.

### 3. Add Runtime NIC Link-Flap Detection

Track `enp1s0` link down and up events during normal runtime.

Required outcomes:

- Keep boot-recovery link noise separate from runtime instability.
- Only flag link flaps as suspicious after the unit has been up long enough to be considered settled, for example 10 or more minutes after boot.
- Show link-flap counts in incident data and the UI.
- Include runtime link-flap evidence in incident packs.
- Add an explicit boot-settling period to incident interpretation so expected post-boot wobble is not treated as the root cause.

### 4. Improve Crash Persistence And Post-Mortem Clues

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
- Consider BIOS, platform firmware, and SSD firmware review if software-side evidence continues to end abruptly without a clear kernel or software cause.

### 5. Check And Surface Storage Risk Properly

Root disk pressure is already a live risk and should be treated as such.

Current concern:

- root disk is effectively full at around 99.89 percent

Required outcomes:

- Improve UI and incident reporting for root disk pressure.
- Review and surface a fuller SMART interpretation for `/dev/sdb`, not just a short summary.
- If practical, include a clearer disk-health verdict in incidents and in the operator view.
- Add explicit recording and storage error counters for:
  - invalid record headers
  - file repair attempts
  - missing recording file on startup
  - recording index repair attempts
- Review GPT warnings on `/dev/sda` and decide whether they are harmless legacy layout noise or something that should be corrected.

### 6. Fix Watchdog/Web Instability First

The watchdog web UI must not add noise during incident work.

Known failure that must stay fixed:

- `va-connect-watchdog-web.service` crash loop caused by:
  - `SyntaxError: f-string expression part cannot include a backslash`
  - file: `/opt/va-connect-watchdog/va_connect_watchdog_web.py`

Required outcomes:

- Keep the UI reliable during incident review.
- Treat web-side rendering or export regressions as high priority because they block evidence review.

### 7. Validate The Network Path As An A/B Test

If operations allow, test cable, port, or RUT path changes for the encoder.

Purpose:

- determine whether runtime `enp1s0` instability disappears on a cleaner physical path
- if incidents continue with a clean physical path, increase suspicion on platform or system freeze rather than simple network path issues

### 8. Controlled Platform Comparison Later

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

- one or two independent truth sources outside the main app path
- a clear incident row in the UI
- a last-known-healthy summary
- packable evidence for the minutes before failure
- heartbeat evidence that helps separate full unit freeze, network outage, and app stall
- lightweight `vsapp` runtime state before the outage
- runtime link-flap context separated from boot recovery noise
- clearer storage, recording, and crash-persistence evidence
- wording that is accurate enough for reporting across multiple units
