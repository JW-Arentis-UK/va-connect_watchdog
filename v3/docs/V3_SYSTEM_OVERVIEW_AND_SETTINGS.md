# VA-Connect Watchdog V3 - System Overview and Settings

Last updated: 2026-07-20

This document explains what the current V3 watchdog system does, what each web page is for, and what the main configuration settings mean.

It is intended for:

- Sharing the current state with ChatGPT/Codex.
- Reviewing what is useful and what is too complicated.
- Deciding what should be kept, changed, simplified, or removed.

## Short Summary

VA-Connect Watchdog V3 is a local Ubuntu service and web dashboard for CCTV gateway PCs.

It runs as:

```bash
va-watchdog.service
```

The web dashboard is served on:

```text
http://<gateway-ip>:9110
```

The main status API is:

```text
/api/status
```

V3 currently monitors:

- CPU temperature.
- CPU load.
- RAM usage.
- Root disk usage.
- CCTV recording storage.
- Basic storage write test.
- Core VA-Connect services.
- Network placeholders and remote access services.
- Hardware watchdog device presence.
- Whether V3 is actively feeding the hardware watchdog.
- Events.
- History.
- Updates.
- Retention/purge of watchdog data.

## Important Current Behaviour

The hardware watchdog is now split into two different ideas:

- Device present: `/dev/watchdog0` exists.
- Protection active: V3 has opened `/dev/watchdog0` and is actively feeding it.

The Overview page should not show the hardware watchdog as fully healthy just because the device exists.

If `/dev/watchdog0` exists but V3 is not feeding it, the system should show:

```text
Hardware WDT: Not feeding
```

This should be a warning state.

## Install Location

On the gateway, the current install location is normally:

```text
/opt/va-connect-watchdog-v3
```

The V3 Python package is under:

```text
/opt/va-connect-watchdog-v3/v3/va_watchdog
```

The active config file is normally:

```text
/etc/va-watchdog/config.json
```

The watchdog data directory is normally:

```text
/var/lib/va-watchdog
```

## Page-By-Page Overview

## Overview Page

Purpose:

The Overview page is the main quick-read page for an engineer or operator.

It shows:

- Gateway summary.
- Current health state.
- Current score.
- Current version/commit.
- Config path.
- Data path.
- Health breakdown.
- CPU temperature.
- CPU load.
- RAM.
- Root disk.
- Recording storage.
- Hardware watchdog feed state.
- Services table.
- Recent events.
- System information.
- Health history preview.

Important detail:

The hardware watchdog tile should show whether V3 is feeding the watchdog, not just whether `/dev/watchdog0` exists.

Expected examples:

```text
Hardware WDT: Feeding
Hardware WDT: Not feeding
Hardware WDT: Not present
```

Possible simplification:

The Overview should probably only show the most important operational items:

- Overall state.
- Recording storage.
- Services.
- Hardware watchdog feed.
- Recent events.

Everything else could be moved to detail pages.

## Hardware Page

Purpose:

The Hardware page is for discovery and diagnostics.

It shows:

- CPU model.
- CPU cores.
- Architecture.
- RAM total.
- RAM available.
- Block devices.
- Watchdog devices.
- Intel TCO driver status.
- Kernel module status.
- `wdctl` identity.
- `wdctl` timeout.
- Legacy watchdog daemon information.
- Hardware probe logs.

Important detail:

The Hardware page should be mostly read-only.

Watchdog setup and test controls should live on the Watchdog page, not be spread across Hardware and Watchdog.

Possible simplification:

Hide most raw device output behind an "Advanced details" button.

## Watchdog Page

Purpose:

The Watchdog page is the main page for setting up and testing the hardware watchdog.

It now tries to explain the setup as layers:

- Intel TCO driver.
- Watchdog device.
- Driver identity.
- Legacy daemon cleanup.
- V3 config.
- V3 device owner.
- Live hardware feed.
- V3 systemd process watchdog.

Current sections:

- Top action panel.
- Driver/device/feed/legacy status boxes.
- Setup checklist.
- Existing watchdog cleanup.
- Current V3 configuration.
- Explanation of watchdog layers.
- Safe watchdog test.
- Deliberate trip test.
- Timeout extension.
- Advanced tools.

Key meanings:

- Hardware watchdog: a Linux hardware watchdog device such as `/dev/watchdog0`.
- V3 feed: this V3 service opening and feeding `/dev/watchdog0`.
- Systemd process watchdog: systemd restarting `va-watchdog` if the Python process hangs.
- Legacy watchdog: older Ubuntu watchdog service/package that may conflict with V3.

Important current behaviour:

If V3 feed is disabled, the page should show that setup is not complete.

If a legacy watchdog service is active/enabled, the page should clearly show that it may conflict and should be cleaned up.

Possible simplification:

Turn the page into a wizard with four simple steps:

1. Check hardware.
2. Clean old watchdogs.
3. Enable V3 feed.
4. Test watchdog.

Move the rest into "Advanced".

## Services Page

Purpose:

The Services page monitors important VA-Connect services.

Currently configured service examples:

- `esg.service`
- `bridge.service`
- `esg-config.service`

It shows:

- Service name.
- Active state.
- Substate.
- Enabled state.
- CPU.
- Memory.
- Restart count.
- Uptime.
- Critical flag.
- Manual restart/details actions.

Current behaviour:

Some services are marked critical. Critical service failure can affect whether watchdog feeding should continue.

Possible simplification:

Add a simple top summary:

```text
All critical services running
```

Then hide the detailed table unless expanded.

## Storage Page

Purpose:

The Storage page covers two separate areas:

- CCTV recording storage.
- Watchdog data storage and retention.

Recording storage shows:

- Status.
- Device.
- Mountpoint.
- Recordings folder.
- Owner/group.
- Label.
- Filesystem.
- Capacity.
- Free space.
- Used percentage.
- Used warning/critical thresholds.
- Writable state.
- SMART state.
- Drive temperature.
- Last successful check.
- Recording service mount guard.

Watchdog data storage shows:

- Data directory.
- Used watchdog data.
- Maximum watchdog data size.
- Events retention.
- History retention.
- Purge controls.

Recording storage behaviour:

- Can monitor an existing mounted storage location without changing it.
- Can configure an existing ext4 recording partition or whole-disk ext4 filesystem.
- Can prepare a new blank disk with explicit confirmation.
- Protects the system/root disk.
- Refuses to modify `/`, `/boot`, and `/boot/efi`.
- Refuses the parent disk containing the active root filesystem.
- Does not list small mount points under 10GB as CCTV candidates.
- Does not automatically unmount or reformat a drive.
- Does not stop Linux booting if recording storage is missing.

Expected fstab style:

```text
LABEL=CCTV_STORAGE /media/vsuser/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2
```

Note:

The earlier requested path used `/media/ususer/Storage`, but the gateway user is `vsuser`, so the active default is:

```text
/media/vsuser/Storage
```

Possible simplification:

Split this into two pages:

- Recording Storage.
- Watchdog Data.

## Network Page

Purpose:

The Network page is for basic connectivity information.

It shows:

- IP addresses.
- Default route.
- DNS.
- Internet host checks.
- Local target placeholders.
- Remote access service placeholders, such as TeamViewer.

Current state:

This page is useful but not complete.

Still to add later:

- Gateway web forwarder status.
- TeamViewer status.
- Local recorder/camera checks.
- Remote connectivity checks.
- Clearer "what IP should I use" output.

## Recovery Page

Purpose:

The Recovery page is intended for recovery and reinstall controls.

Current/expected areas:

- Watchdog reinstall/reconfigure.
- Recovery engine settings.
- Restart failed services.
- Restart non-critical services.
- Max restart attempts.
- Critical grace period.
- Allow/disallow automatic reboot.
- Last reboot reason.

Current state:

Recovery exists but should remain conservative.

Risk note:

Automatic reboot/recovery can be dangerous on live CCTV systems, so these settings should stay off unless deliberately enabled.

Possible simplification:

Keep this page as:

- Reinstall watchdog.
- Restart watchdog service.
- Show recovery settings.
- Advanced recovery policy hidden by default.

## Events Page

Purpose:

The Events page shows recent state changes and actions.

It supports:

- Compact event list.
- Expand/collapse event details.
- Severity counts.
- Export JSON.
- Export CSV.
- Local display times.

Typical events:

- Watchdog started.
- System ready.
- Storage missing.
- Storage mounted.
- Storage restored.
- SMART warning/failure.
- Service changed state.
- Watchdog setup started.
- Watchdog probe started.
- Watchdog feed opened.
- Updates started/completed.

Important detail:

Repeated unchanged faults should not be logged over and over.

Possible simplification:

Default to showing only:

- Time.
- Severity.
- Message.

Expand only when detail is needed.

## History Page

Purpose:

The History page stores health snapshots over time.

It shows:

- Health score trend.
- CPU/RAM trend.
- Temperature trend.
- Disk trend.
- Recent samples.
- Export options.

Current state:

Useful for proving stability over time, but still basic.

Possible simplification:

Show only:

- Last 24 hours.
- Last 7 days.
- Worst event.
- Current trend.

## Settings Page

Purpose:

The Settings page allows editing common watchdog configuration.

Current settings include:

- Poll interval.
- History sample interval.
- History retention.
- Max watchdog data size.
- Root disk warning/critical thresholds.
- Recording disk warning/critical thresholds.
- Network targets.
- Remote access services.
- Update remote.
- Update branch.
- Recovery settings.

Current state:

This page is powerful but may be too technical.

Possible simplification:

Split into:

- Basic Settings.
- Advanced Settings.

Basic settings should include only:

- Recording disk warning/critical.
- Watchdog timeout.
- Theme.
- Update branch.
- Data retention.

## Updates Page

Purpose:

The Updates page updates the watchdog from GitHub.

It shows:

- Update state.
- Message.
- Branch.
- Commit.
- Last update time.
- Log file.
- Log tail.
- Update button.

Current behaviour:

- The web update button works.
- The service may restart after update.
- The page returns after the update request.
- Current commit is shown on Overview so it is clear whether the gateway updated.

Possible simplification:

Make update state easier to read:

```text
Current version
Available version
Last update result
Update now
```

## Diagnostics Page

Purpose:

The Diagnostics page is for support and troubleshooting.

It shows:

- `va-watchdog` service status.
- Journal tail.
- Raw status JSON.
- Update status JSON.
- Advanced troubleshooting information.

Current state:

This is where raw/debug information should live.

Possible simplification:

Keep raw JSON only here, never on Overview.

## Main Configuration Settings

The example config is stored at:

```text
v3/config.example.json
```

The live config is normally:

```text
/etc/va-watchdog/config.json
```

## poll_interval_seconds

Example:

```json
"poll_interval_seconds": 5
```

Meaning:

How often the watchdog checks system health.

Lower value:

- Faster updates.
- More system activity.

Higher value:

- Less overhead.
- Slower detection.

## status_path

Example:

```json
"status_path": "/var/lib/va-watchdog/status.json"
```

Meaning:

Where the latest status snapshot is written.

## events_path

Example:

```json
"events_path": "/var/lib/va-watchdog/events.jsonl"
```

Meaning:

Where event history is stored.

Format:

One JSON event per line.

## history_path

Example:

```json
"history_path": "/var/lib/va-watchdog/history.jsonl"
```

Meaning:

Where regular history snapshots are stored.

## web

Example:

```json
"web": {
  "enabled": true,
  "host": "0.0.0.0",
  "port": 9110
}
```

Settings:

- `enabled`: whether the web dashboard is enabled.
- `host`: which interface to bind to.
- `port`: web port.

Current default:

```text
0.0.0.0:9110
```

## hardware_watchdog

Example:

```json
"hardware_watchdog": {
  "enabled": false,
  "device": "/dev/watchdog0",
  "feed_interval_seconds": 10
}
```

Settings:

- `enabled`: whether V3 should feed the hardware watchdog.
- `device`: hardware watchdog device path.
- `feed_interval_seconds`: how often V3 feeds the watchdog.
- `timeout_seconds`: hardware watchdog timeout, where configured.

Important:

`/dev/watchdog0` present does not mean V3 protection is active.

V3 protection is active only when:

- Hardware watchdog feed is enabled.
- V3 has opened the device.
- Recent feed has been recorded.

## thresholds

Example:

```json
"thresholds": {
  "cpu_temp_warning_c": 75,
  "cpu_temp_critical_c": 90,
  "ram_warning_percent": 85,
  "ram_critical_percent": 95,
  "root_disk_warning_percent": 80,
  "root_disk_critical_percent": 95,
  "recordings_disk_warning_percent": 85,
  "recordings_disk_critical_percent": 95
}
```

Meaning:

Controls when checks become warning or critical.

Important:

Recording storage now uses the configured used-percent recording thresholds by default.

Example:

If:

```text
recordings warning = 98
recordings critical = 99
```

Then:

```text
94.9% used should not be a capacity warning
```

Other warnings may still appear, for example SMART unavailable.

## services

Example:

```json
"services": [
  {"name": "esg.service", "critical": true, "restart": true},
  {"name": "bridge.service", "critical": true, "restart": true},
  {"name": "esg-config.service", "critical": false, "restart": true}
]
```

Settings:

- `name`: systemd service name.
- `critical`: whether failure should count as critical.
- `restart`: whether recovery is allowed to restart it when recovery is enabled.

Current default services:

- `esg.service`
- `bridge.service`
- `esg-config.service`

## storage

Example:

```json
"storage": {
  "root_path": "/",
  "recordings_path": "/home/vsuser/recordings",
  "write_test_path": "/tmp",
  "monitored_paths": []
}
```

Settings:

- `root_path`: path for root disk monitoring.
- `recordings_path`: older/simple recordings path check.
- `write_test_path`: path used for general write testing.
- `monitored_paths`: list of paths with individual thresholds.

Note:

This is separate from the newer `recording_storage` section.

## recording_storage

Example:

```json
"recording_storage": {
  "enabled": true,
  "expected_label": "CCTV_STORAGE",
  "mountpoint": "/media/vsuser/Storage",
  "filesystem": "ext4",
  "fstab_options": "defaults,nofail,x-systemd.device-timeout=5",
  "recording_subdir": "recordings",
  "owner": "vsuser",
  "group": "",
  "directory_mode": "775",
  "minimum_candidate_gb": 10,
  "used_warning_percent": null,
  "used_critical_percent": null,
  "free_warning_percent": null,
  "free_warning_enabled": false,
  "temperature_warning_c": 55,
  "recording_services": []
}
```

Settings:

- `enabled`: enables recording storage monitoring.
- `expected_label`: expected disk/filesystem label.
- `mountpoint`: expected mount point.
- `filesystem`: expected filesystem type.
- `fstab_options`: mount options used when V3 configures fstab.
- `recording_subdir`: folder under the mountpoint used for recordings.
- `owner`: Linux user that should own the recording folder.
- `group`: Linux group; blank means detect the owner's primary group.
- `directory_mode`: permissions for mountpoint and recording folder.
- `minimum_candidate_gb`: do not show smaller disks/mounts as CCTV candidates.
- `used_warning_percent`: override warning threshold for this storage.
- `used_critical_percent`: override critical threshold for this storage.
- `free_warning_percent`: legacy free-space threshold.
- `free_warning_enabled`: enables the legacy free-space threshold.
- `temperature_warning_c`: warning temperature for recording disk.
- `recording_services`: services that should require the recording mount before starting.

Recommended current mount:

```text
/media/vsuser/Storage
```

Recommended fstab entry:

```text
LABEL=CCTV_STORAGE /media/vsuser/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2
```

Important:

The watchdog must not be required for Linux to mount recording storage.

Linux should mount recording storage through `/etc/fstab`.

## network

Example:

```json
"network": {
  "internet_hosts": ["1.1.1.1", "8.8.8.8"],
  "local_targets": [],
  "remote_access_services": ["teamviewerd"]
}
```

Settings:

- `internet_hosts`: remote IPs to ping/check.
- `local_targets`: local devices/services to check later.
- `remote_access_services`: services such as TeamViewer.

## retention

Example:

```json
"retention": {
  "max_total_mb": 100,
  "events_retention_days": 30,
  "history_retention_days": 30,
  "history_sample_seconds": 60,
  "history_max_rows": 50000,
  "exports_retention_days": 14
}
```

Settings:

- `max_total_mb`: maximum storage area for watchdog data.
- `events_retention_days`: keep events for this many days.
- `history_retention_days`: keep history for this many days.
- `history_sample_seconds`: write history every this many seconds.
- `history_max_rows`: maximum history rows.
- `exports_retention_days`: how long exports should be kept.

Purpose:

Prevent watchdog logs/history from filling the CCTV storage or system disk.

## recovery

Example:

```json
"recovery": {
  "enabled": false,
  "restart_failed_services": false,
  "restart_noncritical_services": false,
  "max_restart_attempts": 3,
  "critical_grace_seconds": 60,
  "allow_reboot": false
}
```

Settings:

- `enabled`: enables recovery engine.
- `restart_failed_services`: allows restarting failed critical services.
- `restart_noncritical_services`: allows restarting failed non-critical services.
- `max_restart_attempts`: maximum restart attempts.
- `critical_grace_seconds`: how long a critical issue must persist before action.
- `allow_reboot`: allows recovery-triggered reboot.

Recommended:

Keep automatic reboot disabled until fully tested.

## update

Example:

```json
"update": {
  "enabled": true,
  "remote": "origin",
  "branch": "",
  "state_path": "/var/lib/va-watchdog/update-state.json",
  "log_path": "/var/lib/va-watchdog/update.log"
}
```

Settings:

- `enabled`: enables web update.
- `remote`: Git remote to pull from.
- `branch`: branch to update from; blank means current branch.
- `state_path`: update state file.
- `log_path`: update log file.

Current branch:

```text
codex/v3-gateway-ready
```

## Current Known Issues / Things To Simplify

This section is for discussion. It does not mean the system is broken.

Possible simplifications:

- Make light mode default.
- Improve dark mode contrast.
- Make Overview less busy.
- Rename Hardware WDT to Hardware Watchdog Feed.
- Split Storage into Recording Storage and Watchdog Data.
- Hide advanced/raw details by default.
- Turn Watchdog into a simpler wizard.
- Make Settings less technical.
- Make Updates show current/available/last result more clearly.
- Keep Diagnostics as the only page with raw JSON.

## Questions To Decide Next

Use this section to decide what should stay, change, or be removed.

## Keep

Write what should definitely stay:

-
-
-

## Change

Write what works but needs changing:

-
-
-

## Remove

Write what is not useful or too confusing:

-
-
-

## Add

Write new things that are needed:

-
-
-

## Make Simpler

Write pages or wording that should be simplified:

-
-
-

## Open Questions

Write anything we still need to decide:

-
-
-
