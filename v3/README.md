# VA-Connect Watchdog V3

Health monitoring and crash evidence for Ubuntu Videosoft gateways and Raspberry
Pi OS. Build `20261027.5` retires historical V1/V2 deployment sources and duplicate
status rendering. Existing operational features remain.

## Operator Pages

- Status: current services, connectivity, storage, hardware protection and latest
  restart evidence. Saved results from another boot cannot appear healthy.
- Maintenance: identity, storage, protection, analytics, remote access, updates
  and support. Device-specific tools appear where applicable.
- Analytics: ANPR collection/search/export, people/crossing counts, charts and PDF
  reports. Hikvision diagnostics, push setup and event capture remain.
- Network and remote access: optional router monitoring, speed tests, saved web
  links and TeamViewer monitoring/password controls remain.
- Evidence: before-crash recorder, boot incidents, journals, system logs, compact
  history and support downloads. Neousys reports are not offered on Pi.

Status has one renderer. Historical `/advanced`, `/legacy` and `/overview` links
redirect to it. Detailed setup and support still use the shared page renderer.

## Install And Update

For a clean Ubuntu Videosoft gateway:

```bash
wget -O install_v3_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/install_v3_gateway.sh
bash ./install_v3_gateway.sh
```

The installer asks for site identity, offers persistent journald, installs
dependencies/services and preserves existing configuration. Confirm the gateway
identity before changing a remote unit, particularly a cloned image.
The dashboard is at `http://<gateway-ip>:9110/`.

For new, existing or partially installed Ubuntu 22.04 amd64 gateways, the full
setup entry point also handles repository and Python dependency setup:

```bash
wget -O setup_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/setup_gateway.sh && bash ./setup_gateway.sh
```

It preserves existing V3 identity and journal settings. New installs prompt for
identity and enable persistent crash logging. Active/enabled V1/V2 services
require attended migration; other platforms need their platform-specific setup.

For an existing V3 installation with working package repositories, update
through the dashboard or:

```bash
wget -O update_v3_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/update_v3_gateway.sh &&
sudo bash ./update_v3_gateway.sh origin codex/gui-refresh
```

On builds older than `20261124.2`, use this SSH command once instead of the
installed updater or dashboard button. It downloads the current updater before
changing the checkout. Subsequent updates hand over to the downloaded setup
script before installing dependencies, accounts, helpers and service units.

Use the complete updater rather than copying Python files: service accounts,
permissions and the restricted helper must match the code. Updates restart
watchdog services, not the gateway. The updater runs outside those services and
records its result.

V1/V2 deployments need an attended migration. Do not run an old uninstall helper
against historical evidence. See [legacy migration](../docs/legacy-runtime.md).

## Build 20261124.1

The web service now permits its allowlisted authentication helper to verify the
configured Ubuntu operator password. Normal installation and updates install the
corrected service unit; the web process still runs as `va-watchdog-web`.
Recording history shows the span between the oldest and latest file timestamps
in days. This includes any gaps and does not imply continuous footage.

## Recording Storage

Gateway setup offers two choices:

1. **Prepare a new recording drive**: guarded destructive preparation, explicit
   disk selection and confirmation, with system disks excluded.
2. **Monitor an existing recording location**: monitor the path already selected
   in Videosoft, including a folder on the OS drive. No formatting, relabelling,
   remounting, ownership or filesystem-table changes.

For new-drive preparation, confirm the resulting path in Videosoft. Normal looping
recording and its free-space reserve are not an instruction to erase files.
Linux owns mounting; monitoring is not required to keep a mount available.

Pi has its own storage/history page rather than Neousys disk commissioning.
See [Pi installation and storage](docs/raspberry-pi.md).

## Protection And Recovery

Separate core, web and hardware-feeder services isolate responsibilities. The web
process runs unprivileged and uses an authenticated, allowlisted helper for
privileged actions. Web liveness checks can restart the web service without
restarting the gateway. There is no fallback HTTP server in the core loop.

Collectors are isolated from supervisor liveness. A stalled collector has a
bounded worker and becomes unknown rather than freezing all checks. Software
recovery uses bounded service restarts with cooldowns and budgets. Network,
storage, service, CPU and RAM warnings cannot request an automatic V3 reboot.

On supported Neousys POC-451VTC/551VTC gateways the independent WDT_DIO feeder
handles hardware protection. Installation does not silently arm a clean system.
Activation and deliberate reset tests require an attended maintenance window.
Startup/post-test grace preserves access; current-boot feed evidence is required
before protection is reported proven. Ordinary health warnings do not stop
feeding. Stale supervisor heartbeat and deliberate trip tests are separate from
software recovery.

Pi uses its native watchdog through systemd PID 1. Its protection page reports
that configuration, without Neousys driver/trip controls. Enabling it is an
explicit attended step using `v3/scripts/enable_pi_native_watchdog.sh`. Do not
open the device with a second feeder. System-hang protection is not proof an
application freeze will cause a reset.

## Security

Operator sign-in protects actions. Remote downloads of sensitive support evidence
also need authorization. Loopback diagnostics do not bypass action authorization.
Use a trusted VPN or HTTPS reverse proxy for remote access: plain HTTP does not
encrypt credentials. Preserve the account/helper permissions installed by the
updater.

## Crash Evidence

Before-crash samples are bounded and persisted on the OS disk independently of
recording storage. A new boot freezes previous-boot evidence before live retention
can overwrite it. Incident archives contain matching heartbeat, black-box and
history samples, saved status/feed state, previous kernel journal, `last -x`,
restart evidence and available persistent crash records.

Defaults retain ten incidents and 25 MB, always keeping the newest. Evidence
cannot be recovered if it was never written or storage failed. A clean shutdown
does not identify who initiated it; missing proof stays unknown.

Support bundles include bounded syslog tails/rotations and configured system
evidence. Persistent journald is explicitly enabled through a separate drop-in,
capped at 512 MB with 1 GB reserved and 30-day retention. Review bundles as
sensitive operational information before sharing.

## Verification

```bash
PYTHONPATH=v3 python3 -m unittest discover -s v3/tests -q
systemctl is-active va-watchdog va-watchdog-feed va-watchdog-web
curl -fsS http://127.0.0.1:9110/api/healthz
curl -fsS http://127.0.0.1:9110/api/readyz
```

Also confirm recording timestamps advance, hardware evidence is fresh where
configured, and downloaded evidence contains system logs. Do not use an unattended
trip test as a routine update check.

- [Hardening review](docs/watchdog-review-2026-10-27.md)
- [Cleanup reassessment](docs/watchdog-cleanup-2026-10-27.md)
- [Ellingers recovery test plan](docs/ellingers-watchdog-recovery-test-plan.md)

Older stage plans and incident notes are historical references, not current
deployment instructions.

## LAN devices / Cameras (build 20261124.4)

Open Maintenance > LAN devices / Cameras (`/lan-devices`). Select a connected
IPv4 network and click Scan LAN. The read-only scan lists IP address,
manufacturer, device-reported model and serial number where available. It uses
TCP/ICMP responses, the neighbour cache, ONVIF discovery, Hikvision ISAPI device
information and ONVIF GetDeviceInformation. Unknown devices and rejected camera
credentials are explicitly labelled; models are never inferred from an IP.

Scans run in the short-lived authenticated operator helper, not the watchdog
core. Each selected network is limited to the gateway's /24 or smaller subnet,
16 workers and a 90-second scheduling budget. Separate VLANs, NVR-private
networks, silent hosts and nonstandard camera HTTP ports may not be identified.
HTTPS-only cameras require a trusted certificate. Camera requests do not follow
redirects or use ambient proxy settings.

The camera username initially displays `admin`. Save the site camera password
once in Camera credentials, or use a private provisioning file. The public
repository contains no site password. Blank passwords retain the saved value;
the checkbox removes it. Changing username requires entering a password again.
Camera credentials are independent of the Ubuntu operator login. The secret is
stored root-only in `/etc/va-watchdog-private/lan-camera.json` and is not returned
to the browser. Existing installs and updates preserve it. Only a username and
password-present indicator are published to the authenticated page.

Validation: fixture-based Hikvision/ONVIF, subnet limits, rejected targets,
credential retention/redaction, privileged action dispatch and browser scan/save
checks. Live camera discovery must still be verified at a site.

## Automatic recording-location detection (build 20261124.5)

Recording history and disk health now share automatic detection, enabled by
default for existing V3 configurations as well as new installations. Mounted
physical filesystems are checked for Unix-timestamped `.data`, `.mp4` or `.mkv`
files, directly in a recording folder or one timestamp-bucket level below it.
Empty folders alone do not count as evidence. This supports labelled mounts such
as `/media/vsuser/Storage/recordings` and UUID mounts such as
`/media/1cac11a8-caf7-4184-a750-c2046e26a1ba/recordings`.

Discovery prefers an evidenced dedicated disk over system-disk footage. If more
than one dedicated location is found, an evidenced configured location can break
the tie; otherwise monitoring reports ambiguity rather than guessing. Detection
is bounded and cached for 30 seconds. The root collector remembers the disk UUID
(or device when no UUID is available) in
`/var/lib/va-watchdog/recording-location.json`. A missing remembered disk is
reported as missing without silently monitoring the root disk instead. A changed
mountpoint for the same UUID is followed automatically.

Detection changes only the effective monitoring location. It does not edit
Videosoft configuration, move files, mount/format/relabel disks, or rewrite fstab.
Existing capacity/free-space thresholds and administrative disk-action targets
are retained. The normal small writability probe remains part of disk health,
but is not run for missing or ambiguous automatically detected disks.

Set `recording_storage.auto_detect` to `false` to use manual configuration. An
intentional disk replacement can be commissioned by updating the configured
recording path (which resets remembered selection), or by removing only the
`recording-location.json` discovery-state file before the next check. No footage
should be removed. Storage details report the detected recording folder.

This feature does not install V3 on a machine that lacks it and does not change
the Ubuntu 22.04 requirement of the unified setup entry point. A Melton-style UUID
mount is supported; Melton's Ubuntu 20.04 installation needs a separate supported
runtime/migration assessment.
