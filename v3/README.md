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

Update an existing V3 installation through the dashboard or:

```bash
sudo bash /opt/va-connect-watchdog-v3/v3/scripts/update.sh origin codex/gui-refresh
```

Use the complete updater rather than copying Python files: service accounts,
permissions and the restricted helper must match the code. Updates restart
watchdog services, not the gateway. The updater runs outside those services and
records its result.

V1/V2 deployments need an attended migration. Do not run an old uninstall helper
against historical evidence. See [legacy migration](../docs/legacy-runtime.md).

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
