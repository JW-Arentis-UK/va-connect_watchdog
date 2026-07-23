# VA-Connect Watchdog

Health Engine prototype for Ubuntu gateways.

Current scope:
- System health checks
- Service checks
- Storage checks
- Temperature/RAM/CPU
- Event log
- JSON status output
- Local HTTP status page/API
- Optional hardware watchdog feeding

Working plan:
- [`docs/plan.md`](docs/plan.md)
- [`docs/stage1_reboot_checklist.md`](docs/stage1_reboot_checklist.md)
- [`docs/stage3_recovery.md`](docs/stage3_recovery.md)
- [`docs/stage4_dashboard.md`](docs/stage4_dashboard.md)
- [`scripts/stage1_reboot_check.sh`](scripts/stage1_reboot_check.sh)

The web page includes a watchdog update action that pulls the configured/current branch in a separate transient systemd unit. This allows the updater to restart `va-watchdog` without being terminated with the service, then records the final result in the Updates page and update log.

Default monitored services:
- esg.service
- bridge.service
- sysops.service
- esg-config.service

## Full installation on a gateway

For a clean Ubuntu 22.04 Videosoft gateway, download and run the full installer:

```bash
cd ~/Desktop
wget -O install_v3_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/install_v3_gateway.sh
bash ./install_v3_gateway.sh
```

The installer:

- prompts for the site name and optional asset ID
- explicitly offers persistent journald for post-crash evidence
- installs Python, Git, SMART, sensor, network, and performance tools
- clones or safely updates `/opt/va-connect-watchdog-v3`
- backs up an existing configuration and preserves the previous Git commit
- installs and enables both watchdog systemd services
- verifies the local health and identity APIs

Hardware watchdog feeding is deliberately not enabled on a clean install. Configure
and test it from the Watchdog page after confirming `/dev/watchdog0` is correct.

For an unattended install:

```bash
bash ./install_v3_gateway.sh \
  --site-name "Ellingers" \
  --asset-id "GW-017" \
  --persistent-journal \
  --non-interactive
```

Manual install on target:

```bash
cd /opt
sudo git clone <YOUR_REPO_URL> va-connect-watchdog-v3
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/install.sh
```

Or bootstrap from a downloaded script on the gateway:

```bash
cd ~/Desktop
wget -O bootstrap_v3_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/1758091/bootstrap_v3_gateway.sh
bash ./bootstrap_v3_gateway.sh
```

Check status:
```bash
systemctl status va-watchdog
curl http://127.0.0.1:9110/api/status
```

Web page:
```text
http://<gateway-ip>:9110/
```

After installing or restoring a cloned gateway image, open **Settings > Gateway identity** and set:

- **Site name**: the operator-facing location, for example `Ellingers`.
- **Asset ID**: an optional physical gateway identifier.

The page also shows the hostname, hardware fingerprint, OS disk serial, and recording
disk serial. Confirm these before changing a remote unit because cloned gateways may
share the same hostname. The site identity is included in page headers, APIs, CSV
exports, support bundles, and new Stage 0 baseline archive names.

Recording storage is mounted by Linux through `/etc/fstab`; the watchdog monitors and can safely configure the labelled entry, but it is not required for the mount to exist. Intended entry:

```fstab
LABEL=CCTV_STORAGE /media/vsuser/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2
```

The Storage page includes a Recording Storage panel and guarded setup flows. Existing-partition setup refuses protected system mounts and the parent disk containing `/`, never formats a disk, and only relabels a selected ext4 partition after explicit confirmation. Blank-disk setup is separate and requires explicit confirmation before creating a single ext4 partition labelled `CCTV_STORAGE`. Setup also prepares `/media/vsuser/Storage/recordings` for the `vsuser` account so the recording application can create files there.

For an already-working recorder mount that must not be changed, use Storage > Configure recording storage > Monitor only. This updates watchdog monitoring to the current mountpoint/label without relabelling, remounting, editing `/etc/fstab`, or changing permissions. Candidate lists hide devices smaller than 10 GB.

For a gateway where the operating system and recordings share one physical drive,
use **Storage > Configure recording storage > One Drive: Monitor Existing Recording
Folder**. Enter the existing path selected in Videosoft, such as
`/home/vsuser/recordings`. This mode keeps the system disk protected and makes no
partition, label, mount, ownership, or `/etc/fstab` changes.

Hardware watchdog is disabled by default. Enable only after testing:
For POC-451VTC / Intel Atom x6425E gateways, first expose the Intel TCO watchdog:

```bash
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/setup_itco_watchdog.sh
```

Only enable feeding after `/dev/watchdog0` exists and `wdctl /dev/watchdog0` reports `iTCO_wdt`:

```json
"hardware_watchdog": {
  "enabled": true,
  "device": "/dev/watchdog0",
  "feed_interval_seconds": 10,
  "timeout_seconds": 30,
  "startup_grace_seconds": 300,
  "post_trip_grace_seconds": 900
}
```

When hardware feeding is enabled, VA-Connect intentionally leaves `/dev/watchdog0` closed for five minutes after a normal reboot. A reboot caused by the deliberate trip test receives a 15-minute safety window. This gives remote support time to reconnect and disable hardware feeding before it is armed again. The Watchdog page shows the countdown and provides guarded controls to extend the current window, arm immediately, or disable feeding before the device is opened. Once armed, the hardware timeout remains 30 seconds.
