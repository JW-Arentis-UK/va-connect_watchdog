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

Hardware watchdog feeding is deliberately not enabled on a clean install. This
test branch installs the bundled Neousys driver, but activation and the first trip
test must be performed from the Watchdog page during an attended maintenance window.

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

Hardware watchdog feeding is disabled by default. This test build supports only the
Neousys WDT_DIO backend on POC-451VTC. Install the bundled reviewed driver without
starting the hardware timer:

```bash
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/install_neousys_wdt.sh
```

Activation is explicit. It removes the Ubuntu legacy watchdog package/service,
removes and blacklists Intel TCO hardware paths, selects `/dev/wdt_dio`, and starts
a 15-minute remote-access safety window:

```bash
sudo ./v3/scripts/install_neousys_wdt.sh --activate
```

The effective hardware settings are:

```json
"hardware_watchdog": {
  "enabled": true,
  "backend": "neousys_wdt_dio",
  "device": "/dev/wdt_dio",
  "library_path": "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
  "feed_interval_seconds": 10,
  "timeout_seconds": 30,
  "startup_grace_seconds": 300,
  "post_trip_grace_seconds": 900
}
```

When hardware feeding is enabled, the independent feeder controls the vendor API.
It continues feeding during startup grace while stale-heartbeat enforcement is
deferred, allowing the main application and remote access to initialise without a
reboot loop. Ordinary service, storage, network, CPU, and RAM warnings never stop
feeding. Only a stale main heartbeat, a deliberate trip test, shutdown, or an
explicitly configured fatal condition can pause the hardware feed.

## Preserved crash evidence

When a new boot ID is detected, V3 freezes the previous boot's evidence before live
retention can overwrite it. Each incident archive is stored below
`/var/lib/va-watchdog/incidents` and is included in the downloadable support bundle.
It contains matching heartbeat, Black Box, and history rows, the last status and feed
state, previous-boot kernel journal, `last -x`, recent events, reboot classification,
and any available `pstore` records.

Incident archives are bounded independently to 10 incidents and 25 MB by default.
The newest archive is always retained. Reboot classification only reports a watchdog
or kernel reset when direct evidence supports it; informational messages such as
`NMI watchdog: Enabled` do not establish a reset cause.

The explicit persistent-journal action writes a separate
`/etc/systemd/journald.conf.d/va-watchdog-persistent.conf` drop-in. It limits journal
storage to 512 MB, reserves 1 GB free on the OS disk, and retains up to 30 days
without editing unrelated journald configuration.
