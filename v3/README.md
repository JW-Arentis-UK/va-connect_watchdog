# VA-Connect Watchdog V3

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

The web page now includes a watchdog update action that pulls the current branch and restarts the service in the background.

Default monitored services:
- esg.service
- bridge.service
- esg-config.service

Install on target:
```bash
cd /opt
sudo git clone <YOUR_REPO_URL> va-connect-watchdog-v3
cd /opt/va-connect-watchdog-v3
sudo ./scripts/install.sh
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

Recording storage is mounted by Linux through `/etc/fstab`; the watchdog monitors and can safely configure the labelled entry, but it is not required for the mount to exist. Intended entry:

```fstab
LABEL=CCTV_STORAGE /media/ususer/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2
```

The Storage page includes a Recording Storage panel and a guarded configuration flow. It refuses protected system mounts and the parent disk containing `/`, never formats a disk, and only relabels a selected ext4 partition after explicit confirmation.

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
  "feed_interval_seconds": 10
}
```
