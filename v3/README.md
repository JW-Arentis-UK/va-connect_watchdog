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

Hardware watchdog is disabled by default. Enable only after testing:
```json
"hardware_watchdog": {
  "enabled": true,
  "device": "/dev/watchdog0",
  "feed_interval_seconds": 10
}
```
