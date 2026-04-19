# v1 Uninstall

Use this on a gateway that previously had the old VA-Connect v1 install.

Run:

```bash
sudo bash tools/ubuntu/uninstall_v1_watchdog.sh
```

What it removes:
- `va-connect-site-watchdog.service`
- `va-connect-watchdog.service`
- `va-connect-watchdog.timer`
- the legacy `va-connect-watchdog-web.service` only when it still looks like the v1 unit
- old v1 helper scripts in `/opt/va-connect-watchdog`
- the legacy `watchdog-update` and `watchdog-restart` wrappers in `/usr/local/bin`
- the old v1 data and log directories

What it keeps:
- the v2 checkout in `/opt/va-connect-watchdog` if it exists
- the v2 watchdog service
- the v2 web UI service when it is already a v2 unit

After uninstalling v1, you can install v2 with:

```bash
sudo bash /opt/va-connect-watchdog/bootstrap_v2_gateway.sh
```

If you are starting from a fresh gateway, you can skip the uninstall and just run the v2 bootstrap.
