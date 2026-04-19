# v2 Uninstall

Use this to remove the current v2 gateway install from a machine.

Run:

```bash
sudo bash tools/ubuntu/uninstall_v2_gateway.sh
```

If you want to skip the confirmation prompt:

```bash
sudo bash tools/ubuntu/uninstall_v2_gateway.sh --yes
```

What it removes:
- `/opt/va-connect-watchdog`
- `/var/lib/va-connect-v2`
- `/var/lib/va-connect-site-watchdog`
- `/var/log/va-connect-site-watchdog`
- `va-connect-watchdog-web.service`
- `site_watchdog.service`
- `va-connect-site-watchdog.service`
- `va-connect-watchdog.service`
- `va-connect-watchdog.timer`
- `/usr/local/bin/watchdog-update`
- `/usr/local/bin/watchdog-restart`
- any `/opt/va-connect-watchdog.backup.*` directories created during bootstrap

What it keeps:
- system packages
- user-local Python packages
- unrelated files outside the paths above

If you are cleaning a broken test box, this is the safest way to remove the whole v2 footprint before starting again.
