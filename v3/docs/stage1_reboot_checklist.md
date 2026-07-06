# Stage 1 Reboot Checklist

Use this on the gateway to confirm the v3 watchdog survives a reboot.

## One-command helper

If you want a quick check before reboot, use:

```bash
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/stage1_reboot_check.sh before
```

After the reboot, run:

```bash
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/stage1_reboot_check.sh after
```

## What to note

- the service should be `enabled`
- the service should be `active (running)`
- the status JSON should show the current health state

## Reboot

Reboot the gateway normally.

## What to confirm after reboot

- the service starts automatically
- the log shows a clean startup
- the web UI still responds on port `9110`
- the dashboard still renders the expected health state

## If something fails

- If the service does not start, check the unit file and the install path.
- If the web UI does not load, check the watchdog process and port `9110`.
- If the status is wrong, inspect `/var/lib/va-watchdog/status.json` and the journal.
