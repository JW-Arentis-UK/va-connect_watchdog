# VA-Connect v2 Systemd Setup

This is the minimal systemd setup for the v2 site watchdog.

It uses one service only:

- `site_watchdog.service`

It does not use `WATCHDOG=1`.
It only restarts the process if it exits or crashes.

This unit expects the repository venv at `/opt/va-connect-watchdog/.venv`.

## Service File

```ini
[Unit]
Description=VA-Connect v2 site watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/va-connect-watchdog
Environment=PYTHONUNBUFFERED=1
Environment=VA_CONNECT_V2_DATA_DIR=/var/lib/va-connect-v2
Environment=VA_CONNECT_V2_CONFIG=/opt/va-connect-watchdog/config.json
EnvironmentFile=-/opt/va-connect-watchdog/site_watchdog.env
ExecStart=/opt/va-connect-watchdog/.venv/bin/python -m tools.ubuntu.runtime.site_watchdog
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Install Steps

1. Copy the service file into `/etc/systemd/system/`.

```bash
sudo cp ./tools/ubuntu/deploy/site_watchdog.service /etc/systemd/system/site_watchdog.service
```

2. Reload systemd.

```bash
sudo systemctl daemon-reload
```

3. Enable the service.

```bash
sudo systemctl enable site_watchdog.service
```

4. Start the service.

```bash
sudo systemctl start site_watchdog.service
```

## Start, Stop, Restart

```bash
sudo systemctl start site_watchdog.service
sudo systemctl stop site_watchdog.service
sudo systemctl restart site_watchdog.service
```

## Status And Logs

Check service state:

```bash
systemctl status site_watchdog.service
```

Follow logs live:

```bash
journalctl -u site_watchdog.service -f
```

If your systemd version accepts the shorter unit name in context, these also work:

```bash
systemctl status site_watchdog
journalctl -u site_watchdog -f
```

## Environment And Config

The service supports both environment variables and an optional config file.

### Optional environment file

If present, systemd loads:

```text
/opt/va-connect-watchdog/site_watchdog.env
```

You can use it for values like:

```bash
VA_CONNECT_V2_DATA_DIR=/var/lib/va-connect-v2
VA_CONNECT_V2_DEVICE_ID=POC-451VTC
VA_CONNECT_V2_APP_MATCH=va-connect
VA_CONNECT_V2_WAN_HOSTS=1.1.1.1,8.8.8.8
VA_CONNECT_V2_CHECK_INTERVAL_SECONDS=30
VA_CONNECT_V2_PING_TIMEOUT_SECONDS=3
VA_CONNECT_V2_LOG_LEVEL=INFO
```

### Optional config file

The runtime also reads:

```text
/opt/va-connect-watchdog/config.json
```

If the file does not exist, defaults and environment values are still used.

Example config file:

```json
{
  "device_id": "POC-451VTC",
  "data_dir": "/var/lib/va-connect-v2",
  "app_match": "va-connect",
  "wan_hosts": "1.1.1.1,8.8.8.8",
  "check_interval_seconds": 30,
  "ping_timeout_seconds": 3,
  "web_host": "127.0.0.1",
  "web_port": 8787,
  "log_level": "INFO"
}
```

## Common Troubleshooting Issues

### Service does not start

Check:

- the service file was copied to `/etc/systemd/system/site_watchdog.service`
- `systemctl daemon-reload` was run
- `WorkingDirectory=/opt/va-connect-watchdog` points to the real install path
- `python3` exists at `/usr/bin/python3`

### Service exits immediately

Check:

- the repository was deployed to `/opt/va-connect-watchdog`
  - the `.venv` directory exists under `/opt/va-connect-watchdog`
  - the module path `tools.ubuntu.runtime.site_watchdog` is importable from the working directory

### Logs are empty

Check:

- `PYTHONUNBUFFERED=1` is present
- `journalctl -u site_watchdog.service -f` is reading the correct unit
- the service is actually active

### No incidents appear

Check:

- the watchdog loop is running
- WAN and process checks are configured
- the data directory exists and is writable

### Config changes are ignored

Check:

- the environment file is in place if you use one
- `VA_CONNECT_V2_CONFIG` points to the expected JSON file
- the service was restarted after editing config

### Permission problems

If the service cannot write to `/var/lib/va-connect-v2`, fix ownership or change `VA_CONNECT_V2_DATA_DIR` to a writable path.

## Minimal Rule Set

- one service
- one working directory
- one restart policy
- one optional env file
- one optional config file

That is enough for the minimal v2 watchdog.
