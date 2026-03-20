# Ubuntu Watchdog For VA-Connect

This setup gives an Ubuntu PC two watchdog layers for VA-Connect:

- a lightweight process watchdog for simple "app stopped" cases
- a continuous site watchdog for remote fault finding, recovery, and reboot backoff

## Files

- `tools/ubuntu/va_connect_watchdog.sh`
- `tools/ubuntu/va_connect_site_watchdog.py`
- `tools/ubuntu/install_watchdog.sh`
- `tools/ubuntu/va-connect-watchdog.service`
- `tools/ubuntu/va-connect-watchdog.timer`
- `tools/ubuntu/va-connect-site-watchdog.service`
- `tools/ubuntu/va-connect.env.example`
- `tools/ubuntu/site-watchdog.json.example`

## Fast install

If the whole project is already on the Ubuntu machine, you can install everything with:

```bash
sudo ./tools/ubuntu/install_watchdog.sh
```

The installer:

- copies the watchdog script into `/opt/va-connect-watchdog`
- creates `/opt/va-connect-watchdog/va-connect.env` if it does not already exist
- creates `/opt/va-connect-watchdog/site-watchdog.json` if it does not already exist
- installs the `systemd` service and timer
- installs the continuous site watchdog service
- reloads `systemd` and enables the timer

After that, edit both config files with your real command and site IPs.

## 1. Copy the files to the Ubuntu machine

Place the watchdog folder somewhere durable, for example:

```bash
sudo mkdir -p /opt/va-connect-watchdog
sudo cp va_connect_watchdog.sh /opt/va-connect-watchdog/
sudo cp va-connect.env.example /opt/va-connect-watchdog/va-connect.env
sudo chmod +x /opt/va-connect-watchdog/va_connect_watchdog.sh
```

## 2. Edit the environment file

Update `/opt/va-connect-watchdog/va-connect.env` for your VA-Connect install.

Important values:

- `APP_MATCH`
  Process text used to detect whether VA-Connect is already running.
- `APP_START_CMD`
  Full command used to start VA-Connect.
- `APP_WORKDIR`
  Working folder for the start command.
- `WATCHDOG_LOG`
  Where the watchdog writes status entries.

Example:

```bash
APP_NAME="VA-Connect"
APP_MATCH="/opt/va-connect/va-connect"
APP_START_CMD="/opt/va-connect/start-va-connect.sh"
APP_WORKDIR="/opt/va-connect"
WATCHDOG_LOG="/var/log/va-connect-watchdog.log"
START_COOLDOWN_SECONDS="20"
```

If VA-Connect is a Python app, `APP_START_CMD` can be something like:

```bash
/opt/va-connect/.venv/bin/python /opt/va-connect/va_connect.py
```

If it is an AppImage, script, or compiled binary, use that executable instead.

## 3. Configure the site watchdog

Update `/opt/va-connect-watchdog/site-watchdog.json` so it reflects the real site.

Most important values:

- `internet_hosts`
  Public IPs to prove WAN access is working.
- `tcp_targets`
  Local devices you care about, such as the RUT and an RTSP endpoint.
- `app_match`
  Process text used to prove VA-Connect is still alive.
- `app_start_command`
  Command used if the process disappears.
- `network_restart_command`
  Optional network repair action before reboot.
- `base_reboot_timeout_seconds`
  First reboot delay after a fault begins.
- `max_reboot_timeout_seconds`
  Ceiling for the expanding reboot delay.

Example targets:

```json
"tcp_targets": [
  { "host": "192.168.1.1", "port": 80 },
  { "host": "192.168.1.132", "port": 554 }
]
```

What the site watchdog writes:

- `/var/log/va-connect-site-watchdog/events.jsonl`
  Structured event log for remote review.
- `/var/log/va-connect-site-watchdog/snapshots/`
  Evidence bundles captured when a fault starts, changes, or just before reboot.
- `/var/lib/va-connect-site-watchdog/state.json`
  Current state, counters, and backoff progress.

Each snapshot contains items such as:

- `ip addr`
- `ip route`
- resolver status
- memory and disk usage
- top processes
- recent system journal
- recent `NetworkManager` journal
- recent `teamviewerd` journal

## 4. Install the systemd files

Copy the service and timer:

```bash
sudo cp va-connect-watchdog.service /etc/systemd/system/
sudo cp va-connect-watchdog.timer /etc/systemd/system/
sudo cp va-connect-site-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now va-connect-watchdog.timer
sudo systemctl enable --now va-connect-site-watchdog.service
```

## 5. Check status

```bash
systemctl status va-connect-watchdog.timer
systemctl status va-connect-watchdog.service
systemctl status va-connect-site-watchdog.service
journalctl -u va-connect-watchdog.service -n 50 --no-pager
tail -n 50 /var/log/va-connect-watchdog.log
journalctl -u va-connect-site-watchdog.service -n 50 --no-pager
tail -n 50 /var/log/va-connect-site-watchdog/events.jsonl
```

## 6. Run an immediate check

```bash
sudo systemctl start va-connect-watchdog.service
sudo systemctl restart va-connect-site-watchdog.service
```

## How it behaves

- If VA-Connect is already running, the watchdog logs an `OK` entry.
- If it is missing, the watchdog runs `APP_START_CMD`.
- If a restart was attempted recently, the cooldown prevents rapid restart loops.

The site watchdog behaves differently because it is meant for remote fault finding:

- If WAN, LAN targets, and app process are all healthy, it writes a heartbeat.
- If a fault starts, it records the fault and captures a diagnostic snapshot.
- If the app disappears, it tries to start it.
- If WAN is down, it can restart networking first.
- If the fault persists long enough, it reboots the PC.
- After each reboot attempt, the next reboot threshold expands using backoff.
- Once the system is healthy again, the reboot threshold resets to the base delay.

## Notes

- The timer is set to run every minute.
- The service runs as `root` by default in the sample so it can launch whatever command you point it at. If VA-Connect should run as a normal user, change `User=` and `Group=` in the service file.
- For your type of remote site, the continuous site watchdog is the more useful layer because it leaves evidence behind after a recovery.
- If you already launch VA-Connect with its own `systemd` service, the cleaner approach is often to monitor that service directly and let `systemd` restart it. This bundle is most useful when VA-Connect is launched by a script, AppImage, or vendor binary outside a managed service.
