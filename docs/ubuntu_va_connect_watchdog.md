# Ubuntu Watchdog For VA-Connect

This setup gives an Ubuntu PC two watchdog layers for VA-Connect:

- a lightweight process watchdog for simple "app stopped" cases
- a continuous site watchdog for remote fault finding, recovery, and reboot backoff

## Files

- `tools/ubuntu/va_connect_watchdog.sh`
- `tools/ubuntu/va_connect_site_watchdog.py`
- `tools/ubuntu/va_connect_watchdog_web.py`
- `tools/ubuntu/install_watchdog.sh`
- `tools/ubuntu/va-connect-watchdog.service`
- `tools/ubuntu/va-connect-watchdog.timer`
- `tools/ubuntu/va-connect-site-watchdog.service`
- `tools/ubuntu/va-connect-watchdog-web.service`
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
- installs the web UI service
- reloads `systemd`, disables the legacy minute timer, and enables the site watchdog and web UI

After that, edit both config files if needed for your site.

## POC-451VTC baseline

The current known values from the VA-Connect encoder are:

- hostname: `POC-451VTC`
- Linux user: `vsuser`
- project folder on the Desktop: `/home/vsuser/Desktop/va-connect-watchdog`
- installed watchdog runtime: `/opt/va-connect-watchdog`
- active NIC/IP: `enp3s0` on `192.168.1.100/16`
- default gateway / RUT: `192.168.1.1`
- VA-Connect launcher: `/home/vsuser/vsgwgui/vsgwgui`
- remote access present: `teamviewerd`

The example files now reflect those confirmed values:

- `site-watchdog.json.example` monitors `192.168.1.1:80`
- `site-watchdog.json.example` includes `teamviewerd.service`
- `va-connect.env.example` uses `/home/vsuser/vsgwgui` as the default workdir
- both example config files use the Desktop launcher command for `vsgwgui`

## Fastest first-time install on a new gateway

If the gateway can reach GitHub, the easiest first install is:

```bash
cd ~/Desktop
wget -O bootstrap_watchdog_from_github.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/master/tools/ubuntu/bootstrap_watchdog_from_github.sh
bash ./bootstrap_watchdog_from_github.sh
```

If this is a brand new gateway and you want a fuller preflight first, use:

```bash
cd ~/Desktop
wget -O bootstrap_gateway_watchdog.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/master/tools/ubuntu/bootstrap_gateway_watchdog.sh
bash ./bootstrap_gateway_watchdog.sh
```

That fuller bootstrap will:

- inventory disks and mounted storage
- fail early if root or install-path free space is too low
- install `git`, `python3`, network tools, and hardware-diagnostics packages
- warn if the expected VA-Connect launcher or `teamviewerd` baseline is missing
- clone the repo and run the watchdog installer

That will:

- install `git`
- clone the public watchdog repo into `~/Desktop/va-connect-watchdog`
- run the installer
- enable the watchdog services

If you prefer GitHub SSH access, the same script also accepts an SSH repo URL:

```bash
bash ./bootstrap_watchdog_from_github.sh git@github.com:JW-Arentis-UK/va-connect_watchdog.git
```

In SSH mode it will:

- make an SSH key if needed
- print the public key
- stop and tell you to add the key if GitHub access is not ready yet

## Quick site info capture

If copy and paste is awkward over the remote connection, run this from the project folder:

```bash
chmod +x ./tools/ubuntu/collect_va_connect_site_info.sh
./tools/ubuntu/collect_va_connect_site_info.sh
```

It writes a timestamped text file to the Desktop, for example:

```text
~/Desktop/va_connect_site_info_<hostname>_<timestamp>.txt
```

That file includes the user, hostname, process list, desktop launchers, IP config, routes, and related `systemd` and journal details.

## Export an incident window

If you want a pack of everything around a fault, use:

```bash
chmod +x ./tools/ubuntu/export_watchdog_incident.sh
./tools/ubuntu/export_watchdog_incident.sh --incident "2026-03-23 22:26" --reboot "2026-03-24 08:12"
```

Or use an explicit time range:

```bash
./tools/ubuntu/export_watchdog_incident.sh --since "2026-03-23 21:56" --until "2026-03-24 08:42"
```

This writes a folder and `.tar.gz` archive to the Desktop containing:

- filtered `events.jsonl`
- filtered `metrics.jsonl`
- current state and build info
- system and kernel journal for the selected window
- service journals for `esg`, `bridge`, `sysops`, `teamviewerd`, and networking
- boot history
- snapshots captured in the same time window
- the latest `previous-boot-review` snapshot even if it falls just outside the selected window

## Hardware clues surfaced automatically

The site watchdog now also keeps a lightweight hardware summary in state for the webpage and snapshots:

- kernel warning matches for `EDAC`, machine-check, storage, and link-reset style messages
- `pstore` presence under `/sys/fs/pstore`
- SMART summaries for `/dev/sda` and `/dev/sdb` when `smartctl` is installed

For full disk-health visibility on the gateway, install:

```bash
sudo apt update
sudo apt install -y smartmontools edac-utils
```

After that, the web page will show a `Hardware warnings` section and snapshots will include:

- `smart_sda.txt`
- `smart_sdb.txt`
- `pstore_listing.txt`
- kernel hardware-warning extracts

## Restart watchdog services

If you update files or need to bounce the watchdog stack, run:

```bash
chmod +x ./tools/ubuntu/restart_watchdog_services.sh
sudo ./tools/ubuntu/restart_watchdog_services.sh
```

That reloads `systemd` and restarts:

- `va-connect-site-watchdog.service`
- `va-connect-watchdog-web.service`

It also disables the legacy `va-connect-watchdog.timer` so the older process-only watchdog does not cause noise or false failures.

## Update after changes

When you change any watchdog file, use one script to redeploy everything:

```bash
chmod +x ./tools/ubuntu/update_watchdog.sh
sudo ./tools/ubuntu/update_watchdog.sh
```

That will:

- reinstall the latest watchdog files into `/opt/va-connect-watchdog`
- reload and restart the live watchdog services
- disable the legacy minute timer if needed
- print quick verification checks

## GitHub install and update

For a clean GitHub-based install on the gateway PC:

```bash
sudo apt update && sudo apt install -y git wget
cd ~/Desktop
wget -O bootstrap_watchdog_from_github.sh <your-raw-script-url>
chmod +x bootstrap_watchdog_from_github.sh
./bootstrap_watchdog_from_github.sh <your-github-repo-url> main
```

If the repository is already cloned on the gateway PC, update and redeploy with:

```bash
cd ~/Desktop/va-connect-watchdog/tools/ubuntu
chmod +x git_update_watchdog.sh
./git_update_watchdog.sh
```

That script will:

- run `git pull --ff-only`
- redeploy the latest files into `/opt/va-connect-watchdog`
- restart the live watchdog services
- keep the legacy minute timer disabled

The installer also creates simple commands in `/usr/local/bin`:

```bash
watchdog-update
watchdog-restart
```

So on the gateway PC, once installed, updating is as simple as:

```bash
watchdog-update
```

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
- `systemd_services`
  Services that must stay active, for example Videosoft gateway services.
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
- `web_bind` and `web_port`
  Where the watchdog web UI listens on the VA-Connect encoder.
- `web_token`
  Optional simple token if you want to protect the page.

Example targets:

```json
"systemd_services": [
  "esg.service",
  "sysops.service",
  "bridge.service"
],
"tcp_targets": [
  { "host": "192.168.1.1", "port": 80 },
  { "host": "192.168.1.132", "port": 554 }
]
```

What the site watchdog writes:

- `/var/log/va-connect-site-watchdog/events.jsonl`
  Structured event log for remote review.
- `/var/log/va-connect-site-watchdog/metrics.jsonl`
  Rolling PC metrics used for the 24-hour graph in the web UI.
- `/var/log/va-connect-site-watchdog/snapshots/`
  Evidence bundles captured when a fault starts, changes, or just before reboot.
- `/var/lib/va-connect-site-watchdog/state.json`
  Current state, counters, and backoff progress.

After an unexpected reboot, it also captures a previous-boot review snapshot using `journalctl -b -1` so the next boot can surface clues from the last one.

The web UI defaults to:

```text
http://<encoder-ip>/
```

If you set `web_token`, open it as:

```text
http://<encoder-ip>/?token=your-token
```

From that page you can:

- view current WAN, LAN, and app health
- view monitored `systemd` service health
- view a 24-hour graph of CPU, memory, root disk, and recording disk usage
- view reboot counters and the last detected reboot reason
- review recent watchdog events
- enable or disable monitoring
- enable or disable app restart, network restart, and reboot actions
- edit key watchdog config values such as hosts, ports, timers, and web access settings
- trigger a manual check, snapshot, or network restart

Each snapshot contains items such as:

- `ip addr`
- `ip route`
- resolver status
- memory and disk usage
- load average and `vmstat`
- failed `systemd` services
- kernel journal
- top processes
- service status for key Videosoft services
- storage mount information
- recording storage status under `/mnt/storage`
- recent system journal
- recent `NetworkManager` journal
- recent `teamviewerd` journal

For `POC-451VTC`, the current URL should be:

```text
http://192.168.1.100/
```

## 4. Install the systemd files

Copy the service and timer:

```bash
sudo cp va-connect-watchdog.service /etc/systemd/system/
sudo cp va-connect-watchdog.timer /etc/systemd/system/
sudo cp va-connect-site-watchdog.service /etc/systemd/system/
sudo cp va-connect-watchdog-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now va-connect-watchdog.timer
sudo systemctl enable --now va-connect-site-watchdog.service
sudo systemctl enable --now va-connect-watchdog-web.service
```

## 5. Check status

```bash
systemctl status va-connect-watchdog.timer
systemctl status va-connect-watchdog.service
systemctl status va-connect-site-watchdog.service
systemctl status va-connect-watchdog-web.service
journalctl -u va-connect-watchdog.service -n 50 --no-pager
tail -n 50 /var/log/va-connect-watchdog.log
journalctl -u va-connect-site-watchdog.service -n 50 --no-pager
tail -n 50 /var/log/va-connect-site-watchdog/events.jsonl
journalctl -u va-connect-watchdog-web.service -n 50 --no-pager
```

## 6. Run an immediate check

```bash
sudo systemctl start va-connect-watchdog.service
sudo systemctl restart va-connect-site-watchdog.service
sudo systemctl restart va-connect-watchdog-web.service
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
- The web UI updates the JSON config on disk, so enable or disable choices persist across restarts.

Reboot counters are separated so the page is easier to read:

- `Watchdog reboot commands`
  How many times the watchdog itself issued a reboot command.
- `Detected reboots`
  How many boot transitions the watchdog has seen on startup.
- `Unexpected reboots`
  Reboots that happened without a recent watchdog reboot command, such as manual Ubuntu reboot or relay/power-cycle reboot.

## Notes

- The timer is set to run every minute.
- The service runs as `root` by default in the sample so it can launch whatever command you point it at. If VA-Connect should run as a normal user, change `User=` and `Group=` in the service file.
- For your type of remote site, the continuous site watchdog is the more useful layer because it leaves evidence behind after a recovery.
- If you already launch VA-Connect with its own `systemd` service, the cleaner approach is often to monitor that service directly and let `systemd` restart it. This bundle is most useful when VA-Connect is launched by a script, AppImage, or vendor binary outside a managed service.
