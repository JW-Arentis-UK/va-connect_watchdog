# VA-Connect Watchdog

Lightweight Ubuntu watchdog tooling for a PC running VA-Connect.

## What is included

- `tools/ubuntu/va_connect_watchdog.sh`
- `tools/ubuntu/va_connect_site_watchdog.py`
- `tools/ubuntu/install_watchdog.sh`
- `tools/ubuntu/va-connect-watchdog.service`
- `tools/ubuntu/va-connect-watchdog.timer`
- `tools/ubuntu/va-connect-site-watchdog.service`
- `tools/ubuntu/va-connect.env.example`
- `tools/ubuntu/site-watchdog.json.example`
- `docs/ubuntu_va_connect_watchdog.md`

## Purpose

This project checks whether the VA-Connect process is running and starts it again if it is not detected.

It is designed for Ubuntu systems where VA-Connect is launched by a script, binary, AppImage, or other vendor-provided command.

For harder remote-site faults, it also includes a continuous site watchdog that:

- checks WAN connectivity against multiple hosts
- checks TCP reachability to local targets such as a RUT or RTSP device
- checks whether the VA-Connect process is still running
- captures evidence snapshots when a fault starts or changes
- tries app restart, optional network restart, and only then reboots with expanding backoff

## Quick start

1. Review `docs/ubuntu_va_connect_watchdog.md`.
2. Copy the project onto the Ubuntu machine.
3. Run `sudo ./tools/ubuntu/install_watchdog.sh`.
4. Update the environment file with the real VA-Connect launch command.
5. Update the site watchdog JSON with the real IPs and commands.
6. Start or verify the `systemd` timer and the continuous site watchdog service.

## Notes

- The timer example runs once per minute.
- The watchdog includes a restart cooldown to avoid rapid restart loops.
- The site watchdog writes JSONL events and diagnostic snapshots for remote fault finding.
- If VA-Connect already has its own `systemd` service, native `systemd` restart rules may be a better fit than an external watchdog.
