# VA-Connect Watchdog

V3 is the current watchdog for Videosoft gateways and Raspberry Pi units. It
monitors system, services, connectivity and recording storage, keeps pre-crash
evidence, and provides independent hardware protection where configured.

## Install Or Update

For a new installation, download the current installer:

```sh
wget -O install_v3_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/install_v3_gateway.sh
bash install_v3_gateway.sh
```

For an existing V3 installation, use the authenticated update button or run:

```sh
sudo bash /opt/va-connect-watchdog-v3/v3/scripts/update.sh origin codex/gui-refresh
```

Open `http://<unit-ip>:9110/`. Operator actions require the existing configured
local account. Use VPN or HTTPS forwarding for remote sign-in; plain HTTP does
not encrypt passwords.

The complete installer/updater is required: copying a Python file alone does not
install service accounts, permissions, helpers or systemd units. Existing
configuration and evidence are preserved. Hardware watchdog activation is an
explicit attended commissioning step, not an automatic installation action.

## Included Features

- Health, recording/storage monitoring, bounded service recovery and event history.
- Independent hardware feeding on supported Neousys gateways; native systemd
  watchdog observation on Pi.
- Persistent Black Box buffer, boot attribution, syslog and support bundles.
- ANPR collection, plate searches/database and exports.
- People/crossing analytics, camera delivery/configuration diagnostics and PDF reports.
- Network speed tests, custom web links and TeamViewer password management.
- Updates, evidence, protected commissioning and recovery tools.

Network and general health failures cannot request a V3 software reboot.
Explicit manual reboot and deliberate hardware tests remain guarded actions.
Hardware reset protection and service recovery are different mechanisms.

## Documentation

- [Installation and configuration](v3/README.md)
- [Raspberry Pi profile](v3/docs/raspberry-pi.md)
- [Current reassessment and acceptance status](v3/docs/watchdog-review-2026-10-27.md)
- [Legacy runtime archive and migration](docs/legacy-runtime.md)

The old V1/V2 runtime, installers and duplicate dashboards are retired from the
current branch. Their source remains recoverable in Git. Historical incident
evidence is not removed by this cleanup.
