# VA-Connect Watchdog

V3 is the current watchdog for Videosoft gateways and Raspberry Pi units. It
monitors system, services, connectivity and recording storage, keeps pre-crash
evidence, and provides independent hardware protection where configured.

## Install Or Update

For a new, older V3 or partially installed **Ubuntu 22.04 amd64 gateway**, run:

```sh
wget -O setup_gateway.sh https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/setup_gateway.sh && bash ./setup_gateway.sh
```

The entry point downloads the current full installer instead of running an old
installed updater. It temporarily uses the official Ubuntu main, updates and
security repositories (including universe), keeps signature checks enabled, and
installs Python virtual-environment support before application setup. Permanent
APT sources and third-party repository settings are not changed.

New installations prompt for the site name and optional asset ID and enable
persistent crash logging. Existing V3 installations retain their identity and
journal settings, back up configuration, and run complete setup to repair missing
accounts, dependencies, helpers and service units. Tracked local source changes
stop installation rather than being discarded. The published login and recording
span fixes are included; Ubuntu account passwords are not changed.

Active or enabled V1/V2 services stop this entry point with an attended-migration
message. It does not uninstall legacy services or erase their evidence. Other
operating systems/architectures are rejected before package changes; use the
platform-specific documentation for Raspberry Pi.

After this installation, the dashboard update button uses the corrected updater.
For options, run `bash ./setup_gateway.sh --help`.

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
- LAN device/camera discovery with model and serial information and editable site credentials.
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
