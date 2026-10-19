# Raspberry Pi watchdog profile

V3 uses one monitoring engine for Ubuntu gateways and Raspberry Pi OS. On a new
installation, the installer detects Raspberry Pi hardware and applies
`v3/config.pi.json` over the normal example configuration. Existing
`/etc/va-watchdog/config.json` files are backed up and preserved; the installer
does not replace an existing site's monitoring policy unless
`--apply-pi-profile` is selected. That option backs up the prior file and
replaces only the settings named in the Pi profile; identity and unrelated
site-specific settings remain intact.

The Pi profile uses the lightweight web view on port 9110. It monitors
TeamViewer Host, LightDM, SSH, the X11 session, network reachability, CPU,
temperature, memory, root storage, and reboot evidence. It does not expect the
Videosoft gateway services, a CCTV recording volume, or a Neousys watchdog.
Software service restarts and machine reboots remain disabled by default. The
display monitor may restart LightDM if the graphical session fails repeatedly;
this can disconnect a TeamViewer session, while SSH remains available.

On a Raspberry Pi OS system with a desktop, LightDM, and TeamViewer Host already
installed, run the repository's top-level installer from a published ref that
contains this profile:

```sh
bash install_v3_gateway.sh --site-name 'Pi AIO'
```

For an existing V3 configuration that still names Ubuntu gateway services, use
`bash install_v3_gateway.sh --site-name 'Pi AIO' --apply-pi-profile` after
reviewing the Pi profile. Leave that option out to keep a custom Pi policy.

The installer downloads the selected repository ref and installs the systemd
services. `v3/scripts/install.sh` is the local install step when the checkout is
already present at `/opt/va-connect-watchdog-v3`. Verify with:

```sh
systemctl is-active va-watchdog va-watchdog-feed va-watchdog-web
curl -fsS http://127.0.0.1:9110/api/healthz
```

Open `http://<pi-ip>:9110/lite` from a machine that can reach the Pi. Review
`/etc/va-watchdog/config.json` to add site-specific network targets or change
the monitored services. If TeamViewer, LightDM, or SSH has a different unit name,
update `services` and `display_monitor.manager` before interpreting its alerts.
Headless HDMI setup is separate; see [headless-display.md](headless-display.md).

The current hardware feeder is specific to reviewed Neousys gateways. The Pi
profile does not enable a Raspberry Pi hardware watchdog or automatic reboot.
