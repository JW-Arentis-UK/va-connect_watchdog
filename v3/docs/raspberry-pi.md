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

The Pi Status page has **Update watchdog** in its top navigation. The Storage
tile opens Pi storage, which shows the physical drive, root partition, and
unused space. On a standard Raspberry Pi OS DOS partition layout with ext4 as
partition 2 and the final partition, an engineer can confirm the exact root
device to run `raspi-config nonint do_expand_rootfs`. Reboot afterward to finish
the filesystem resize. The action requires the Pi's local browser, its account
password, and the exact root device as confirmation. Unsupported layouts are
shown without an action button.

Install build `20261019.4` once through SSH if an earlier lightweight build
shows those links but returns "Not found":

```sh
sudo bash /opt/va-connect-watchdog-v3/v3/scripts/update.sh origin codex/gui-refresh
```

The lightweight server in this build serves the linked update and Pi storage
pages. Subsequent watchdog updates can be started from its top link.

Build `20261019.5` fixes the storage layout probe for Raspberry Pi OS images
whose `lsblk` does not provide the `PARTN` column. It reads the disk capacity
without `blockdev`, so the storage page can report size without raw-device
access. The root-expansion action remains disabled until all layout checks pass.

From build `20261019.6`, the lightweight update page disables the action while
an update is running, retries status checks through the web-service restart,
and returns to Status after completion. Status displays the last successful
update time and build number; failed or current attempts do not erase that
record.

From build `20261019.7`, Pi storage offers a password-confirmed reboot button
when the root partition has grown, the ext4 filesystem is still smaller, and
Raspberry Pi OS has queued its one-time resize script. The button schedules a
controlled reboot after the response is shown. Once the Pi returns, revisit
Pi storage to confirm that the filesystem uses the expanded partition.

Capture the reusable image **before** expanding a source drive. Expanding a
29 GiB root partition to fill a 1 TB SSD makes the image unsuitable for a
smaller target. A whole-disk raw image of a 1 TB SSD is also still a 1 TB
layout even when most of it is empty; prepare a compact image whose partition
table fits the smallest target, then expand the restored target from Pi storage.

The current hardware feeder is specific to reviewed Neousys gateways. The Pi
profile does not enable a Raspberry Pi hardware watchdog or automatic reboot.
