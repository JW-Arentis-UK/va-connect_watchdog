# Optional headless display

The setup module installs/configures a virtual 1920×1080 output and enables display monitoring in the V3 watchdog. It is opt-in. An existing desktop environment and one of `gdm3`, `gdm`, `lightdm`, or `sddm` must already be installed; a console-only Raspberry Pi OS Lite image needs a desktop and display manager first. Run the preview before applying:

For a Pi, `enable_pi_dummy_display.py` in the repository root is a self-contained file you can copy over SSH. Run `sudo python3 enable_pi_dummy_display.py --dry-run`, then `sudo python3 enable_pi_dummy_display.py`. It backs up changed files under `/var/backups/va-watchdog/headless-display` and asks for a reboot. If the updated V3 watchdog is installed, it also enables display monitoring.

```sh
sudo env PYTHONPATH=/opt/va-connect-watchdog-v3/v3 python3 -m va_watchdog.display_setup
sudo env PYTHONPATH=/opt/va-connect-watchdog-v3/v3 python3 -m va_watchdog.display_setup --apply
```

Use `--manager lightdm.service` if several managers are installed. Use `--output HDMI-A-2` for the second HDMI connector on a Pi. The apply command makes timestamped backups of files it changes, enables the existing display manager and `graphical.target`, and enables the optional watchdog monitor. It starts an inactive display manager, but leaves an already active session running. Reboot or restart the display manager later to load the new virtual output. Restarting the display manager disconnects current desktop sessions; SSH remains the way to recover if the desktop does not return.

| Host | Setup |
| --- | --- |
| Ubuntu/Debian | Installs `xserver-xorg-video-dummy` and writes `/etc/X11/xorg.conf.d/99-dummy.conf`. GDM is set to use X11. |
| Fedora | Installs Fedora's `xorg-x11-drv-dummy` package and writes the same Xorg configuration. GDM is set to use X11. |
| Raspberry Pi OS Buster/legacy | Adds a managed block in `/boot/config.txt` (or `/boot/firmware/config.txt`) with `hdmi_force_hotplug=1`, DMT group 2 and mode 82 for 1080p. |
| Raspberry Pi OS Bullseye/Bookworm or newer | Adds or replaces the chosen HDMI output's `video=HDMI-A-1:1920x1080M@60D` kernel parameter in `cmdline.txt`, keeping that file on one line. No Xorg dummy driver is installed. |

Every 30 seconds, the watchdog checks the configured display manager and an Xorg session on standard Linux, or an Xorg/Wayland compositor session on modern Pi OS. Two consecutive failures after a 90-second startup grace trigger a manager restart. Restarts are separated by at least five minutes and limited to three per hour. A display failure is reported as a noncritical warning and cannot request a gateway reboot through V3 recovery. The setup module enables this with `display_monitor.enabled`; machines without the option keep the feature off.

For TeamViewer specifically, a virtual HDMI signal is only one requirement. Raspberry Pi OS Bookworm normally uses Wayland, while some remote desktop products require an X11 session. If TeamViewer still shows a black screen, select an X11 desktop session using Raspberry Pi OS configuration and verify the TeamViewer host supports that OS/session. The setup module does not silently change Bookworm's Wayland default.

References: [Raspberry Pi display configuration](https://www.raspberrypi.com/documentation/computers/configuration.html), [legacy HDMI options](https://www.raspberrypi.com/documentation/computers/legacy_config_txt.html), [KMS hotplug guidance](https://pip-assets.raspberrypi.com/categories/1259-audio-camera-and-display/documents/RP-004341-WP/Troubleshooting-KMS-HDMI-output), [Ubuntu dummy driver](https://packages.ubuntu.com/search?keywords=xserver-xorg-video-dummy), [Fedora dummy driver](https://packages.fedoraproject.org/pkgs/xorg-x11-drv-dummy/xorg-x11-drv-dummy/).
