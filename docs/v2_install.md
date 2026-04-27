# v2 Install

Use this to install the current web-only v2 base on a gateway.

Run from a cloned repo:

```bash
sudo bash tools/ubuntu/install_v2_gateway.sh
```

What it does:
- clones or updates the repo into `/opt/va-connect-watchdog`
- prepares `/var/lib/va-connect-site-watchdog`
- writes `/opt/va-connect-watchdog/site-watchdog.json`
- installs and starts `va-connect-watchdog-web.service`
- serves the UI on port `8787`

If you are starting from a blank gateway, clone the repo first:

```bash
git clone https://github.com/JW-Arentis-UK/va-connect_watchdog.git
cd va-connect_watchdog
sudo bash tools/ubuntu/install_v2_gateway.sh
```
