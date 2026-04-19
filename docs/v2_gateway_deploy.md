# VA-Connect v2 Gateway Deploy

Minimal deployment steps for a Linux gateway.

If the gateway still has the old v1 install, remove it first:

```bash
sudo bash tools/ubuntu/uninstall_v1_watchdog.sh
```

## Fresh gateway bootstrap

For a brand-new gateway, fetch and run the root bootstrap script:

```bash
curl -fsSL https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/master/bootstrap_v2_gateway.sh -o /tmp/bootstrap_v2_gateway.sh
sudo bash /tmp/bootstrap_v2_gateway.sh
```

If `curl` is not installed, use Python instead:

```bash
python3 - <<'PY'
from urllib.request import urlretrieve
urlretrieve(
    "https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/master/bootstrap_v2_gateway.sh",
    "/tmp/bootstrap_v2_gateway.sh",
)
PY
sudo bash /tmp/bootstrap_v2_gateway.sh
```

That one script will clone the repository from GitHub and finish the install.

That script will:

- install prerequisites
- clone or update the repo in `/opt/va-connect-watchdog`
- create `/var/lib/va-connect-site-watchdog`
- create `/opt/va-connect-watchdog/site-watchdog.json`
- install and start `va-connect-watchdog-web.service` using the legacy web server

## 1. Copy the project

Copy the repository to:

```bash
/opt/va-connect-watchdog
```

If you already cloned the repo manually, you can also run the same script from the repo root:

```bash
sudo bash bootstrap_v2_gateway.sh
```

## 2. Create the data directory

The watchdog writes local state, incidents, events, and logs to:

```bash
/var/lib/va-connect-site-watchdog
```

Create it and make sure it is writable:

```bash
sudo mkdir -p /var/lib/va-connect-site-watchdog
sudo chown -R root:root /var/lib/va-connect-site-watchdog
sudo chmod -R 755 /var/lib/va-connect-site-watchdog
```

## 3. Set permissions

Make sure the project tree is readable:

```bash
sudo chmod -R a+rX /opt/va-connect-watchdog
```

If you use a virtual environment or local config file, make sure those files are readable too.

## 4. Configure optional settings

The watchdog reads environment variables and an optional config file:

- `SITE_WATCHDOG_CONFIG=/opt/va-connect-watchdog/site-watchdog.json`

The bootstrap installs `va-connect-watchdog-web.service` and starts it automatically on port `8787`.

Check status:

```bash
systemctl status va-connect-watchdog-web
```

Follow logs:

```bash
journalctl -u va-connect-watchdog-web -f
```

## 5. Test commands

Check the local page and endpoints:

```bash
curl http://127.0.0.1:8787/
curl http://127.0.0.1:8787/api/base-status
curl http://127.0.0.1:8787/api/status
```

Check that the data directory is writable:

```bash
test -w /var/lib/va-connect-site-watchdog && echo writable
```

## 6. Browser access

Open the UI from another machine on the same network:

```text
http://<gateway-ip>:8787
```

## 7. Common issues

- If the service does not start, check `systemctl status va-connect-watchdog-web` and `journalctl -u va-connect-watchdog-web -f`.
- If the web UI does not bind to port 8787, another service may already be using it.
- If state files are not written, confirm `/var/lib/va-connect-site-watchdog` exists and is writable.
- If config changes do not apply, confirm `SITE_WATCHDOG_CONFIG` points to the right file and restart the service.

That is the stripped-down gateway deployment path for the working web base.
