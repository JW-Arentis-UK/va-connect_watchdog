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
- create `/var/lib/va-connect-v2`
- create `.venv`
- install Python dependencies
- install and start `site_watchdog.service`
- install and start `va-connect-watchdog-web.service`

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
/var/lib/va-connect-v2
```

Create it and make sure it is writable:

```bash
sudo mkdir -p /var/lib/va-connect-v2
sudo chown -R root:root /var/lib/va-connect-v2
sudo chmod -R 755 /var/lib/va-connect-v2
```

If you run the service as a non-root user, change ownership to that user instead.

## 3. Set permissions

Make sure the project tree is readable:

```bash
sudo chmod -R a+rX /opt/va-connect-watchdog
```

If you use a virtual environment or local config file, make sure those files are readable too.

## 4. Configure optional settings

The watchdog reads environment variables and an optional config file:

- `VA_CONNECT_V2_DATA_DIR=/var/lib/va-connect-v2`
- `VA_CONNECT_V2_CONFIG=/opt/va-connect-watchdog/config.json`
- `VA_CONNECT_V2_DEVICE_ID=...`
- `VA_CONNECT_V2_WEB_HOST=0.0.0.0`
- `VA_CONNECT_V2_WEB_PORT=8787`

The systemd unit already supports an optional env file:

```bash
/opt/va-connect-watchdog/site_watchdog.env
```

## 5. Start the watchdog service

Install the unit file:

```bash
sudo cp /opt/va-connect-watchdog/tools/ubuntu/deploy/site_watchdog.service /etc/systemd/system/site_watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable site_watchdog.service
sudo systemctl start site_watchdog.service
```

The bootstrap also installs `va-connect-watchdog-web.service` and starts it automatically.

Check status:

```bash
systemctl status site_watchdog
systemctl status va-connect-watchdog-web
```

Follow logs:

```bash
journalctl -u site_watchdog -f
journalctl -u va-connect-watchdog-web -f
```

## 6. Run the API manually

Start the API on the gateway with:

```bash
cd /opt/va-connect-watchdog
source .venv/bin/activate
uvicorn tools.ubuntu.web.app:app --host 0.0.0.0 --port 8787
```

If the port is already in use or you do not have permission to bind to port 8787, stop the other service or run with elevated privileges.

## 7. Test commands

Check the watchdog logs:

```bash
journalctl -u site_watchdog -f
```

Check the API:

```bash
curl http://127.0.0.1/health
curl http://127.0.0.1/gateways
curl http://127.0.0.1/debug/last-incident
```

Check that the data directory is writable:

```bash
test -w /var/lib/va-connect-v2 && echo writable
```

## 8. Browser access

Open the UI from another machine on the same network:

```text
http://<gateway-ip>:8787
```

## 9. Common issues

- If the service does not start, check `systemctl status site_watchdog` and `journalctl -u site_watchdog -f`.
- If the API does not bind to port 8787, another service may already be using it.
- If state files are not written, confirm `/var/lib/va-connect-v2` exists and is writable.
- If config changes do not apply, confirm `VA_CONNECT_V2_CONFIG` points to the right file and restart the service.

That is the full gateway deployment path for v2.
