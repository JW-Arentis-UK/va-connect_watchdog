"""Check the active web layout after an update."""
import time
from urllib.request import ProxyHandler, build_opener

from .config import load_config


def check_setup(cfg, attempts=10, opener=None, sleeper=time.sleep):
    web = cfg.get("web", {})
    if not web.get("enabled", True):
        return
    host = web.get("host", "0.0.0.0")
    host = "127.0.0.1" if host in {"", "0.0.0.0"} else "::1" if host == "::" else host
    if ":" in host:
        host = f"[{host}]"
    lightweight = bool(web.get("lightweight"))
    url = f"http://{host}:{int(web.get('port', 9110))}{'/' if lightweight else '/setup'}"
    client = opener or build_opener(ProxyHandler({}))
    for attempt in range(attempts):
        try:
            with client.open(url, timeout=3) as response:
                body = response.read(256 * 1024)
                expected = b'id="cards"' if lightweight else b"Setup"
                if response.getcode() == 200 and b"<html" in body.lower() and expected in body:
                    return
        except OSError:
            pass
        if attempt + 1 < attempts:
            sleeper(2)
    page = "lightweight Status" if lightweight else "Setup"
    raise RuntimeError(f"The service is running but its {page} page did not pass the HTTP check. Review the service log; update not marked successful.")


if __name__ == "__main__":
    check_setup(load_config())
    print("Setup HTTP smoke check passed")
