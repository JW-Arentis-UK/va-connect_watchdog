"""Check that the local Setup page actually renders after an update."""
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
    url = f"http://{host}:{int(web.get('port', 9110))}/setup"
    client = opener or build_opener(ProxyHandler({}))
    for attempt in range(attempts):
        try:
            with client.open(url, timeout=3) as response:
                body = response.read(256 * 1024)
                if response.getcode() == 200 and b"<html" in body.lower() and b"Setup" in body:
                    return
        except OSError:
            pass
        if attempt + 1 < attempts:
            sleeper(2)
    raise RuntimeError("The service is running but its Setup page did not pass the HTTP check. Review the service log; update not marked successful.")


if __name__ == "__main__":
    check_setup(load_config())
    print("Setup HTTP smoke check passed")
