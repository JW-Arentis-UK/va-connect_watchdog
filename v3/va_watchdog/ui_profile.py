"""Device-specific presentation and a shared guard for incompatible setup tools."""
from pathlib import Path


def is_pi(cfg):
    return cfg.get("platform", {}).get("kind") == "raspberry_pi"


def route_supported(cfg, route):
    if route.startswith("/pi-storage"):
        return is_pi(cfg)
    if is_pi(cfg):
        prefixes = ("/neousys-watchdog-", "/hardware-watchdog-", "/watchdog-hardware-",
                    "/watchdog-legacy-", "/watchdog-grace-", "/watchdog-arm-",
                    "/watchdog-trip-", "/watchdog-test-", "/watchdog-liveness-",
                    "/watchdog-timeout-")
        return not (route.startswith(prefixes) or route == "/api/diagnostics/manufacturer-report.zip")
    return True


def maintenance_page(cfg):
    page = Path(__file__).with_name("maintenance.html").read_text(encoding="utf-8")
    values = {
        "__HARDWARE_DESCRIPTION__": "Review native systemd watchdog protection on this Pi." if is_pi(cfg) else "Review the Neousys watchdog driver, feed state, last reset test and recovery protection.",
        "__STORAGE_DESCRIPTION__": "Review Pi recording history and root partition space." if is_pi(cfg) else "Confirm the recording disk, mount point, free space and automatic mounting.",
        "__STORAGE_LINK__": "/pi-storage" if is_pi(cfg) else "/setup#storage",
        "__UPDATE_LINK__": "/update-confirm" if is_pi(cfg) else "/setup#software-update",
        "__EVIDENCE_LINK__": "/api/evidence.zip" if is_pi(cfg) else "/evidence-download",
    }
    for marker, value in values.items():
        page = page.replace(marker, value)
    return page.encode("utf-8")
