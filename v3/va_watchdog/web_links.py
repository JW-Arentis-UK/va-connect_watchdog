from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


LINK_GROUPS = ("rut", "camera", "other")
MAX_LINKS = 50


def normalize_web_link(name: Any, url: Any, group: Any) -> dict[str, str]:
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 80 or any(ord(character) < 32 for character in clean_name):
        raise ValueError("link name must be 1 to 80 printable characters")

    clean_group = str(group or "other").strip().lower()
    if clean_group not in LINK_GROUPS:
        raise ValueError("link type must be RUT, Camera, or Other")

    clean_url = str(url or "").strip()
    if not clean_url:
        raise ValueError("enter an IP address or URL")
    if "://" not in clean_url:
        clean_url = "http://" + clean_url
    if len(clean_url) > 512 or any(ord(character) < 33 for character in clean_url):
        raise ValueError("link URL must be a single printable value up to 512 characters")
    parsed = urlsplit(clean_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("link URL must use http:// or https://")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("link URL contains an invalid port") from exc
    if not parsed.hostname:
        raise ValueError("link URL must include a valid host or IP address")
    if parsed.username or parsed.password:
        raise ValueError("do not include usernames or passwords in web links")

    return {"name": clean_name, "url": clean_url, "group": clean_group}


def configured_web_links(cfg: dict[str, Any]) -> list[dict[str, str]]:
    links = cfg.get("web_links", [])
    if not isinstance(links, list):
        return []
    cleaned = []
    for item in links[:MAX_LINKS]:
        if not isinstance(item, dict):
            continue
        try:
            cleaned.append(normalize_web_link(item.get("name"), item.get("url"), item.get("group")))
        except ValueError:
            continue
    return cleaned
