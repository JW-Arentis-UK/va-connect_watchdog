"""On-demand, read-only discovery on directly attached IPv4 networks."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import (HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm,
                            HTTPRedirectHandler, ProxyHandler, Request, build_opener)
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

SECRET = Path("/etc/va-watchdog-private/lan-camera.json")
STATE = Path("/var/lib/va-watchdog/lan-devices.json")
SETTINGS = Path("/var/lib/va-watchdog/lan-camera-settings.json")
TIMEOUT = 1.5


def _command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=4, check=False)
        return json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def interfaces():
    networks = []
    for item in _command(["ip", "-j", "-4", "addr", "show", "up"]):
        name = item.get("ifname", "")
        if name == "lo":
            continue
        for address in item.get("addr_info", []):
            if address.get("scope") != "global":
                continue
            try:
                local = ipaddress.IPv4Interface(f"{address['local']}/{address['prefixlen']}")
            except (KeyError, ValueError):
                continue
            if local.ip.is_loopback or local.ip.is_multicast:
                continue
            # Keep the first implementation bounded to the gateway's /24 or smaller.
            network = ipaddress.ip_network(f"{local.ip}/{max(local.network.prefixlen, 24)}", strict=False)
            networks.append({"id": f"{name}|{local.ip}|{network}", "interface": name,
                             "address": str(local.ip), "network": str(network),
                             "label": f"{name} - {network}", "limited": local.network.prefixlen < 24})
    return networks


def selected_network(selection):
    match = next((item for item in interfaces() if item["id"] == selection), None)
    if match is None:
        raise ValueError("Select a currently connected local network.")
    return match


def _read(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, ValueError):
        return default


def _write(path, value, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    os.chmod(temporary, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle)
    os.replace(temporary, path)


def credentials():
    value = _read(SECRET, {})
    return str(value.get("username") or "admin"), str(value.get("password") or "")


def save_credentials(username, password, clear=False):
    username = username.strip()
    if not username or len(username) > 64 or len(password) > 128:
        raise ValueError("Enter a username up to 64 characters and password up to 128 characters.")
    if any(ord(char) < 32 for char in username + password):
        raise ValueError("Credentials cannot contain control characters.")
    previous_user, previous_password = credentials()
    if not password and not clear and username != previous_user and previous_password:
        raise ValueError("Enter a password when changing the camera username.")
    password = "" if clear else (password or previous_password)
    SECRET.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(SECRET.parent, 0o700)
    _write(SECRET, {"username": username, "password": password}, 0o600)
    public = {"username": username, "password_set": bool(password)}
    _write(SETTINGS, public)
    return public


def status():
    settings = _read(SETTINGS, {"username": "admin", "password_set": False})
    return {"networks": interfaces(), "settings": {"username": settings.get("username", "admin"),
            "password_set": bool(settings.get("password_set"))},
            "scan": _read(STATE, {"devices": [], "state": "not_scanned"})}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_xml(url, username, password, body=None):
    manager = HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, url, username, password)
    # Never use ambient proxies or follow a device redirect with site credentials.
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPDigestAuthHandler(manager))
    request = Request(url, data=body, headers={"Content-Type": "application/soap+xml; charset=utf-8"} if body else {})
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            data = response.read(65537)
        if len(data) > 65536 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            return None, "Invalid device response"
        return ET.fromstring(data), ""
    except HTTPError as exc:
        code = exc.code
        exc.close()
        return None, "Credentials required or rejected" if code in {401, 403} else "Device information unavailable"
    except (OSError, URLError, ValueError, ET.ParseError):
        return None, "Device information unavailable"


def xml_fields(root):
    if root is None:
        return {}
    return {node.tag.rsplit("}", 1)[-1]: (node.text or "").strip()[:256] for node in root.iter()}


def onvif_body(username, password):
    nonce = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
    return (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:t="http://www.onvif.org/ver10/device/wsdl" '
            f'xmlns:w="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
            f'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
            f'<s:Header><w:Security><w:UsernameToken><w:Username>{escape(username)}</w:Username>'
            f'<w:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</w:Password>'
            f'<w:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(nonce).decode()}</w:Nonce>'
            f'<u:Created>{created}</u:Created></w:UsernameToken></w:Security></s:Header>'
            f'<s:Body><t:GetDeviceInformation/></s:Body></s:Envelope>').encode()


def discovery(network):
    """Use responder source IPs; never fetch untrusted advertised URLs."""
    found = {}
    subnet = ipaddress.ip_network(network["network"])
    packet = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
              'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:n="http://www.onvif.org/ver10/network/wsdl">'
              f'<s:Header><a:MessageID>uuid:{uuid.uuid4()}</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
              '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header>'
              '<s:Body><d:Probe><d:Types>n:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>').encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((network["address"], 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(network["address"]))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.settimeout(0.25)
            sock.sendto(packet, ("239.255.255.250", 3702))
            end = time.monotonic() + 1.5
            while time.monotonic() < end:
                try:
                    data, source = sock.recvfrom(16384)
                    if ipaddress.ip_address(source[0]) not in subnet or b"<!" in data:
                        continue
                    fields = xml_fields(ET.fromstring(data))
                    if "XAddrs" in fields:
                        found[source[0]] = True
                except socket.timeout:
                    continue
                except (ValueError, ET.ParseError):
                    continue
    except OSError:
        pass
    return found


def inspect_device(ip, interface, known, onvif, username, password, deadline):
    if time.monotonic() >= deadline:
        return None
    ports = []
    for port in (80, 443, 554):
        try:
            with socket.create_connection((ip, port), timeout=0.25):
                ports.append(port)
        except OSError:
            pass
    reachable = bool(ports or onvif)
    if not reachable:
        try:
            reachable = subprocess.run(["ping", "-n", "-I", interface, "-c", "1", "-W", "1", ip],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=1.5, check=False).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not reachable and not known:
        return None
    result = {"ip": ip, "manufacturer": "Unknown", "model": "Unavailable", "serial": "Unavailable",
              "mac": known.get("lladdr", ""), "status": "Responding" if reachable else "Neighbour cache only",
              "kind": "ONVIF camera" if onvif else "LAN device", "ports": ports}
    if not ports and not onvif:
        return result
    for scheme, port in (("http", 80), ("https", 443)):
        if port not in ports:
            continue
        base = f"{scheme}://{ip}"
        root, error = request_xml(base + "/ISAPI/System/deviceInfo", username, password)
        fields = xml_fields(root)
        if root is not None and root.tag.rsplit("}", 1)[-1] == "DeviceInfo" and fields.get("model"):
            result.update(manufacturer=fields.get("manufacturer") or "Hikvision / ISAPI-compatible",
                          model=fields["model"], serial=fields.get("serialNumber") or "Unavailable",
                          status="Identified", kind="Camera / video device")
            return result
        if "Credentials" in error:
            result["status"] = error
            return result
        if onvif:
            root, error = request_xml(base + "/onvif/device_service", username, password,
                                      onvif_body(username, password))
            fields = xml_fields(root)
            if fields.get("Model"):
                result.update(manufacturer=fields.get("Manufacturer") or "Unknown", model=fields["Model"],
                              serial=fields.get("SerialNumber") or "Unavailable", status="Identified", kind="ONVIF camera")
                return result
            if "Credentials" in error or fields.get("Fault") is not None:
                result["status"] = "Credentials required or device information unavailable"
    return result


def scan(selection):
    network = selected_network(selection)
    subnet = ipaddress.ip_network(network["network"])
    neighbours = {}
    for item in _command(["ip", "-j", "neigh", "show", "dev", network["interface"]]):
        try:
            if ipaddress.ip_address(item.get("dst", "")) in subnet and item.get("lladdr"):
                neighbours[item["dst"]] = item
        except ValueError:
            pass
    cameras = discovery(network)
    username, password = credentials()
    deadline = time.monotonic() + 90
    targets = [str(ip) for ip in subnet.hosts() if str(ip) != network["address"]]
    started = datetime.now(timezone.utc).isoformat()
    # Runs inside the short-lived operator helper, never the watchdog core.
    with ThreadPoolExecutor(max_workers=16) as workers:
        rows = workers.map(lambda ip: inspect_device(ip, network["interface"], neighbours.get(ip, {}),
                           ip in cameras, username, password, deadline), targets)
        devices = [row for row in rows if row is not None]
    devices.sort(key=lambda row: ipaddress.ip_address(row["ip"]))
    value = {"state": "complete", "started_at": started, "checked_at": datetime.now(timezone.utc).isoformat(),
             "network": network["label"], "devices": devices, "partial": time.monotonic() >= deadline,
             "note": "Read-only scan. Silent devices, separate VLANs and NVR-private networks may not appear. Model is the device-reported model, not a guaranteed ordering part number."}
    _write(STATE, value)
    return value
