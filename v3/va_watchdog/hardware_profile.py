from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any


DEFAULT_DMI_ROOT = Path("/sys/class/dmi/id")

# Stamford's older BIOS identifies a physically verified POC-451VTC only by its
# POC-400 family. Keep this fingerprint exact so other POC-400 models stay blocked.
LEGACY_POC451_DMI = {
    "manufacturer": "Neousys Technology Inc.",
    "model": "POC-400 Series",
    "version": "Rev. ES2",
    "board_vendor": "Neousys Technology Inc.",
    "board": "POC-400 Series",
    "board_version": "Rev. ES2",
    "bios_version": "Build220614",
    "bios_date": "06/14/2022",
}


def hardware_identity(dmi_root: Path = DEFAULT_DMI_ROOT) -> dict[str, Any]:
    """Return raw DMI details plus the reviewed VA-Connect hardware profile."""
    identity: dict[str, Any] = {
        "manufacturer": _read_text(dmi_root / "sys_vendor"),
        "model": _read_text(dmi_root / "product_name"),
        "version": _read_text(dmi_root / "product_version"),
        "board_vendor": _read_text(dmi_root / "board_vendor"),
        "board": _read_text(dmi_root / "board_name"),
        "board_version": _read_text(dmi_root / "board_version"),
        "bios_version": _read_text(dmi_root / "bios_version"),
        "bios_date": _read_text(dmi_root / "bios_date"),
    }
    identity.update(_classify(identity))
    return identity


def _classify(identity: dict[str, Any]) -> dict[str, Any]:
    manufacturer = str(identity.get("manufacturer") or "")
    reported_model = str(identity.get("model") or "")
    if "neousys" in manufacturer.casefold() and "poc-451vtc" in reported_model.casefold():
        return {
            "display_model": "POC-451VTC",
            "model_note": "Exact model reported by BIOS",
            "wdt_supported": True,
            "wdt_support_reason": "reviewed POC-451VTC DMI model",
        }

    if all(
        str(identity.get(key) or "").casefold() == expected.casefold()
        for key, expected in LEGACY_POC451_DMI.items()
    ):
        return {
            "display_model": "POC-451VTC",
            "model_note": "Legacy BIOS reports POC-400 Series",
            "wdt_supported": True,
            "wdt_support_reason": "reviewed POC-451VTC legacy BIOS fingerprint Build220614",
        }

    return {
        "display_model": reported_model,
        "model_note": "Model reported by BIOS" if reported_model else "Hardware model unavailable",
        "wdt_supported": False,
        "wdt_support_reason": f"unsupported DMI hardware profile: {reported_model or 'unknown model'}",
    }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the reviewed Neousys WDT_DIO hardware profile")
    parser.add_argument("--dmi-root", type=Path, default=DEFAULT_DMI_ROOT)
    args = parser.parse_args()
    identity = hardware_identity(args.dmi_root)
    print(str(identity["wdt_support_reason"]))
    return 0 if identity["wdt_supported"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
