"""Bounded syslog collection shared by both support download formats."""
from pathlib import Path


def add_syslogs(archive, cfg, budget=20 * 1024 * 1024):
    manifest = {"included": [], "omitted": [], "missing": []}
    directory = Path(cfg.get("evidence_syslog_dir", "/var/log"))
    remaining = max(0, budget)
    for filename in ("syslog", "syslog.1", "syslog.2.gz", "syslog.3.gz", "syslog.4.gz"):
        path = directory / filename
        name = f"system-logs/{filename}"
        try:
            if path.is_symlink():
                manifest["omitted"].append(name)
                continue
            if not path.is_file():
                manifest["missing"].append(name)
                continue
            size = path.stat().st_size
            allowance = min(4 * 1024 * 1024, remaining)
            if allowance <= 0 or (size > allowance and filename.endswith(".gz")):
                manifest["omitted"].append(name)
                continue
            with path.open("rb") as source:
                if size > allowance:
                    source.seek(size - allowance)
                    source.readline(allowance)  # Skip a partial line without an unbounded read.
                    name += ".tail"
                payload = source.read(allowance + 1)
            if len(payload) > allowance:
                manifest["omitted"].append(name)
                continue
        except OSError:
            manifest["omitted"].append(name)
            continue
        archive.writestr(name, payload)
        remaining -= len(payload)
        manifest["included"].append(name)
    return manifest
