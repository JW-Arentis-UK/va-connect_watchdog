"""Bounded tail reads shared by routine log consumers."""
from pathlib import Path


def tail_lines(path, limit=100, max_bytes=1024 * 1024):
    try:
        with Path(path).open('rb') as handle:
            handle.seek(0, 2)
            position = handle.tell()
            data = b''
            while position and data.count(b'\n') <= limit and len(data) < max_bytes:
                size = min(position, 16384, max_bytes - len(data))
                position -= size
                handle.seek(position)
                data = handle.read(size) + data
            lines = data.splitlines()
            if position and lines:
                lines = lines[1:]
            return [line.decode('utf-8', errors='replace') for line in lines[-max(1, limit):]]
    except OSError:
        return []
