"""Bounded MIME framing for ISAPI alertStream; media parts are discarded."""
import re
from email.message import Message


class AlertParts:
    def __init__(self, content_type):
        message = Message()
        message["content-type"] = content_type
        boundary = message.get_param("boundary")
        if not boundary or not re.fullmatch(r"[\x21-\x7e]{1,100}", boundary):
            raise ValueError("Camera did not return a multipart event stream")
        self.boundary = b"--" + boundary.encode("ascii")
        self.buffer = b""
        self.state = "boundary"
        self.remaining = None
        self.keep = False
        self.payload = bytearray()
        self.limit = 256 * 1024

    def feed(self, chunk):
        self.buffer += chunk
        result = []
        while True:
            if self.state == "boundary":
                index = self.buffer.find(self.boundary)
                if index < 0:
                    self.buffer = self.buffer[-len(self.boundary):]
                    break
                end = self.buffer.find(b"\n", index + len(self.boundary))
                if end < 0:
                    if len(self.buffer) > 8192:
                        raise ValueError("Event boundary line exceeds limit")
                    break
                self.buffer = self.buffer[end + 1:]
                self.state = "headers"
            elif self.state == "headers":
                match = re.search(br"\r?\n\r?\n", self.buffer)
                if not match:
                    if len(self.buffer) > 8192:
                        raise ValueError("Event MIME headers exceed limit")
                    break
                headers = {}
                for line in self.buffer[:match.start()].splitlines():
                    key, _, value = line.partition(b":")
                    headers[key.lower().strip()] = value.strip()
                self.buffer = self.buffer[match.end():]
                kind = headers.get(b"content-type", b"").lower().split(b";", 1)[0]
                self.keep = kind in {b"application/xml", b"text/xml", b"application/json"}
                length = headers.get(b"content-length")
                self.remaining = int(length) if length is not None else None
                if self.remaining is not None and self.remaining < 0:
                    raise ValueError("Negative MIME length")
                self.payload.clear()
                self.state = "body"
            else:
                if self.remaining is not None:
                    size = min(len(self.buffer), self.remaining)
                    data, self.buffer = self.buffer[:size], self.buffer[size:]
                    self.remaining -= size
                    complete = self.remaining == 0
                else:
                    index = self.buffer.find(b"\n" + self.boundary)
                    complete = index >= 0
                    size = index if complete else max(0, len(self.buffer) - len(self.boundary) - 3)
                    data, self.buffer = self.buffer[:size], self.buffer[size:]
                if self.keep:
                    if len(self.payload) + len(data) > self.limit:
                        raise ValueError("Event data exceeds limit")
                    self.payload.extend(data)
                if complete:
                    if self.keep:
                        result.append(bytes(self.payload).rstrip(b"\r\n"))
                    self.payload.clear()
                    self.state = "boundary"
                else:
                    break
        return result
