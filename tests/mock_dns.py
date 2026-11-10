"""Minimal scriptable DNS server used by blockcheck's tests (stdlib only).

A scenario is a dict mapping a query name to (kind, value):

    ("A", "1.2.3.4")        answer A / AAAA-less
    ("CNAME", "target")     CNAME, plus an A record for the target
    ("NX", None)            NXDOMAIN
    ("NODATA", None)        NOERROR with an empty answer section
    ("DROP", None)          say nothing at all (timeout)
    ("SERVFAIL", None)      SERVFAIL
    ("REFUSED", None)       REFUSED

Names that are not in the table get ``default``.
"""

import socket
import struct
import threading

RCODE = {"NX": 3, "SERVFAIL": 2, "REFUSED": 5}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna")
    return out + b"\x00"


def read_name(buf, off):
    labels = []
    while True:
        ln = buf[off]
        off += 1
        if ln == 0:
            return ".".join(labels), off
        if ln & 0xC0 == 0xC0:  # compression, only seen in responses
            ptr = struct.unpack("!H", buf[off - 1:off + 1])[0] & 0x3FFF
            name, _ = read_name(buf, ptr)
            labels.append(name)
            return ".".join(labels), off + 1
        labels.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln


class MockDNS:
    def __init__(self, scenario, default=("A", "1.2.3.4")):
        self.scenario = {k.lower(): v for k, v in scenario.items()}
        self.default = default
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries = []
        self._stop = False

    def start(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def address(self):
        return ("127.0.0.1", self.port)

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                reply = self._answer(data)
            except Exception:
                continue
            if reply is None:
                continue
            try:
                self.sock.sendto(reply, addr)
            except OSError:
                return

    def _answer(self, data):
        tid = data[:2]
        name, off = read_name(data, 12)
        qtype, _ = struct.unpack("!HH", data[off:off + 4])
        question = data[12:off + 4]
        self.queries.append((name, qtype))
        kind, value = self.scenario.get(name.lower(), self.default)
        if kind == "DROP":
            return None

        answers, ancount = b"", 0
        if kind == "A" and qtype == 1:
            answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) \
                + socket.inet_aton(value)
            ancount = 1
        elif kind == "CNAME" and qtype in (1, 28):
            rdata = encode_name(value)
            answers = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
            ancount = 1
            if qtype == 1:
                target = self.scenario.get(value.lower(), self.default)
                ip = target[1] if target[0] == "A" else "1.2.3.4"
                answers += encode_name(value) \
                    + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                ancount = 2

        flags = 0x8180 | RCODE.get(kind, 0)
        header = tid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
        return header + question + answers
