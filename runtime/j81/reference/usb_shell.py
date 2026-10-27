"""USB-shell transport copied from the hardware-confirmed J81 graphics helper.
Original run-graphics.py SHA256 b2845a6e38ef1b32e3fe1c408bede19d747911fb26b605cae39c4a642ca5ede1.
Only the bounded TelnetDecoder and IPadShell classes are retained. No desktop code.
"""
import re
import secrets
import socket
import time

IPAD = "172.16.42.1"
MAC = "172.16.42.2"

class TelnetDecoder:
    """Small bounded RFC854 decoder; no terminal escape interpretation."""
    def __init__(self):
        self.state = "data"
        self.negotiation = None

    def feed(self, data):
        plain, reply = bytearray(), bytearray()
        for byte in data:
            if self.state == "data":
                if byte == 255:
                    self.state = "iac"
                else:
                    plain.append(byte)
            elif self.state == "iac":
                if byte == 255:
                    plain.append(255)
                    self.state = "data"
                elif byte in (251, 252, 253, 254):
                    self.negotiation = byte
                    self.state = "option"
                elif byte == 250:
                    self.state = "sub"
                else:
                    self.state = "data"
            elif self.state == "option":
                if self.negotiation == 251:  # WILL: accept echo and suppress-GA only.
                    reply.extend((255, 253 if byte in (1, 3) else 254, byte))
                elif self.negotiation == 253:  # DO: client has no optional features.
                    reply.extend((255, 252, byte))
                self.state = "data"
            elif self.state == "sub":
                if byte == 255:
                    self.state = "sub-iac"
            elif self.state == "sub-iac":
                self.state = "data" if byte == 240 else "sub"
        return bytes(plain), bytes(reply)


class IPadShell:
    def __init__(self):
        self.sock = socket.create_connection((IPAD, 23), timeout=6, source_address=(MAC, 0))
        self.sock.settimeout(1)
        self.decoder = TelnetDecoder()
        self.buffer = bytearray()
        try:
            self._until(re.compile(rb"j81-ram# "), 8)
        except BaseException:
            self.sock.close()
            raise

    def _until(self, pattern, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            match = pattern.search(self.buffer)
            if match:
                result = bytes(self.buffer[:match.start()])
                groups = match.groups()
                del self.buffer[:match.end()]
                return result, groups
            if len(self.buffer) > 1024 * 1024:
                raise RuntimeError("iPad command output exceeded its limit")
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not data:
                raise ConnectionError("The iPad USB shell disconnected")
            plain, reply = self.decoder.feed(data)
            if reply:
                self.sock.sendall(reply)
            self.buffer.extend(plain.replace(b"\r\x00", b"\r"))
        raise TimeoutError("The iPad command did not finish in time")

    def run(self, command, seconds=20, check=True):
        marker = "J81_DONE_" + secrets.token_hex(12)
        # A subshell prevents an expected `exit` from closing the control shell.
        script = "(\n" + command + "\n); j81_rc=$?; printf '\\n" + marker + ":%s\\n' \"$j81_rc\"\n"
        self.sock.sendall(script.encode().replace(b"\xff", b"\xff\xff"))
        pattern = re.compile(rb"\r?\n" + marker.encode() + rb":([0-9]+)\r?\n")
        raw, groups = self._until(pattern, seconds)
        code = int(groups[0])
        output = raw.decode("utf-8", "replace").replace("\r", "")
        # Echoed command text can contain harmless download capabilities; never log it.
        lines = output.splitlines()
        last_echo = next((i for i in range(len(lines)-1, -1, -1) if marker in lines[i]), -1)
        if last_echo >= 0:
            output = "\n".join(lines[last_echo+1:]).strip()
        if check and code:
            # New diagnostics may contain private OTP/ADT data. Never attach
            # command output to a user-facing exception.
            raise RuntimeError(f"The private iPad diagnostic failed (status {code}).")
        return output, code

    def close(self):
        try:
            self.sock.sendall(b"exit\n")
        except OSError:
            pass
        self.sock.close()


