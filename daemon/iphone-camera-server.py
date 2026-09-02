#!/usr/bin/env python3
"""Omarchy iPhone Camera daemon.

Serves a pairing page on HTTP and a Safari camera capture page on HTTPS,
receives JPEG frames over WebSocket, and publishes them as a V4L2 webcam
via ffmpeg + v4l2loopback.

Both listeners bind to this node's Tailscale address only. The iPhone must be
on the same tailnet; the local Wi-Fi network can never reach the ports.

No third-party Python packages. Stdlib + ffmpeg, openssl, qrencode,
idevice_id (optional).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

NAME = "iPhone Camera"
HTTP_PORT = 4747
HTTPS_PORT = 4748
VIDEO_NR = 42
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Pairing model
# -------------
# The QR code carries a one-time pairing code in the URL *fragment*. Safari keeps
# the fragment on the phone, so the plaintext request for the landing page never
# contains a credential. The landing page turns the fragment into an HTTPS-only
# request to /pair, which exchanges the code for a session cookie. Only that
# cookie (Secure, HttpOnly) authenticates the camera page and the WebSocket.
PAIR_TTL = 10 * 60             # a QR code is valid for this long, then a fresh one is issued
SESSION_TTL = 30 * 24 * 3600   # a paired phone stays paired for this long
MAX_SESSIONS = 8               # paired phones remembered at once
SESSION_COOKIE = "ioscam_session"
PAIR_CODE_RE = re.compile(r"[0-9a-f]{32}")
SESSION_RE = re.compile(r"[0-9a-f]{64}")

# Network
# -------
# The daemon listens on this node's Tailscale address only. The Wi-Fi LAN
# cannot reach the ports at all, and both the pairing hop and the video stream
# ride inside WireGuard on top of the daemon's own TLS. The address comes from
# the local tailscaled (via the CLI), must sit in the Tailscale range, and must
# be present on a local interface before we bind to it. If Tailscale is down
# the daemon waits; it never falls back to another interface.
TAILSCALE_NET = ipaddress.IPv4Network("100.64.0.0/10")

PLUGIN_ID = "io.github.boraoku.ioscam"


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    path = Path(base) / "omarchy-iphone-camera"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local/state")
    path = Path(base) / "omarchy-iphone-camera"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local/share")
    path = Path(base) / "omarchy-iphone-camera"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def plugin_root() -> Path:
    return Path(__file__).resolve().parent.parent


def log(msg: str) -> None:
    sys.stderr.write(f"iphone-camera: {msg}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class App:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.running = True
        self.stop_event = threading.Event()
        self.streaming = False
        self.paired = False
        self.camera = "back"
        self.device = ""
        self.fps = 0.0
        self.width = 0
        self.height = 0
        self.error = ""
        self.phone_name = ""
        self.frames = 0
        self._fps_mark = time.monotonic()
        self._fps_count = 0
        self.ffmpeg: subprocess.Popen[bytes] | None = None
        self.ws_conn: socket.socket | None = None
        self.conns: set[socket.socket] = set()   # every open client socket, closed at shutdown
        self.latest_jpeg: bytes | None = None
        self.preview_slot = 0
        self.pair_code = ""
        self.pair_expires = 0.0
        self.sessions: dict[str, dict] = {}
        self.bind_ip = ""          # tailnet address the listeners are bound to, "" until bound
        self.tailscale_ip = ""
        # Earlier versions kept one reusable token here; it is obsolete.
        (state_dir() / "token").unlink(missing_ok=True)
        self._load_sessions()
        self._new_pair_code()
        self.preview_path = runtime_dir() / "preview-0.jpg"
        self.qr_path = runtime_dir() / "qr.png"
        self.qr_url = ""
        self.status_path = runtime_dir() / "status.json"
        self.ctl_path = runtime_dir() / "ctl.sock"
        self.pid_path = runtime_dir() / "server.pid"
        self.ca_dir = data_dir() / "ca"
        self.ca_dir.mkdir(mode=0o700, exist_ok=True)

    # -- one-time pairing code -------------------------------------------

    def _new_pair_code(self) -> None:
        self.pair_code = secrets.token_hex(16)
        self.pair_expires = time.time() + PAIR_TTL

    def refresh_pair_code(self) -> bool:
        """Issue a fresh code once the current one has expired. True if it changed."""
        with self.lock:
            if time.time() < self.pair_expires:
                return False
            self._new_pair_code()
            return True

    def redeem_pair_code(self, given: str | None, agent: str = "") -> str | None:
        """Exchange a one-time pairing code for a session token, or None if refused."""
        if not given or not PAIR_CODE_RE.fullmatch(given):
            return None
        with self.lock:
            if time.time() >= self.pair_expires or not hmac.compare_digest(given, self.pair_code):
                return None
            # Single use: burn the code so a photo of the QR cannot be replayed.
            self._new_pair_code()
            token = secrets.token_hex(32)
            self.sessions[token] = {"created": int(time.time()), "agent": agent[:120]}
            while len(self.sessions) > MAX_SESSIONS:
                oldest = min(self.sessions, key=lambda t: self.sessions[t]["created"])
                del self.sessions[oldest]
            self._save_sessions()
        return token

    # -- paired sessions ---------------------------------------------------

    def session_ok(self, given: str | None) -> bool:
        if not given or not SESSION_RE.fullmatch(given):
            return False
        now = time.time()
        ok = False
        with self.lock:
            for token, meta in list(self.sessions.items()):
                if now - meta.get("created", 0) > SESSION_TTL:
                    del self.sessions[token]
                    continue
                if hmac.compare_digest(given, token):
                    ok = True
        return ok

    def rotate_token(self) -> None:
        """Panel action "New pairing code": forget every paired phone, issue a new code."""
        with self.lock:
            self.sessions.clear()
            self._save_sessions()
            self._new_pair_code()
            self.paired = False
        _close_stream("Pairing reset", notify="reset")
        publish()

    def _sessions_path(self) -> Path:
        return state_dir() / "sessions.json"

    def _load_sessions(self) -> None:
        path = self._sessions_path()
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except (OSError, json.JSONDecodeError):
            data = {}
        if not isinstance(data, dict):
            return
        now = time.time()
        for token, meta in data.items():
            if not (isinstance(token, str) and SESSION_RE.fullmatch(token) and isinstance(meta, dict)):
                continue
            created = meta.get("created")
            if isinstance(created, int) and now - created <= SESSION_TTL:
                self.sessions[token] = {"created": created, "agent": str(meta.get("agent") or "")[:120]}

    def _save_sessions(self) -> None:
        path = self._sessions_path()
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.sessions) + "\n")
        tmp.chmod(0o600)
        tmp.replace(path)


APP = App()


def find_loopback() -> str:
    try:
        out = subprocess.check_output(["v4l2-ctl", "--list-devices"], text=True, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.CalledProcessError):
        out = ""
    current = None
    for line in out.splitlines():
        if not line.startswith("\t") and line.strip().endswith(":"):
            current = line.strip()[:-1]
        elif current and "iPhone Camera" in current:
            m = re.search(r"(/dev/video\d+)", line)
            if m:
                return m.group(1)
    # Fallback: sysfs card labels
    for node in sorted(Path("/sys/class/video4linux").glob("video*")):
        name = (node / "name").read_text().strip() if (node / "name").exists() else ""
        if name == NAME:
            return f"/dev/{node.name}"
    return ""


def iface_addrs() -> list[tuple[str, str]]:
    """(interface, IPv4) pairs currently configured on this host."""
    pairs: list[tuple[str, str]] = []
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "scope", "global"], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return pairs
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface, cidr = parts[1], parts[3]
        ip = cidr.split("/")[0]
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        pairs.append((iface, ip))
    return pairs


def tailscale_ip() -> str:
    """This node's IPv4 on the tailnet, or "" when Tailscale is not up.

    The CLI answers from the local tailscaled socket, never from the network.
    The address must be inside 100.64.0.0/10 and actually be configured on a
    local interface, so we never bind to (or advertise) something stale.
    """
    local = {ip for _, ip in iface_addrs()}
    candidates: list[str] = []
    cli = shutil.which("tailscale")
    if cli:
        try:
            out = subprocess.check_output([cli, "ip", "-4"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            candidates += out.split()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    candidates += [ip for iface, ip in iface_addrs() if iface.lower().startswith("tailscale")]
    for cand in candidates:
        try:
            addr = ipaddress.IPv4Address(cand)
        except ipaddress.AddressValueError:
            continue
        if addr in TAILSCALE_NET and str(addr) in local:
            return str(addr)
    return ""


def tailscale_dns() -> str:
    try:
        ts = subprocess.check_output(["tailscale", "status", "--json"], text=True, stderr=subprocess.DEVNULL, timeout=5)
        data = json.loads(ts)
        return str((data.get("Self") or {}).get("DNSName") or "").rstrip(".")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return ""


def advertised() -> list[str]:
    """Hosts the phone may use to reach us: the tailnet IP, then the MagicDNS name.

    Nothing is reachable until the listeners are bound, so this is empty (and
    the panel shows no QR) while we wait for Tailscale.
    """
    ip = APP.tailscale_ip if APP.bind_ip else ""
    if not ip:
        return []
    dns = tailscale_dns()
    return [ip] + ([dns] if dns else [])


def usb_iphone() -> dict:
    info = {"connected": False, "name": ""}
    try:
        udids = subprocess.check_output(["idevice_id", "-l"], text=True, stderr=subprocess.DEVNULL).split()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return info
    if not udids:
        return info
    info["connected"] = True
    try:
        name = subprocess.check_output(
            ["ideviceinfo", "-u", udids[0], "-k", "DeviceName"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        info["name"] = name
    except (FileNotFoundError, subprocess.CalledProcessError):
        info["name"] = "iPhone"
    return info


def pair_urls() -> list[str]:
    # The one-time code rides in the fragment, which the phone never sends to
    # the server, so the plaintext landing-page request carries no secret.
    code = APP.pair_code
    urls: list[str] = []
    for host in advertised():
        url = f"http://{host}:{HTTP_PORT}/#{code}"
        if url not in urls:
            urls.append(url)
    return urls


def public_pair_url() -> str:
    urls = pair_urls()
    return urls[0] if urls else ""


def write_qr(url: str) -> None:
    if url == APP.qr_url and APP.qr_path.exists():
        return
    if not url:
        APP.qr_path.unlink(missing_ok=True)
        APP.qr_url = ""
        return
    qrencode = shutil.which("qrencode")
    if not qrencode:
        return
    tmp = APP.qr_path.with_suffix(".tmp.png")
    try:
        subprocess.run(
            [qrencode, "-o", str(tmp), "-s", "8", "-m", "2", "-t", "PNG", url],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        tmp.replace(APP.qr_path)
        APP.qr_url = url
    except (subprocess.CalledProcessError, OSError):
        if tmp.exists():
            tmp.unlink(missing_ok=True)


PUBLISH_LOCK = threading.Lock()
PREVIEW_LOCK = threading.Lock()


def publish() -> None:
    """Write status.json (and the QR) for the panel.

    Called from the main loop, the control thread, and WebSocket threads.
    Serialized because two writers racing on the same temp file makes one
    rename fail with FileNotFoundError; a failed publish must never take the
    daemon down, so errors are logged and the next tick simply retries.
    """
    with PUBLISH_LOCK:
        try:
            _publish()
        except OSError as e:
            log(f"could not publish status: {e}")


def _publish() -> None:
    APP.refresh_pair_code()
    device = find_loopback()
    phone = usb_iphone()
    ts_ip = tailscale_ip()
    with APP.lock:
        APP.tailscale_ip = ts_ip
        if not APP.bind_ip:
            APP.error = "Tailscale is not connected on this computer. Start it, then the QR code appears."
        elif APP.error.startswith("Tailscale is not connected"):
            APP.error = ""
    urls = pair_urls()
    pair = public_pair_url()
    write_qr(pair)
    with APP.lock:
        APP.device = device
        status = {
            "ok": True,
            "schema": 1,
            "running": True,
            "listening": bool(APP.bind_ip),
            "bindAddr": APP.bind_ip,
            "tailscaleIp": ts_ip,
            "streaming": APP.streaming,
            "paired": APP.paired,
            "camera": APP.camera,
            "device": device,
            "deviceReady": bool(device) and os.access(device, os.W_OK),
            "needsDevice": not bool(device),
            "urls": urls,
            "pairUrl": pair,
            "pairExpires": int(APP.pair_expires),
            "pairedPhones": len(APP.sessions),
            "trustUrl": (pair.split("#")[0] + "ca.mobileconfig") if pair else "",
            "qrPng": str(APP.qr_path) if APP.qr_path.exists() else "",
            "previewJpg": str(APP.preview_path) if APP.preview_path.exists() else "",
            "iphoneUsb": phone["connected"],
            "iphoneName": phone["name"],
            "fps": round(APP.fps, 1),
            "width": APP.width,
            "height": APP.height,
            "httpPort": HTTP_PORT,
            "httpsPort": HTTPS_PORT,
            "error": APP.error,
            "label": NAME,
        }
    path = APP.status_path
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status) + "\n")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def ensure_certs() -> tuple[Path, Path]:
    ca_key = APP.ca_dir / "ca.key"
    ca_crt = APP.ca_dir / "ca.crt"
    server_key = APP.ca_dir / "server.key"
    server_crt = APP.ca_dir / "server.crt"
    san_stamp = APP.ca_dir / "san.txt"

    if not ca_key.exists() or not ca_crt.exists():
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509", "-days", "3650", "-nodes",
                "-newkey", "rsa:2048",
                "-keyout", str(ca_key), "-out", str(ca_crt),
                "-subj", "/CN=Omarchy iPhone Camera CA",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ca_key.chmod(0o600)

    ts_ip = tailscale_ip()
    ts_dns = tailscale_dns()
    san_parts = ([f"IP:{ts_ip}"] if ts_ip else []) + ([f"DNS:{ts_dns}"] if ts_dns else [])
    san_parts += ["IP:127.0.0.1", "DNS:localhost"]
    # Unique, stable order
    seen: set[str] = set()
    san: list[str] = []
    for p in san_parts:
        if p not in seen:
            seen.add(p)
            san.append(p)
    san_line = ",".join(san)
    if san_stamp.exists() and san_stamp.read_text() == san_line and server_crt.exists() and server_key.exists():
        return server_key, server_crt

    ext = APP.ca_dir / "server.ext"
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san_line}\n"
    )
    csr = APP.ca_dir / "server.csr"
    subprocess.run(
        [
            "openssl", "req", "-new", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", str(server_key), "-out", str(csr),
            "-subj", "/CN=omarchy-iphone-camera",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_key.chmod(0o600)
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(server_crt), "-days", "825", "-extfile", str(ext),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    csr.unlink(missing_ok=True)
    san_stamp.write_text(san_line)
    return server_key, server_crt


def ca_der_b64() -> str:
    ca_crt = APP.ca_dir / "ca.crt"
    der = subprocess.check_output(["openssl", "x509", "-in", str(ca_crt), "-outform", "DER"])
    return base64.encodebytes(der).decode("ascii")


def mobileconfig() -> bytes:
    payload_uuid = "7e2c1f80-3b6a-4d4e-9c3a-a1b2c3d4e5f6"
    ca_uuid = "8f3d2e91-4c7b-5e6f-0d1a-b2c3d4e5f607"
    b64 = ca_der_b64()
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>omarchy-iphone-camera.cer</string>
      <key>PayloadContent</key>
      <data>
{b64}      </data>
      <key>PayloadDescription</key>
      <string>Trust this computer so Safari can use the iPhone camera as a webcam.</string>
      <key>PayloadDisplayName</key>
      <string>Omarchy iPhone Camera</string>
      <key>PayloadIdentifier</key>
      <string>org.omarchy.iphone-camera.ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{ca_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>One-time trust profile for using this iPhone as a webcam on Omarchy.</string>
  <key>PayloadDisplayName</key>
  <string>Omarchy iPhone Camera</string>
  <key>PayloadIdentifier</key>
  <string>org.omarchy.iphone-camera</string>
  <key>PayloadOrganization</key>
  <string>Omarchy</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{payload_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""
    return xml.encode("utf-8")


# ---------------------------------------------------------------------------
# ffmpeg / v4l2
# ---------------------------------------------------------------------------

def start_ffmpeg(device: str) -> subprocess.Popen[bytes] | None:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg or not device:
        return None
    # Constant 24 fps, constant size: v4l2loopback flickers when the producer
    # starves or renegotiates format between frames.
    cmd = [
        ffmpeg, "-hide_banner", "-loglevel", "error",
        "-fflags", "nobuffer+genpts", "-flags", "low_delay",
        "-probesize", "32", "-analyzeduration", "0",
        "-use_wallclock_as_timestamps", "1",
        "-f", "mjpeg", "-framerate", "24", "-i", "pipe:0",
        "-vf", "scale=1280:720:force_original_aspect_ratio=increase,crop=1280:720,format=yuv420p",
        "-pix_fmt", "yuv420p", "-r", "24",
        "-f", "v4l2", device,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        log(f"ffmpeg failed to start: {e}")
        return None
    return proc


def feed_loop() -> None:
    interval = 1.0 / 24.0
    nxt = time.monotonic()
    while APP.running:
        jpeg = None
        with APP.lock:
            jpeg = APP.latest_jpeg
            proc = APP.ffmpeg
            device = APP.device or find_loopback()
            APP.device = device
        if jpeg and device:
            if not proc or proc.poll() is not None:
                proc = start_ffmpeg(device)
                APP.ffmpeg = proc
            if proc and proc.stdin:
                try:
                    proc.stdin.write(jpeg)
                    proc.stdin.flush()
                except BrokenPipeError:
                    stop_ffmpeg()
        nxt += interval
        delay = nxt - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            nxt = time.monotonic()


def stop_ffmpeg() -> None:
    proc = APP.ffmpeg
    APP.ffmpeg = None
    if not proc:
        return
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass


def _close_sock(sock: socket.socket | None) -> None:
    """Tear down a socket another thread may be blocked reading.

    close() alone does not wake a blocked recv() on Linux; shutdown() does, so
    the WebSocket thread exits promptly instead of waiting out its timeout.
    """
    if not sock:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


WS_CLOSE_STOPPED = 4000   # private close code: "the computer ended this stream on purpose"


def _close_stream(reason: str = "", notify: str | None = None) -> None:
    """Drop the live stream.

    `notify` names why, for the phone: "stop", "reset" or "shutdown". The page
    then stops the camera and tells the user instead of reconnecting. Pass
    None (e.g. for an in-place restart) to let the phone reconnect on its own.
    """
    with APP.lock:
        APP.streaming = False
        APP.fps = 0.0
        APP.latest_jpeg = None
        sock = APP.ws_conn
        APP.ws_conn = None
    stop_ffmpeg()
    if sock and notify:
        try:
            sock.settimeout(1.0)
            send_ws(sock, 0x1, json.dumps({"type": "stop", "reason": notify}).encode())
            send_ws(sock, 0x8, WS_CLOSE_STOPPED.to_bytes(2, "big") + notify.encode())
        except OSError:
            pass
    _close_sock(sock)
    if reason:
        log(reason)


def write_preview(jpeg: bytes) -> None:
    # Two WebSocket threads can overlap briefly while one displaces the other.
    with PREVIEW_LOCK:
        slot = 1 - APP.preview_slot
        path = runtime_dir() / f"preview-{slot}.jpg"
        tmp = path.with_suffix(".tmp.jpg")
        try:
            tmp.write_bytes(jpeg)
            tmp.replace(path)
        except OSError:
            return
        with APP.lock:
            APP.preview_slot = slot
            APP.preview_path = path


def push_frame(jpeg: bytes) -> None:
    if len(jpeg) < 20 or jpeg[:2] != b"\xff\xd8":
        return
    now = time.monotonic()
    with APP.lock:
        APP.latest_jpeg = jpeg
        APP._fps_count += 1
        APP.frames += 1
        elapsed = now - APP._fps_mark
        if elapsed >= 1.0:
            APP.fps = APP._fps_count / elapsed
            APP._fps_count = 0
            APP._fps_mark = now
    write_preview(jpeg)


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

def ws_accept(key: str) -> str:
    digest = hashlib.sha1((key + WS_MAGIC).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def read_ws_message(sock: socket.socket) -> tuple[int, bytes]:
    payload = bytearray()
    opcode = None
    while True:
        header = recv_exact(sock, 2)
        fin = header[0] & 0x80
        op = header[0] & 0x0F
        masked = header[1] & 0x80
        length = header[1] & 0x7F
        if length == 126:
            length = int.from_bytes(recv_exact(sock, 2), "big")
        elif length == 127:
            length = int.from_bytes(recv_exact(sock, 8), "big")
        if length > 8_000_000:
            raise ConnectionError("frame too large")
        mask = recv_exact(sock, 4) if masked else b""
        data = recv_exact(sock, length) if length else b""
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if op in (0x8, 0x9, 0xA):
            return op, data
        if opcode is None:
            opcode = op
        payload.extend(data)
        if fin:
            return opcode or 0, bytes(payload)


def send_ws(sock: socket.socket, opcode: int, data: bytes) -> None:
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    n = len(data)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(n.to_bytes(8, "big"))
    sock.sendall(header + data)


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

def load_camera_html() -> bytes:
    path = plugin_root() / "web" / "index.html"
    if path.exists():
        return path.read_bytes()
    return b"<h1>Missing web/index.html</h1>"


PAGE_STYLE = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100dvh; font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    background: #111; color: #f2f2f2; padding: 28px 22px 48px;
  }
  h1 { font-size: 1.6rem; margin: 0 0 8px; }
  p, li { color: #bdbdbd; line-height: 1.45; }
  ol { padding-left: 1.2em; }
  a.btn, button {
    display: block; width: 100%; text-align: center; text-decoration: none;
    background: #f2f2f2; color: #111; border: 0; border-radius: 14px;
    padding: 16px 18px; font-size: 1.05rem; font-weight: 650; margin: 14px 0;
  }
  a.secondary { background: #2a2a2a; color: #f2f2f2; }
  .note { font-size: .9rem; color: #8a8a8a; }
  .warn { color: #ffb4b4; }
  [hidden] { display: none !important; }
"""


def denied_html(message: str) -> bytes:
    safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>iPhone Camera</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
  <h1>Not paired</h1>
  <p class="warn">{safe}</p>
  <p class="note">Open the camera panel in the Omarchy bar and scan the QR code with the iPhone camera.</p>
</body>
</html>
""".encode("utf-8")


def landing_html() -> bytes:
    # Served over plaintext HTTP, so this page must not contain any secret.
    # The pairing code lives in the URL fragment and is read on the phone only.
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="referrer" content="no-referrer">
<title>iPhone Camera</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
  <h1>Use this iPhone as a webcam</h1>
  <p id="missing" class="warn" hidden>This link has no pairing code. Open the camera panel in the Omarchy bar and scan the QR code again.</p>
  <p>First time on this phone, install the trust profile so Safari can open the camera. Then start the back camera.</p>
  <ol>
    <li>Tap <b>Install trust profile</b>, then Allow / Install.</li>
    <li>Open <b>Settings → General → About → Certificate Trust Settings</b> and enable <b>Omarchy iPhone Camera</b>.</li>
    <li>Come back and tap <b>Open camera</b>. Allow camera access. Keep this page in the foreground.</li>
  </ol>
  <a class="btn secondary" href="/ca.mobileconfig">Install trust profile</a>
  <a id="open" class="btn" href="#">Open camera</a>
  <p class="note">The back camera is used by default, the same way Continuity Camera does on a Mac. Pick <b>iPhone Camera</b> in Zoom, Meet, OBS, or any app.</p>
<script>
(() => {{
  const code = (location.hash || "").replace(/^#/, "");
  const open = document.getElementById("open");
  if (/^[0-9a-f]{{32}}$/.test(code)) {{
    open.href = "https://" + location.hostname + ":{HTTPS_PORT}/pair?p=" + code;
  }} else {{
    open.hidden = true;
    document.getElementById("missing").hidden = false;
  }}
}})();
</script>
</body>
</html>
""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    https = False
    # Idle keep-alive connections must not pin a request thread forever, or
    # the joined shutdown below would hang on them.
    timeout = 30

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def setup(self) -> None:
        super().setup()
        with APP.lock:
            APP.conns.add(self.connection)

    def finish(self) -> None:
        with APP.lock:
            APP.conns.discard(self.connection)
        try:
            super().finish()
        except OSError:
            pass

    def _session_cookie(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name.strip() == SESSION_COOKIE:
                return value.strip()
        return ""

    def _paired(self) -> bool:
        return self.https and APP.session_ok(self._session_cookie())

    def _html(self, code: int, body: bytes, extra: list[tuple[str, str]] | None = None) -> None:
        self._send(code, body, "text/html; charset=utf-8", extra)

    def _send(self, code: int, body: bytes, content_type: str, extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra or []:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._websocket()
            return
        if path in ("/ca.mobileconfig", "/ca.pem", "/ca.crt"):
            if path == "/ca.mobileconfig":
                body = mobileconfig()
                self._send(
                    200,
                    body,
                    "application/x-apple-aspen-config",
                    [("Content-Disposition", 'attachment; filename="omarchy-iphone-camera.mobileconfig"')],
                )
            else:
                self._send(200, (APP.ca_dir / "ca.crt").read_bytes(), "application/x-pem-file")
            return
        if path == "/pair":
            self._pair(parse_qs(parsed.query))
            return
        if path in ("/", "/index.html"):
            if not self.https:
                self._html(200, landing_html())
            elif self._paired():
                self._html(200, load_camera_html())
            else:
                self._html(403, denied_html("This phone is not paired with the computer, or the pairing was reset."))
            return
        self._send(404, b"not found", "text/plain")

    def _pair(self, query: dict[str, list[str]]) -> None:
        if not self.https:
            # Never accept, or burn, a pairing code over plaintext.
            self._html(403, denied_html("Pairing only works over the secure link."))
            return
        code = (query.get("p") or [""])[0]
        token = APP.redeem_pair_code(code, self.headers.get("User-Agent", ""))
        if not token:
            self._html(403, denied_html("This pairing code has expired or was already used."))
            return
        log("iPhone paired")
        publish()
        cookie = f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"
        self._send(303, b"", "text/plain", [("Location", "/"), ("Set-Cookie", cookie)])

    def _websocket(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/ws":
            self._send(404, b"not found", "text/plain")
            return
        if not self.https:
            self._send(403, b"websocket requires https", "text/plain")
            return
        if not self._paired():
            self._send(403, b"not paired", "text/plain")
            return
        # Same-origin only: a page from another site must not drive the camera
        # with this phone's cookie (Safari sends Origin on every WS handshake).
        origin = self.headers.get("Origin", "").strip().lower()
        host = self.headers.get("Host", "").strip().lower()
        if not host or origin != f"https://{host}":
            self._send(403, b"bad origin", "text/plain")
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self._send(400, b"missing key", "text/plain")
            return
        self.close_connection = True
        accept = ws_accept(key)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        sock = self.connection
        sock.settimeout(60)
        with APP.lock:
            old = APP.ws_conn
            APP.ws_conn = sock
            APP.paired = True
            APP.streaming = True
            APP.error = ""
        if old and old is not sock:
            _close_sock(old)
        log("iPhone connected")
        publish()
        try:
            send_ws(sock, 0x1, b'{"type":"ok","camera":"back"}')
            while APP.running:
                try:
                    op, data = read_ws_message(sock)
                except socket.timeout:
                    send_ws(sock, 0x9, b"")
                    continue
                if op == 0x8:
                    break
                if op == 0x9:
                    send_ws(sock, 0xA, data)
                    continue
                if op == 0xA:
                    continue
                if op == 0x1:
                    try:
                        msg = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if msg.get("type") == "hello":
                        with APP.lock:
                            APP.camera = str(msg.get("camera") or "back")
                            APP.width = int(msg.get("width") or 0)
                            APP.height = int(msg.get("height") or 0)
                        publish()
                    continue
                if op == 0x2:
                    push_frame(data)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            with APP.lock:
                if APP.ws_conn is sock:
                    APP.ws_conn = None
                    APP.streaming = False
                    APP.fps = 0.0
            stop_ffmpeg()
            log("iPhone disconnected")
            publish()


class HTTPSHandler(Handler):
    https = True


class HTTPHandler(Handler):
    https = False


class Server(ThreadingHTTPServer):
    # Request threads are joined by server_close(). Daemon threads that are
    # still writing to stderr while the interpreter finalizes make CPython
    # abort ("could not acquire lock for <stderr> at interpreter shutdown").
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def handle_error(self, request: object, client_address: object) -> None:
        # socketserver reports handler exceptions here (not on the handler),
        # printing a traceback to stderr by default. Dropped connections are
        # routine; log anything else in one line.
        err = sys.exception()
        if isinstance(err, (ConnectionError, TimeoutError, ssl.SSLError, OSError)):
            return
        peer = client_address[0] if isinstance(client_address, tuple) and client_address else "?"
        log(f"request from {peer} failed: {err!r}")


# ---------------------------------------------------------------------------
# Control socket
# ---------------------------------------------------------------------------

def handle_ctl(raw: str) -> dict:
    try:
        msg = json.loads(raw) if raw.strip() else {"cmd": "status"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad json"}
    cmd = str(msg.get("cmd") or "")
    if cmd in ("status", ""):
        publish()
        return json.loads(APP.status_path.read_text()) if APP.status_path.exists() else {"ok": True}
    if cmd in ("rotate-token", "new-token"):
        APP.rotate_token()
        return json.loads(APP.status_path.read_text())
    if cmd == "stop-stream":
        _close_stream("stop-stream", notify="stop")
        publish()
        return {"ok": True}
    if cmd == "shutdown":
        APP.running = False
        threading.Thread(target=lambda: (time.sleep(0.2), os.kill(os.getpid(), signal.SIGTERM)), daemon=True).start()
        return {"ok": True}
    return {"ok": False, "error": f"unknown cmd {cmd}"}


def schedule_reexec(reason: str) -> None:
    """Restart in place (same PID, same systemd unit) so the listeners rebind.

    Runs on a short delay so the control reply gets out first. Sockets are
    non-inheritable, so the old listeners die with the exec.
    """
    def go() -> None:
        time.sleep(0.3)
        _close_stream(f"restarting: {reason}")
        sys.stderr.flush()
        script = sys.argv[0] if sys.argv and os.path.isfile(sys.argv[0]) else str(Path(__file__).resolve())
        os.execv(sys.executable, [sys.executable, script, *sys.argv[1:]])

    threading.Thread(target=go, name="reexec", daemon=True).start()


def ctl_server() -> None:
    path = APP.ctl_path
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(8)
    sock.settimeout(1.0)
    while APP.running:
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            try:
                data = conn.recv(65536).decode("utf-8", "replace")
                reply = handle_ctl(data)
                conn.sendall((json.dumps(reply) + "\n").encode())
            except OSError:
                pass
    try:
        sock.close()
        path.unlink(missing_ok=True)
    except OSError:
        pass


def ctl_client(cmd: str) -> int:
    path = runtime_dir() / "ctl.sock"
    if not path.exists():
        sys.stderr.write("iphone-camera: daemon is not running\n")
        return 1
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(path))
        sock.sendall((json.dumps({"cmd": cmd}) + "\n").encode())
        print(sock.makefile().read(), end="")
    finally:
        sock.close()
    return 0


# ---------------------------------------------------------------------------
# systemd user unit
# ---------------------------------------------------------------------------

def install_user_unit() -> Path:
    unit_dir = Path.home() / ".config/systemd/user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit = unit_dir / "omarchy-iphone-camera.service"
    script = Path(__file__).resolve()
    unit.write_text(
        f"""[Unit]
Description=Omarchy iPhone Camera daemon
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {script} serve
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"""
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    return unit


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def already_running() -> bool:
    pid_path = runtime_dir() / "server.pid"
    if not pid_path.exists():
        return False
    try:
        pid = int(pid_path.read_text().strip())
    except ValueError:
        return False
    if pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # Confirm it is us via the ctl socket
    return (runtime_dir() / "ctl.sock").exists()


def serve() -> int:
    if already_running():
        log("already running")
        return 0
    APP.pid_path.write_text(str(os.getpid()) + "\n")

    def stop(*_args: object) -> None:
        # Only flag the exit here; the main thread does the orderly teardown.
        APP.running = False
        APP.stop_event.set()

    servers: list[Server] = []
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    # The control socket comes up first so the panel can talk to us (status,
    # reset, shutdown) even while we are waiting for Tailscale below.
    threading.Thread(target=ctl_server, name="ctl", daemon=True).start()

    # Fail closed: never bind to another interface. Wait until the tailnet
    # address exists on this host, publishing the reason meanwhile.
    bind = ""
    while APP.running:
        bind = tailscale_ip()
        if bind:
            break
        publish()
        APP.stop_event.wait(3)
    if not APP.running:
        APP.status_path.unlink(missing_ok=True)
        APP.pid_path.unlink(missing_ok=True)
        return 0
    # The certificate must name the address we are about to serve on.
    try:
        server_key, server_crt = ensure_certs()
    except subprocess.CalledProcessError as e:
        log(f"could not create TLS certificates: {e}")
        return 1

    try:
        httpd = Server((bind, HTTP_PORT), HTTPHandler)
        httpsd = Server((bind, HTTPS_PORT), HTTPSHandler)
    except OSError as e:
        log(f"could not listen on {bind}: {e}")
        return 1
    servers[:] = [httpd, httpsd]
    with APP.lock:
        APP.bind_ip = bind
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(server_crt), str(server_key))
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)

    feed = threading.Thread(target=feed_loop, name="feed", daemon=True)
    feed.start()
    for srv, name in ((httpd, "http"), (httpsd, "https")):
        threading.Thread(target=srv.serve_forever, name=name, daemon=True).start()

    publish()
    log(f"listening on http://{bind}:{HTTP_PORT} and https://{bind}:{HTTPS_PORT} (tailnet only)")
    log(f"pair at {public_pair_url().split('#')[0]} (code shown in the bar panel)")

    while APP.running:
        if APP.stop_event.wait(2.5):
            break
        try:
            publish()
            # Tailscale went away or moved: the bound address is dead. Restart
            # so we go back to waiting for the tailnet rather than serving
            # nothing. The restart also re-issues the certificate.
            if APP.tailscale_ip != bind:
                schedule_reexec("tailscale address changed")
                APP.stop_event.wait(5)
        except Exception as e:  # noqa: BLE001 - the main loop must not die
            log(f"main loop error: {e!r}")

    # Orderly teardown, all from this thread: drop the stream (which wakes the
    # WebSocket thread), stop accepting, then join every request thread so
    # none is still running when the interpreter finalizes.
    _close_stream("shutdown", notify="shutdown")
    for srv in servers:
        srv.shutdown()          # stop accepting
    with APP.lock:
        conns = list(APP.conns)
    for conn in conns:          # wake every request thread still blocked on a client
        _close_sock(conn)
    for srv in servers:
        srv.server_close()      # join request threads
    feed.join(timeout=2)
    APP.status_path.unlink(missing_ok=True)
    APP.pid_path.unlink(missing_ok=True)
    APP.ctl_path.unlink(missing_ok=True)
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd in ("serve", "run", "daemon"):
        return serve()
    if cmd == "install-unit":
        path = install_user_unit()
        print(path)
        return 0
    if cmd == "ctl":
        return ctl_client(argv[2] if len(argv) > 2 else "status")
    if cmd == "status":
        if (runtime_dir() / "ctl.sock").exists():
            return ctl_client("status")
        print(json.dumps({"ok": True, "running": False}))
        return 0
    if cmd in ("rotate-token", "new-token", "stop-stream", "shutdown"):
        return ctl_client(cmd)
    sys.stderr.write(
        "usage: iphone-camera-server.py [serve|status|install-unit|ctl <cmd>]\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
