"""
Zero-Dependency Built-in WebDAV & FTP Scan Receiver Daemon for Windows & macOS.
Allows Sindoh D410 / D410s / D420 / D450 MFPs to send scanned PDF/JPEG/TIFF files directly
to `Desktop/sindohScan` without any OS SMB file-sharing configuration, Windows password,
or macOS SMBv1/v3 compatibility issues.

Supports:
  - RFC 4918 WebDAV Server (`BuiltinScanWebDavServer`, Default port 50080):
    OPTIONS, PROPFIND, PROPPATCH, MKCOL, PUT, GET, HEAD, DELETE, LOCK, UNLOCK, MOVE, COPY
  - RFC 959 FTP Server (`BuiltinScanFtpServer`, Default port 2121):
    USER, PASS, SYST, FEAT, TYPE, PWD, XPWD, CWD, CDUP, MKD, XMKD, PASV, EPSV, PORT, STOR, APPE, LIST, NLST, NOOP, OPTS, SIZE, QUIT
  - Automatic 15-second DHCP IP change detection & MFP Address Book self-healing sync (WebDAV & FTP)
  - Automatic Windows Firewall (`-Profile Any -RemoteAddress LocalSubnet`) & silent reboot startup registration
"""

from __future__ import annotations

import argparse
import datetime
import email.utils
import http.cookiejar
import http.server
import json
import os
import platform
import random
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional


DEFAULT_WEBDAV_PORT = 50080
DEFAULT_FTP_PORT = 2121
DEFAULT_FTP_USER = "sindohscan"
DEFAULT_FTP_PASS = "sindoh1234"
PASV_PORT_MIN = 52100
PASV_PORT_MAX = 52130


def _get_desktop_dir() -> Path:
    """
    Resolve the user's actual Desktop directory on Windows (including OneDrive '바탕 화면' redirection)
    and macOS (`~/Desktop`).
    """
    if platform.system().lower() == "windows":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(260)
            # CSIDL_DESKTOPDIRECTORY = 0x0010
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf) == 0 and buf.value:
                p = Path(buf.value)
                if p.exists():
                    return p
        except Exception:
            pass
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "Desktop")
                expanded = Path(os.path.expandvars(str(val)))
                if expanded.exists():
                    return expanded
        except Exception:
            pass
    return Path.home() / "Desktop"


def get_default_scan_dir() -> Path:
    scan_dir = _get_desktop_dir() / "sindohScan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


# ─────────────────────────────────────────────────────────────────────────────
# Built-in WebDAV Scan Receiver Server (HTTP PUT / PROPFIND / MKCOL / LOCK)
# ─────────────────────────────────────────────────────────────────────────────
class _ThreadingWebDavHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type,
        root_dir: Path,
        on_file_received: Optional[Callable[[Path], None]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.root_dir = root_dir.resolve()
        self.on_file_received = on_file_received
        self.log_cb = log_cb
        super().__init__(server_address, RequestHandlerClass)


class _WebDavRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        # Suppress console spam in background daemon mode
        pass

    def _log(self, msg: str) -> None:
        srv: _ThreadingWebDavHTTPServer = self.server  # type: ignore[assignment]
        if srv.log_cb:
            srv.log_cb(msg)

    def _read_request_body(self) -> bytes:
        transfer_enc = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer_enc:
            body = bytearray()
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                chunk_len_str = line.split(b";", 1)[0].strip()
                if not chunk_len_str:
                    break
                chunk_len = int(chunk_len_str, 16)
                if chunk_len == 0:
                    self.rfile.readline()
                    break
                body.extend(self.rfile.read(chunk_len))
                self.rfile.read(2)  # trailing CRLF
            return bytes(body)

        content_len = int(self.headers.get("Content-Length") or 0)
        if content_len > 0:
            return self.rfile.read(content_len)
        return b""

    def _handle_expect_100(self) -> None:
        expect = (self.headers.get("Expect") or "").lower()
        if "100-continue" in expect:
            try:
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()
            except Exception:
                pass

    def _safe_target_path(self, raw_path: str) -> Path:
        srv: _ThreadingWebDavHTTPServer = self.server  # type: ignore[assignment]
        unquoted = urllib.parse.unquote(raw_path.split("?", 1)[0])
        clean_name = Path(unquoted.replace("\\", "/")).name
        if not clean_name or clean_name in (".", "/", "dav", "SindohScan", "sindohScan"):
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_name = f"SCAN_{ts}.pdf"
        target = srv.root_dir / clean_name
        # Only append a timestamp suffix if a non-empty (>0 bytes) file with the same name already exists.
        # If a 0-byte placeholder exists from a two-phase WebDAV PUT, overwrite it directly.
        if target.exists():
            try:
                if target.stat().st_size == 0:
                    return target
            except Exception:
                pass
            stem = target.stem
            suffix = target.suffix
            ts = datetime.datetime.now().strftime("%H%M%S_%f")[:9]
            target = srv.root_dir / f"{stem}_{ts}{suffix}"
        return target

    def do_OPTIONS(self) -> None:
        self.send_response(200, "OK")
        self.send_header("DAV", "1, 2")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header(
            "Allow",
            "OPTIONS, GET, HEAD, PUT, POST, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PROPFIND(self) -> None:
        self._handle_expect_100()
        _ = self._read_request_body()
        srv: _ThreadingWebDavHTTPServer = self.server  # type: ignore[assignment]

        req_path = urllib.parse.unquote(self.path.split("?", 1)[0])
        depth = (self.headers.get("Depth") or "0").strip()
        clean_tail = Path(req_path.rstrip("/")).name

        # Check if the MFP is probing a specific file that does not exist yet before uploading it
        if clean_tail and "." in clean_tail and clean_tail.lower() not in ("dav", "sindohscan"):
            candidate_file = srv.root_dir / clean_tail
            if not candidate_file.exists():
                self.send_response(404, "Not Found")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            now_http = email.utils.formatdate(candidate_file.stat().st_mtime, usegmt=True)
            fsize = candidate_file.stat().st_size
            xml_resp = f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{urllib.parse.quote(req_path)}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>{clean_tail}</D:displayname>
        <D:getcontentlength>{fsize}</D:getcontentlength>
        <D:getlastmodified>{now_http}</D:getlastmodified>
        <D:resourcetype/>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"""
        else:
            # Directory collection response
            href = req_path if req_path.endswith("/") else req_path + "/"
            now_http = email.utils.formatdate(time.time(), usegmt=True)
            items_xml = f"""  <D:response>
    <D:href>{urllib.parse.quote(href)}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>sindohScan</D:displayname>
        <D:getlastmodified>{now_http}</D:getlastmodified>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>"""

            if depth != "0":
                for item in srv.root_dir.iterdir():
                    if item.is_file():
                        f_href = href + urllib.parse.quote(item.name)
                        f_mtime = email.utils.formatdate(item.stat().st_mtime, usegmt=True)
                        f_size = item.stat().st_size
                        items_xml += f"""
  <D:response>
    <D:href>{f_href}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>{item.name}</D:displayname>
        <D:getcontentlength>{f_size}</D:getcontentlength>
        <D:getlastmodified>{f_mtime}</D:getlastmodified>
        <D:resourcetype/>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>"""

            xml_resp = f'<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n{items_xml}\n</D:multistatus>'

        payload = xml_resp.encode("utf-8")
        self.send_response(207, "Multi-Status")
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_PROPPATCH(self) -> None:
        self._handle_expect_100()
        _ = self._read_request_body()
        req_path = urllib.parse.unquote(self.path.split("?", 1)[0])
        xml_resp = f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{urllib.parse.quote(req_path)}</D:href>
    <D:propstat>
      <D:prop/>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"""
        payload = xml_resp.encode("utf-8")
        self.send_response(207, "Multi-Status")
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_MKCOL(self) -> None:
        self._handle_expect_100()
        _ = self._read_request_body()
        self.send_response(201, "Created")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self) -> None:
        self._handle_expect_100()
        srv: _ThreadingWebDavHTTPServer = self.server  # type: ignore[assignment]
        try:
            data = self._read_request_body()
            # Konica Minolta / Sindoh MFPs perform a two-phase WebDAV upload:
            #   Phase 1: PUT /FILENAME.pdf with Content-Length: 0 (0-byte reservation check) -> LOCK ->
            #   Phase 2: PUT /FILENAME.pdf with the actual scanned PDF/JPEG bytes.
            # Ignore 0-byte reservation PUTs on disk so we never create a 0KB file or force a `_timestamp` rename!
            if not data:
                self.send_response(201, "Created")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            target = self._safe_target_path(self.path)
            target.write_bytes(data)
            self._log(f"WebDAV 스캔 파일 수신 완료: {target.name} ({len(data):,} bytes)")
            if srv.on_file_received:
                srv.on_file_received(target)
            self.send_response(201, "Created")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception as e:
            self._log(f"WebDAV 스캔 저장 오류: {e}")
            self.send_response(500, "Internal Server Error")
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self) -> None:
        self.do_PUT()

    def do_LOCK(self) -> None:
        self._handle_expect_100()
        _ = self._read_request_body()
        token = "opaquelocktoken:d410-d420-scan-lock"
        xml_resp = f"""<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>Infinity</D:depth>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken><D:href>{token}</D:href></D:locktoken>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>"""
        payload = xml_resp.encode("utf-8")
        self.send_response(200, "OK")
        self.send_header("Lock-Token", f"<{token}>")
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_UNLOCK(self) -> None:
        self.send_response(204, "No Content")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self) -> None:
        self.send_response(204, "No Content")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_MOVE(self) -> None:
        self.send_response(201, "Created")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_COPY(self) -> None:
        self.send_response(201, "Created")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        srv: _ThreadingWebDavHTTPServer = self.server  # type: ignore[assignment]
        req_path = urllib.parse.unquote(self.path.split("?", 1)[0])
        clean_tail = Path(req_path.rstrip("/")).name
        if clean_tail and "." in clean_tail and clean_tail.lower() not in ("dav", "sindohscan"):
            f = srv.root_dir / clean_tail
            if not f.exists():
                self.send_response(404, "Not Found")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        self.send_response(200, "OK")
        self.send_header("DAV", "1, 2")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        msg = b"Sindoh D410/D420 WebDAV Scan Receiver Active."
        self.send_response(200, "OK")
        self.send_header("DAV", "1, 2")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)


class BuiltinScanWebDavServer:
    """In-process or standalone WebDAV HTTP server for receiving scans from D410 / D410s / D420."""

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        port: int = DEFAULT_WEBDAV_PORT,
        username: str = DEFAULT_FTP_USER,
        password: str = DEFAULT_FTP_PASS,
        on_file_received: Optional[Callable[[Path], None]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.root_dir = (root_dir or get_default_scan_dir()).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.port = port
        self.username = username
        self.password = password
        self.on_file_received = on_file_received
        self.log_cb = log_cb
        self._httpd: Optional[_ThreadingWebDavHTTPServer] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> tuple[bool, int]:
        if self._running:
            return True, self.port

        for candidate_port in (self.port, 50080, 50443, 50081):
            try:
                httpd = _ThreadingWebDavHTTPServer(
                    ("0.0.0.0", candidate_port),
                    _WebDavRequestHandler,
                    root_dir=self.root_dir,
                    on_file_received=self.on_file_received,
                    log_cb=self.log_cb,
                )
                self._httpd = httpd
                self.port = candidate_port
                self._running = True
                self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
                self._thread.start()
                return True, self.port
            except Exception:
                continue
        return False, self.port

    def stop(self) -> None:
        self._running = False
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None


# ─────────────────────────────────────────────────────────────────────────────
# Built-in FTP Scan Receiver Server (Fallback & Dual-Protocol Support)
# ─────────────────────────────────────────────────────────────────────────────
class _FTPSession(threading.Thread):
    """Handles a single MFP FTP client connection."""

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        root_dir: Path,
        expected_user: str,
        expected_pass: str,
        on_file_received: Optional[Callable[[Path], None]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.root_dir = root_dir.resolve()
        self.cwd = self.root_dir
        self.expected_user = expected_user
        self.expected_pass = expected_pass
        self.on_file_received = on_file_received
        self.log_cb = log_cb

        self.pasv_listener: Optional[socket.socket] = None
        self.active_target: Optional[tuple[str, int]] = None
        self.authenticated = False

    def _log(self, msg: str) -> None:
        if self.log_cb:
            self.log_cb(msg)

    def _send(self, line: str) -> None:
        try:
            self.conn.sendall((line + "\r\n").encode("utf-8"))
        except Exception:
            pass

    def _open_data_socket(self) -> Optional[socket.socket]:
        if self.pasv_listener is not None:
            try:
                self.pasv_listener.settimeout(15.0)
                data_sock, _ = self.pasv_listener.accept()
                return data_sock
            except Exception:
                return None
            finally:
                try:
                    self.pasv_listener.close()
                except Exception:
                    pass
                self.pasv_listener = None

        if self.active_target is not None:
            host, port = self.active_target
            self.active_target = None
            try:
                return socket.create_connection((host, port), timeout=10.0)
            except Exception:
                return None

        return None

    def _safe_target_path(self, filename: str) -> Path:
        clean_name = Path(filename.replace("\\", "/")).name
        if not clean_name:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_name = f"SCAN_{ts}.pdf"
        target = self.root_dir / clean_name
        if target.exists():
            try:
                if target.stat().st_size == 0:
                    return target
            except Exception:
                pass
            stem = target.stem
            suffix = target.suffix
            ts = datetime.datetime.now().strftime("%H%M%S_%f")[:9]
            target = self.root_dir / f"{stem}_{ts}{suffix}"
        return target

    def run(self) -> None:
        self.conn.settimeout(60.0)
        self._send("220 Sindoh D410/D420 Scan FTP Receiver Ready.")
        buf = b""
        try:
            while True:
                chunk = self.conn.recv(1024)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    line = raw_line.decode("utf-8", errors="ignore").strip("\r\n ")
                    if not line:
                        continue
                    parts = line.split(" ", 1)
                    cmd = parts[0].upper()
                    arg = parts[1].strip() if len(parts) > 1 else ""

                    if cmd == "USER":
                        self._send("331 User name okay, need password.")
                    elif cmd == "PASS":
                        self.authenticated = True
                        self._send("230 User logged in, proceed.")
                    elif cmd == "SYST":
                        self._send("215 UNIX Type: L8")
                    elif cmd == "FEAT":
                        self._send("211-Features:\r\n PASV\r\n EPSV\r\n UTF8\r\n SIZE\r\n211 End")
                    elif cmd == "OPTS":
                        self._send("200 OPTS UTF8 command successful.")
                    elif cmd in ("PWD", "XPWD"):
                        self._send('257 "/" is current directory.')
                    elif cmd in ("CWD", "XCWD", "CDUP"):
                        self._send("250 Directory successfully changed.")
                    elif cmd in ("MKD", "XMKD"):
                        self._send(f'257 "{arg}" directory created.')
                    elif cmd == "TYPE":
                        self._send("200 Type set to I.")
                    elif cmd == "MODE":
                        self._send("200 Mode set to S.")
                    elif cmd == "STRU":
                        self._send("200 Structure set to F.")
                    elif cmd == "NOOP":
                        self._send("200 NOOP ok.")
                    elif cmd == "PASV":
                        self._handle_pasv(epsv=False)
                    elif cmd == "EPSV":
                        self._handle_pasv(epsv=True)
                    elif cmd == "PORT":
                        self._handle_port(arg)
                    elif cmd in ("LIST", "NLST"):
                        self._handle_list()
                    elif cmd in ("STOR", "APPE"):
                        self._handle_stor(arg)
                    elif cmd == "SIZE":
                        self._send("213 0")
                    elif cmd == "DELE":
                        self._send("250 Requested file action okay, completed.")
                    elif cmd == "QUIT":
                        self._send("221 Goodbye.")
                        return
                    else:
                        self._send("200 Command okay.")
        except Exception:
            pass
        finally:
            if self.pasv_listener:
                try:
                    self.pasv_listener.close()
                except Exception:
                    pass
            try:
                self.conn.close()
            except Exception:
                pass

    def _handle_pasv(self, epsv: bool = False) -> None:
        if self.pasv_listener:
            try:
                self.pasv_listener.close()
            except Exception:
                pass
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        bound_port = 0
        ports = list(range(PASV_PORT_MIN, PASV_PORT_MAX + 1))
        random.shuffle(ports)
        for p in ports:
            try:
                listener.bind(("0.0.0.0", p))
                bound_port = p
                break
            except Exception:
                continue
        if bound_port == 0:
            listener.bind(("0.0.0.0", 0))
            bound_port = listener.getsockname()[1]

        listener.listen(1)
        self.pasv_listener = listener

        local_ip = self.conn.getsockname()[0]
        if local_ip.startswith("127.") or local_ip == "0.0.0.0":
            local_ip = "127.0.0.1"

        if epsv:
            self._send(f"229 Entering Extended Passive Mode (|||{bound_port}|).")
        else:
            ip_parts = local_ip.split(".")
            p1, p2 = bound_port >> 8, bound_port & 0xFF
            self._send(f"227 Entering Passive Mode ({','.join(ip_parts)},{p1},{p2}).")

    def _handle_port(self, arg: str) -> None:
        try:
            nums = [int(x) for x in arg.strip("() ").split(",")]
            host = ".".join(str(x) for x in nums[:4])
            port = (nums[4] << 8) + nums[5]
            self.active_target = (host, port)
            self._send("200 PORT command successful.")
        except Exception:
            self._send("501 Syntax error in parameters.")

    def _handle_list(self) -> None:
        self._send("150 Opening ASCII mode data connection for file list.")
        dsock = self._open_data_socket()
        if not dsock:
            self._send("425 Can't open data connection.")
            return
        try:
            lines = []
            for item in self.root_dir.iterdir():
                if item.is_file():
                    sz = item.stat().st_size
                    lines.append(f"-rw-r--r-- 1 sindoh sindoh {sz} Jan 01 00:00 {item.name}\r\n")
            dsock.sendall("".join(lines).encode("utf-8"))
            self._send("226 Transfer complete.")
        except Exception:
            self._send("426 Connection closed; transfer aborted.")
        finally:
            dsock.close()

    def _handle_stor(self, filename: str) -> None:
        target = self._safe_target_path(filename)
        self._send("150 Opening BINARY mode data connection for file transfer.")
        dsock = self._open_data_socket()
        if not dsock:
            self._send("425 Can't open data connection.")
            return
        total_bytes = 0
        try:
            with open(target, "wb") as f:
                while True:
                    chunk = dsock.recv(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    total_bytes += len(chunk)
            if total_bytes == 0:
                try:
                    target.unlink(missing_ok=True)
                except Exception:
                    pass
                self._send("226 Transfer complete.")
                return
            self._send("226 Transfer complete.")
            self._log(f"FTP 스캔 파일 수신 완료: {target.name} ({total_bytes:,} bytes)")
            if self.on_file_received:
                self.on_file_received(target)
        except Exception as e:
            self._send("451 Requested action aborted: local error in processing.")
            self._log(f"FTP 스캔 수신 오류: {e}")
        finally:
            dsock.close()


class BuiltinScanFtpServer:
    """In-process or standalone FTP server for receiving scans from D410 / D410s / D420."""

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        port: int = DEFAULT_FTP_PORT,
        username: str = DEFAULT_FTP_USER,
        password: str = DEFAULT_FTP_PASS,
        on_file_received: Optional[Callable[[Path], None]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.root_dir = (root_dir or get_default_scan_dir()).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.port = port
        self.username = username
        self.password = password
        self.on_file_received = on_file_received
        self.log_cb = log_cb
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> tuple[bool, int]:
        if self._running:
            return True, self.port

        for candidate_port in (self.port, 2121, 21, 52121):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", candidate_port))
                sock.listen(10)
                self._sock = sock
                self.port = candidate_port
                self._running = True
                self._thread = threading.Thread(target=self._accept_loop, daemon=True)
                self._thread.start()
                return True, self.port
            except Exception:
                continue
        return False, self.port

    def _accept_loop(self) -> None:
        while self._running and self._sock:
            try:
                conn, addr = self._sock.accept()
                sess = _FTPSession(
                    conn=conn,
                    addr=addr,
                    root_dir=self.root_dir,
                    expected_user=self.username,
                    expected_pass=self.password,
                    on_file_received=self.on_file_received,
                    log_cb=self.log_cb,
                )
                sess.start()
            except Exception:
                if not self._running:
                    break

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


def is_port_listening_locally(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except Exception:
        return False


def _stop_existing_ftp_agent_on_port(port: int, webdav_port: int = DEFAULT_WEBDAV_PORT) -> None:
    """
    Stop any previously running WebDAV/FTP scan receiver daemon on `port` or `webdav_port`
    so old folders are unlocked and can be deleted freely.
    """
    sys_name = platform.system().lower()
    cur_pid = os.getpid()
    try:
        if sys_name == "windows":
            ps_kill = f"""
$curPid = {cur_pid}
Get-NetTCPConnection -LocalPort {port},{webdav_port} -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    Where-Object {{ $_ -gt 4 -and $_ -ne $curPid }} |
    ForEach-Object {{ Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }}
Get-Process -Name 'D410-D420-Connect' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Id -ne $curPid }} |
    ForEach-Object {{ Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }}
"""
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_kill],
                capture_output=True,
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    f"lsof -ti tcp:{port} -ti tcp:{webdav_port} | grep -v ^{cur_pid}$ | xargs kill -9 2>/dev/null || true",
                ],
                capture_output=True,
                timeout=4,
            )
    except Exception:
        pass


def _get_appdata_dir() -> Path:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "SindohD410Connect"
    elif sys_name == "darwin":
        base = Path.home() / "Library" / "Application Support" / "SindohD410Connect"
    else:
        base = Path.home() / ".local" / "share" / "SindohD410Connect"
    base.mkdir(parents=True, exist_ok=True)
    return base


def save_scan_profile(
    mfp_ip: str,
    scan_name: str,
    port: int = DEFAULT_WEBDAV_PORT,
    admin_password: str = "",
    protocol: str = "WEBDAV",
) -> None:
    """Persist scan registration profile so the background daemon can auto-update the MFP if this PC's DHCP IP changes."""
    try:
        profile_path = _get_appdata_dir() / "scan_profile.json"
        data = {
            "mfp_ip": mfp_ip.strip(),
            "scan_name": scan_name.strip(),
            "port": int(port),
            "protocol": protocol.upper(),
            "admin_password": admin_password,
        }
        profile_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _get_local_ip_towards(target_ip: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect((target_ip, 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _search_key_for_name(scan_name: str) -> str:
    if not scan_name:
        return "Other"
    ch = scan_name.strip()[0].upper()
    for grp, key in (
        ("ABC", "Abc"),
        ("DEF", "Def"),
        ("GHI", "Ghi"),
        ("JKL", "Jkl"),
        ("MNO", "Mno"),
        ("PQRS", "Pqrs"),
        ("TUV", "Tuv"),
        ("WXYZ", "Wxyz"),
    ):
        if ch in grp:
            return key
    return "Other"


def _sync_mfp_ip_once(last_checked_ip: str) -> str:
    """
    If this PC's local IPv4 address changed (e.g. after reboot or DHCP renewal),
    verify `/wcd/abbr.xml` on the D410/D420 MFP and automatically update `<Address>` to the new IP.
    Supports both WebDAV (`PSL_C_A_DAV_PTR`) and FTP (`PSL_C_A_FTP_PTR`).
    """
    profile_path = _get_appdata_dir() / "scan_profile.json"
    if not profile_path.exists():
        return last_checked_ip

    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        mfp_ip = str(profile.get("mfp_ip") or "").strip()
        scan_name = str(profile.get("scan_name") or "").strip()
        protocol = str(profile.get("protocol") or "WEBDAV").upper()
        is_webdav = "DAV" in protocol
        port = int(profile.get("port") or (DEFAULT_WEBDAV_PORT if is_webdav else DEFAULT_FTP_PORT))
        admin_password = str(profile.get("admin_password") or "")
        if not mfp_ip or not scan_name:
            return last_checked_ip

        current_ip = _get_local_ip_towards(mfp_ip)
        if not current_ip or current_ip.startswith("127."):
            return last_checked_ip

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=ctx),
        )
        opener.addheaders = [("User-Agent", "Mozilla/5.0"), ("Accept-Language", "ko,en-US;q=0.7")]

        base_url = f"http://{mfp_ip}"
        opener.open(f"{base_url}/wcd/index.html", timeout=3.0).read()
        try:
            opener.open(f"{base_url}/wcd/system_device.xml", timeout=3.0).read()
        except Exception:
            pass

        if admin_password:
            login_payload = urllib.parse.urlencode(
                {"func": "PSL_LP0_LOG", "R_ADM": "Admin", "password": admin_password}
            ).encode("utf-8")
            try:
                opener.open(f"{base_url}/wcd/ulogin.cgi", data=login_payload, timeout=3.0).read()
            except Exception:
                pass

        abbr_xml = opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.5).read().decode("utf-8", errors="ignore")

        # Check if `scan_name` is already registered with `current_ip` and `port`
        matching_nos = []
        already_up_to_date = False
        for m in re.finditer(r"<Abbr>(.*?)</Abbr>", abbr_xml, re.DOTALL):
            block = m.group(1)
            nm = re.search(r"<Name>([^<]+)</Name>", block)
            no = re.search(r"<AbbrNo>(\d+)</AbbrNo>", block)
            addr = re.search(r"<(?:Address|Host)>([^<]+)</(?:Address|Host)>", block)
            pno = re.search(r"<PortNo>(\d+)</PortNo>", block)
            smode = re.search(r"<SendMode>([^<]+)</SendMode>", block)
            if nm and no and nm.group(1).strip().lower() == scan_name.lower():
                matching_nos.append(no.group(1).strip())
                expected_mode = "webdav" if is_webdav else "ftp"
                mode_matches = (not smode) or (smode.group(1).strip().lower() == expected_mode)
                if (
                    addr
                    and addr.group(1).strip() == current_ip
                    and (not pno or int(pno.group(1)) == port)
                    and mode_matches
                ):
                    already_up_to_date = True

        # If exactly 1 entry exists and its IP/port/mode already match, nothing to do!
        if already_up_to_date and len(matching_nos) == 1:
            return current_ip

        # IP changed, duplicate entries exist, or entry missing -> delete all matching entries and re-register cleanly once
        for existing_no in matching_nos:
            del_payload = urllib.parse.urlencode(
                {"func": "PSL_C_ABR_DEL", "C_ABR_H_NUM": existing_no, "C_ABR_H_AKI": "Public", "C_ABR_H_FAV": ""}
            ).encode("utf-8")
            try:
                opener.open(f"{base_url}/wcd/scan.cgi", data=del_payload, timeout=4.0).read()
            except Exception:
                pass
        if matching_nos:
            try:
                opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.5).read()
            except Exception:
                pass

        send_mode_str = "WebDav" if is_webdav else "Ftp"
        new_payload = urllib.parse.urlencode(
            {"func": "PSL_C_ABR_NEW", "H_NEW": "new", "S_SMO": send_mode_str, "H_AKI": "Public", "H_FAV": ""}
        ).encode("utf-8")
        opener.open(f"{base_url}/wcd/scan.cgi", data=new_payload, timeout=4.0).read()
        try:
            opener.open(f"{base_url}/wcd/abbr_edit.xml", timeout=3.5).read()
        except Exception:
            pass

        if is_webdav:
            form_fields = {
                "func": "PSL_C_A_DAV_PTR",
                "H_NUM": "new",
                "H_AKI": "Public",
                "H_FAV": "",
                "H_Kind": "WebDav",
                "B_Name": "",
                "B_Dest": "",
                "R_NUM_": "Space",
                "T_NAM": scan_name,
                "H_Result": "SendOk",
                "C_LANG": "Other",
                "T_FURI": "",
                "S_SER": _search_key_for_name(scan_name),
                "C_WEL": "on",
                "T_HOS": current_ip,
                "T_DIR": "/",
                "T_LOG": DEFAULT_FTP_USER,
                "P_PAS": DEFAULT_FTP_PASS,
                "T_POR": str(port),
                "S_SSL": "Off",
                "S_PRX": "Off",
                "H_PEX": "false",
                "R_REF": "Level",
                "S_LEV": "0",
            }
        else:
            form_fields = {
                "func": "PSL_C_A_FTP_PTR",
                "H_NUM": "new",
                "H_AKI": "Public",
                "H_FAV": "",
                "R_NUM_": "Space",
                "T_NAM": scan_name,
                "C_LANG": "Other",
                "T_FURI": scan_name,
                "S_SER": _search_key_for_name(scan_name),
                "C_WEL": "WellUse",
                "T_HOS": current_ip,
                "T_DIR": ".",
                "T_LOG": DEFAULT_FTP_USER,
                "P_PAS": DEFAULT_FTP_PASS,
                "S_ANO": "false",
                "S_PAS": "true",
                "S_PRX": "false",
                "T_POR": str(port),
                "R_REF": "Level",
            }
        opener.open(f"{base_url}/wcd/scan.cgi", data=urllib.parse.urlencode(form_fields).encode("utf-8"), timeout=5.0).read()
        return current_ip
    except Exception:
        return last_checked_ip


def start_auto_ip_sync_daemon() -> None:
    """Start a background thread that monitors local IP changes and keeps the D410 address book in sync."""
    def _loop() -> None:
        # Wait 25s before the first check so we never race with the foreground installer's initial registration
        time.sleep(25)
        last_ip = ""
        while True:
            last_ip = _sync_mfp_ip_once(last_ip)
            time.sleep(15)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _stage_daemon_to_appdata() -> tuple[str, Optional[Path], Path]:
    """
    Copy the background WebDAV/FTP daemon into a permanent AppData directory
    (`%LOCALAPPDATA%/SindohD410Connect` on Windows, `~/Library/Application Support/SindohD410Connect` on macOS)
    so the user can freely delete the downloaded installer folder in `Downloads` without Windows locking it
    or breaking scan reception after reboot.
    """
    sys_name = platform.system().lower()
    is_frozen = getattr(sys, "frozen", False)
    if sys_name == "windows":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "SindohD410Connect"
    elif sys_name == "darwin":
        base = Path.home() / "Library" / "Application Support" / "SindohD410Connect"
    else:
        base = Path.home() / ".local" / "share" / "SindohD410Connect"

    base.mkdir(parents=True, exist_ok=True)

    if is_frozen and sys_name == "windows":
        src_app_dir = Path(sys.executable).resolve().parent
        dst_app_dir = base / "agent"
        if src_app_dir != dst_app_dir:
            try:
                if dst_app_dir.exists():
                    shutil.rmtree(dst_app_dir, ignore_errors=True)
                shutil.copytree(src_app_dir, dst_app_dir, dirs_exist_ok=True)
                staged_exe = dst_app_dir / Path(sys.executable).name
                if staged_exe.exists():
                    return str(staged_exe), None, dst_app_dir
            except Exception:
                pass
        return sys.executable, None, base

    # Script mode: copy ftp_scan_server.py into AppData so it never locks the repo/download directory
    src_script = Path(__file__).resolve()
    dst_script = base / "ftp_scan_server.py"
    try:
        if src_script != dst_script:
            shutil.copy2(src_script, dst_script)
    except Exception:
        dst_script = src_script

    py_exe = sys.executable
    if sys_name == "windows" and not is_frozen and py_exe.lower().endswith("python.exe"):
        pyw = Path(py_exe).with_name("pythonw.exe")
        if pyw.exists():
            py_exe = str(pyw)
    elif sys_name == "darwin":
        for sys_py in (
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
        ):
            if Path(sys_py).exists():
                py_exe = sys_py
                break

    return py_exe, dst_script, base


def ensure_background_ftp_agent(
    scan_dir: Optional[Path] = None,
    port: int = DEFAULT_FTP_PORT,
    webdav_port: int = DEFAULT_WEBDAV_PORT,
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, int, int]:
    """
    Ensure the detached background WebDAV + FTP scan receiver daemon is running on this PC/Mac,
    and register it for auto-start on login so scans keep arriving even after closing the installer UI.
    Also opens Windows Firewall for WebDAV (`50080`) and FTP (`2121`, `52100-52130`) restricted to `LocalSubnet`.
    Returns `(ok, active_webdav_port, active_ftp_port)`.
    """
    target_dir = (scan_dir or get_default_scan_dir()).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    sys_name = platform.system().lower()

    # 1. Open Windows Firewall rules for WebDAV & FTP ports (Profile Any + RemoteAddress LocalSubnet for security)
    if sys_name == "windows":
        try:
            ps_fw = f"""
Remove-NetFirewallRule -DisplayName 'Sindoh D410/D420 Scan Receiver (FTP)' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Sindoh D410/D420 Scan Receiver (WebDAV/FTP)' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Sindoh D410/D420 Scan Receiver (WebDAV/FTP)' -Direction Inbound -Protocol TCP -LocalPort {webdav_port},{port},{PASV_PORT_MIN}-{PASV_PORT_MAX} -Profile Any -RemoteAddress LocalSubnet -Action Allow -ErrorAction SilentlyContinue | Out-Null
"""
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_fw],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    # 2. Always stop any previous daemon instances so old Downloads folders are unlocked and new target_dir applies
    _stop_existing_ftp_agent_on_port(port, webdav_port)
    for _ in range(10):
        if not is_port_listening_locally(webdav_port) and not is_port_listening_locally(port):
            break
        time.sleep(0.1)

    # 3. Stage daemon into AppData & spawn detached background process with cwd=AppData
    py_exe, staged_script, daemon_cwd = _stage_daemon_to_appdata()
    if staged_script is None:
        cmd = [py_exe, "--daemon", "--webdav-port", str(webdav_port), "--port", str(port), "--dir", str(target_dir)]
        reg_cmd_str = f'"{py_exe}" --daemon --webdav-port {webdav_port} --port {port} --dir "{target_dir}"'
    else:
        cmd = [
            py_exe,
            str(staged_script),
            "--daemon",
            "--webdav-port",
            str(webdav_port),
            "--port",
            str(port),
            "--dir",
            str(target_dir),
        ]
        reg_cmd_str = (
            f'"{py_exe}" "{staged_script}" --daemon --webdav-port {webdav_port} --port {port} --dir "{target_dir}"'
        )
    try:
        if sys_name == "windows":
            vbs_path = (
                daemon_cwd.parent / "start_scan_daemon.vbs"
                if daemon_cwd.name == "agent"
                else daemon_cwd / "start_scan_daemon.vbs"
            )
            vbs_cmd = reg_cmd_str.replace('"', '""')
            vbs_content = (
                'Set sh = CreateObject("WScript.Shell")\r\n'
                'Set env = sh.Environment("PROCESS")\r\n'
                'env("__COMPAT_LAYER") = "RunAsInvoker"\r\n'
                f'sh.CurrentDirectory = "{daemon_cwd}"\r\n'
                f'sh.Run "{vbs_cmd}", 0, False\r\n'
            )
            try:
                vbs_path.write_text(vbs_content, encoding="utf-8")
            except Exception:
                pass

            env_copy = os.environ.copy()
            env_copy["__COMPAT_LAYER"] = "RunAsInvoker"
            flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
            ) | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            subprocess.Popen(cmd, cwd=str(daemon_cwd), env=env_copy, creationflags=flags, close_fds=True)

            run_entry = f'wscript.exe //B //NoLogo "{vbs_path}"' if vbs_path.exists() else reg_cmd_str
            try:
                import winreg

                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_SET_VALUE,
                ) as key:
                    winreg.SetValueEx(key, "SindohD410ScanReceiver", 0, winreg.REG_SZ, run_entry)
            except Exception:
                pass
            try:
                subprocess.run(
                    [
                        "schtasks",
                        "/Create",
                        "/TN",
                        "SindohD410ScanReceiver",
                        "/TR",
                        run_entry,
                        "/SC",
                        "ONLOGON",
                        "/F",
                    ],
                    capture_output=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                pass
        else:
            subprocess.Popen(
                cmd,
                cwd=str(daemon_cwd),
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if sys_name == "darwin":
                _register_macos_launch_agent(
                    py_exe, staged_script or Path(__file__).resolve(), webdav_port, port, target_dir
                )

        if log_cb:
            log_cb(f"내장 WebDAV 스캔 수신 에이전트 시작 완료 (포트: {webdav_port}, 폴더: {target_dir})")
        return True, webdav_port, port
    except Exception as e:
        if log_cb:
            log_cb(f"백그라운드 에이전트 실행 경고 (인앱 서버로 전환): {e}")
        dav_srv = BuiltinScanWebDavServer(root_dir=target_dir, port=webdav_port, log_cb=log_cb)
        ok_d, b_dav = dav_srv.start()
        ftp_srv = BuiltinScanFtpServer(root_dir=target_dir, port=port, log_cb=log_cb)
        _, b_ftp = ftp_srv.start()
        return ok_d, b_dav, b_ftp


def _register_macos_launch_agent(
    py_exe: str, script_path: Path, webdav_port: int, ftp_port: int, target_dir: Path
) -> None:
    """Create `~/Library/LaunchAgents/com.sindoh.d410scan.plist` so macOS runs the WebDAV/FTP scan receiver automatically."""
    try:
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agents_dir / "com.sindoh.d410scan.plist"
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sindoh.d410scan</string>
    <key>ProgramArguments</key>
    <array>
        <string>{py_exe}</string>
        <string>{script_path}</string>
        <string>--daemon</string>
        <string>--webdav-port</string>
        <string>{webdav_port}</string>
        <string>--port</string>
        <string>{ftp_port}</string>
        <string>--dir</string>
        <string>{target_dir}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        plist_path.write_text(plist_content, encoding="utf-8")
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
        subprocess.run(["launchctl", "load", "-w", str(plist_path)], capture_output=True)
    except Exception:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sindoh D410/D420 Built-in WebDAV & FTP Scan Receiver Daemon")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background")
    parser.add_argument("--webdav-port", type=int, default=DEFAULT_WEBDAV_PORT)
    parser.add_argument("--port", type=int, default=DEFAULT_FTP_PORT)
    parser.add_argument("--dir", type=str, default=str(get_default_scan_dir()))
    args = parser.parse_args()

    scan_root = Path(args.dir)
    dav_server = BuiltinScanWebDavServer(root_dir=scan_root, port=args.webdav_port)
    ok_dav, _ = dav_server.start()

    ftp_server = BuiltinScanFtpServer(root_dir=scan_root, port=args.port)
    ok_ftp, _ = ftp_server.start()

    if ok_dav or ok_ftp:
        start_auto_ip_sync_daemon()
        while True:
            time.sleep(3600)
