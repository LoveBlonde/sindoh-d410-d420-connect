"""
Zero-Dependency Built-in FTP Scan Receiver Daemon for Windows & macOS.
Allows Sindoh D410 / D410s / D420 MFPs to send scanned PDF/JPEG/TIFF files directly
to `~/Downloads/sindohScan` without any OS SMB file-sharing configuration, Windows password,
or macOS SMBv1/v3 compatibility issues.

Supports:
  - Standard RFC 959 FTP commands: USER, PASS, SYST, FEAT, TYPE, PWD, XPWD, CWD, CDUP,
    MKD, XMKD, PASV, EPSV, PORT, STOR, APPE, LIST, NLST, NOOP, OPTS, SIZE, QUIT
  - Both Passive (PASV / EPSV) and Active (PORT) data transfer modes
  - Automatic Windows Firewall / macOS background daemon registration
"""

from __future__ import annotations

import argparse
import datetime
import http.cookiejar
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional


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
        # Strip any directory prefixes sent by MFP (e.g. "/sindohScan/SKM_C224e261117.pdf")
        clean_name = Path(filename.replace("\\", "/")).name
        if not clean_name:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_name = f"SCAN_{ts}.pdf"
        target = self.root_dir / clean_name
        if target.exists():
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
                        # Accept any CWD (e.g. /sindohScan or .) so MFP never fails on path mismatch
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

        # Bind within predictable passive port range for firewall friendliness
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
            self._send("226 Transfer complete.")
            self._log(f"스캔 파일 수신 완료: {target.name} ({total_bytes:,} bytes)")
            if self.on_file_received:
                self.on_file_received(target)
        except Exception as e:
            self._send("451 Requested action aborted: local error in processing.")
            self._log(f"스캔 수신 오류: {e}")
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
        """Start listening on `self.port` (or fallback port 21 / 2121) and return (ok, bound_port)."""
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


def _stop_existing_ftp_agent_on_port(port: int) -> None:
    """
    Stop any previously running FTP scan receiver daemon on `port` (and any lingering
    background `D410-D420-Connect.exe` instances from older Downloads folders) so old folders
    are unlocked and can be deleted freely.
    """
    sys_name = platform.system().lower()
    cur_pid = os.getpid()
    try:
        if sys_name == "windows":
            ps_kill = f"""
$curPid = {cur_pid}
Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue |
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
                ["/bin/sh", "-c", f"lsof -ti tcp:{port} | grep -v ^{cur_pid}$ | xargs kill -9 2>/dev/null || true"],
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
    port: int = DEFAULT_FTP_PORT,
    admin_password: str = "",
) -> None:
    """Persist scan registration profile so the background daemon can auto-update the MFP if this PC's DHCP IP changes."""
    try:
        profile_path = _get_appdata_dir() / "scan_profile.json"
        data = {
            "mfp_ip": mfp_ip.strip(),
            "scan_name": scan_name.strip(),
            "port": int(port),
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
    """
    profile_path = _get_appdata_dir() / "scan_profile.json"
    if not profile_path.exists():
        return last_checked_ip

    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        mfp_ip = str(profile.get("mfp_ip") or "").strip()
        scan_name = str(profile.get("scan_name") or "").strip()
        port = int(profile.get("port") or DEFAULT_FTP_PORT)
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
        existing_no = None
        for m in re.finditer(r"<Abbr>(.*?)</Abbr>", abbr_xml, re.DOTALL):
            block = m.group(1)
            nm = re.search(r"<Name>([^<]+)</Name>", block)
            no = re.search(r"<AbbrNo>(\d+)</AbbrNo>", block)
            addr = re.search(r"<Address>([^<]+)</Address>", block)
            pno = re.search(r"<PortNo>(\d+)</PortNo>", block)
            if nm and no and nm.group(1).strip().lower() == scan_name.lower():
                existing_no = no.group(1).strip()
                if addr and addr.group(1).strip() == current_ip and (not pno or int(pno.group(1)) == port):
                    return current_ip
                break

        # IP changed (or entry missing) -> delete old entry and re-register with new IP
        if existing_no:
            del_payload = urllib.parse.urlencode(
                {"func": "PSL_C_ABR_DEL", "C_ABR_H_NUM": existing_no, "C_ABR_H_AKI": "Public", "C_ABR_H_FAV": ""}
            ).encode("utf-8")
            opener.open(f"{base_url}/wcd/scan.cgi", data=del_payload, timeout=4.0).read()
            opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.5).read()

        new_payload = urllib.parse.urlencode(
            {"func": "PSL_C_ABR_NEW", "H_NEW": "new", "S_SMO": "Ftp", "H_AKI": "Public", "H_FAV": ""}
        ).encode("utf-8")
        opener.open(f"{base_url}/wcd/scan.cgi", data=new_payload, timeout=4.0).read()
        try:
            opener.open(f"{base_url}/wcd/abbr_edit.xml", timeout=3.5).read()
        except Exception:
            pass

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
        last_ip = ""
        while True:
            last_ip = _sync_mfp_ip_once(last_ip)
            time.sleep(15)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _stage_daemon_to_appdata() -> tuple[str, Optional[Path], Path]:
    """
    Copy the background FTP daemon into a permanent AppData directory
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
        # Since ftp_scan_server.py uses 100% pure Python stdlib (no Tkinter/pip needed),
        # prefer a persistent system Python for the LaunchAgent so deleting the installer folder never breaks reboot auto-start.
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
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, int]:
    """
    Ensure the detached background FTP scan receiver daemon is running on this PC/Mac,
    and register it for auto-start on login so scans keep arriving even after closing the installer UI.
    Also opens Windows Firewall for the FTP control + passive ports.
    """
    target_dir = (scan_dir or get_default_scan_dir()).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    sys_name = platform.system().lower()

    # 1. Open Windows Firewall rules for FTP port & passive range
    if sys_name == "windows":
        try:
            ps_fw = f"""
New-NetFirewallRule -DisplayName 'Sindoh D410/D420 Scan Receiver (FTP)' -Direction Inbound -Protocol TCP -LocalPort {port},{PASV_PORT_MIN}-{PASV_PORT_MAX} -Action Allow -ErrorAction SilentlyContinue | Out-Null
"""
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_fw],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    # 2. Always stop any previous daemon instances so old Downloads folders are unlocked and new target_dir applies
    _stop_existing_ftp_agent_on_port(port)
    import time
    for _ in range(10):
        if not is_port_listening_locally(port):
            break
        time.sleep(0.1)

    # 3. Stage daemon into AppData & spawn detached background process with cwd=AppData
    py_exe, staged_script, daemon_cwd = _stage_daemon_to_appdata()
    if staged_script is None:
        cmd = [py_exe, "--daemon", "--port", str(port), "--dir", str(target_dir)]
        reg_cmd_str = f'"{py_exe}" --daemon --port {port} --dir "{target_dir}"'
    else:
        cmd = [py_exe, str(staged_script), "--daemon", "--port", str(port), "--dir", str(target_dir)]
        reg_cmd_str = f'"{py_exe}" "{staged_script}" --daemon --port {port} --dir "{target_dir}"'
    try:
        if sys_name == "windows":
            # Create a windowless VBScript launcher with __COMPAT_LAYER=RunAsInvoker so Windows HKCU\...\Run
            # starts the daemon silently on every reboot/login even when the .exe has a --uac-admin manifest.
            vbs_path = daemon_cwd.parent / "start_scan_daemon.vbs" if daemon_cwd.name == "agent" else daemon_cwd / "start_scan_daemon.vbs"
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

            # Register in HKCU Run AND Windows Task Scheduler (ONLOGON) so it starts automatically on every reboot
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
            # macOS / Linux detached daemon + LaunchAgent plist on macOS
            subprocess.Popen(
                cmd,
                cwd=str(daemon_cwd),
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if sys_name == "darwin":
                _register_macos_launch_agent(py_exe, staged_script or Path(__file__).resolve(), port, target_dir)

        if log_cb:
            log_cb(f"내장 FTP 스캔 수신 에이전트 시작 완료 (포트: {port}, 폴더: {target_dir})")
        return True, port
    except Exception as e:
        if log_cb:
            log_cb(f"백그라운드 에이전트 실행 경고 (인앱 서버로 전환): {e}")
        srv = BuiltinScanFtpServer(root_dir=target_dir, port=port, log_cb=log_cb)
        return srv.start()


def _register_macos_launch_agent(py_exe: str, script_path: Path, port: int, target_dir: Path) -> None:
    """Create `~/Library/LaunchAgents/com.sindoh.d410scan.plist` so macOS runs the FTP scan receiver automatically."""
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
        <string>--port</string>
        <string>{port}</string>
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
    except Exception:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sindoh D410/D420 Built-in FTP Scan Receiver Daemon")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background")
    parser.add_argument("--port", type=int, default=DEFAULT_FTP_PORT)
    parser.add_argument("--dir", type=str, default=str(get_default_scan_dir()))
    args = parser.parse_args()

    server = BuiltinScanFtpServer(root_dir=Path(args.dir), port=args.port)
    ok, bound_port = server.start()
    if ok:
        start_auto_ip_sync_daemon()
        while True:
            time.sleep(3600)
