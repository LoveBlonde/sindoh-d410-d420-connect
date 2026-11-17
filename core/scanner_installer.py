"""
Cross-platform Scanner Setup & MFP Address Book Registration for D410 / D410s / D420.
Supports:
  1. Built-in FTP Scan Receiver (`FTP_BUILTIN`, Default, just like Sindoh Connect!):
     - Starts a lightweight local FTP receiver daemon on port 2121 (no Windows/macOS SMB folder sharing or PC account password required!)
     - Registers the PC's IP, port 2121, and generated FTP credentials directly into the D410s/D420 Web Connection (`/wcd/scan.cgi`)
  2. Traditional SMB Shared Folder (`SMB`) or external FTP (`FTP`) registration
  3. Optional silent TWAIN driver installation (`Setup.exe /S`) & target IP mapping on Windows
"""

from __future__ import annotations

import http.cookiejar
import os
import platform
import re
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from core.ftp_scan_server import (
    DEFAULT_FTP_PASS,
    DEFAULT_FTP_PORT,
    DEFAULT_FTP_USER,
    ensure_background_ftp_agent,
)


@dataclass
class ScanSetupResult:
    success: bool
    title: str
    detail: str
    scan_folder: str = ""


def get_default_scan_folder() -> Path:
    """Return `~/Downloads/sindohScan` (matching sindoh Connect behavior on Windows & macOS)."""
    downloads = Path.home() / "Downloads"
    scan_dir = downloads / "sindohScan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


def get_client_ip_for_mfp(mfp_ip: str) -> str:
    """Determine the local IPv4 address on the same interface that routes to `mfp_ip`."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect((mfp_ip, 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def register_km_wcd_address_book(
    mfp_ip: str,
    scan_name: str,
    client_ip: str,
    protocol: str = "FTP",  # "FTP" or "SMB"
    folder_name: str = "/",
    username: str = DEFAULT_FTP_USER,
    password: str = DEFAULT_FTP_PASS,
    port: int = DEFAULT_FTP_PORT,
    admin_password: str = "",
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """
    Register a one-touch scan destination on Konica Minolta / Sindoh D410 / D410s / D420
    Web Connection (`/wcd/index.html` -> `/wcd/ulogin.cgi` -> `/wcd/scan.cgi`)
    or Sindoh Web Monitor (`/cgi-bin/address_book.cgi`).
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
        ("Accept-Language", "ko,en-US;q=0.7,en;q=0.3"),
    ]

    base_url = f"http://{mfp_ip}"
    try:
        # 1. Probe /wcd/common.xml or /wcd/top.xml to establish session cookies & check reachability
        for scheme in ("http", "https"):
            test_url = f"{scheme}://{mfp_ip}/wcd/common.xml"
            try:
                with opener.open(test_url, timeout=2.5) as resp:
                    if resp.status == 200:
                        base_url = f"{scheme}://{mfp_ip}"
                        break
            except Exception:
                continue

        # 2. Public user or Admin login (/wcd/ulogin.cgi)
        login_url = f"{base_url}/wcd/ulogin.cgi"
        if admin_password:
            login_payload = urllib.parse.urlencode(
                {"func": "PSL_LP0_LOG", "R_ADM": "Admin", "password": admin_password}
            ).encode("utf-8")
        else:
            login_payload = urllib.parse.urlencode(
                {"func": "PSL_LP0_TOP", "Mode": "PublicUser"}
            ).encode("utf-8")

        try:
            opener.open(login_url, data=login_payload, timeout=3.0).read()
        except Exception:
            pass

        # 3. Fetch token from /wcd/abbr.xml if present
        token = ""
        try:
            with opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.0) as resp:
                xml_body = resp.read().decode("utf-8", errors="ignore")
                m = re.search(r"<Token>([^<]+)</Token>", xml_body)
                if m:
                    token = m.group(1).strip()
        except Exception:
            pass

        # 4. Submit Address Book registration to /wcd/scan.cgi
        # D410 / D420 Web Connection uses PSL_C_A_FTP_PTR (FTP) or PSL_C_A_SMB_PTR (SMB)
        is_ftp = protocol.upper().startswith("FTP")
        func_code = "PSL_C_A_FTP_PTR" if is_ftp else "PSL_C_A_SMB_PTR"
        form_fields = {
            "func": func_code,
            "H_NUM": "new",
            "H_AKI": "Public",
            "H_FAV": "Yes",
            "T_NAM": scan_name,
            "T_FURI": "",
            "S_LEV": "Other",
            "C_WEL": "true",
            "T_HOS": client_ip,
            "T_DIR": folder_name,
            "T_LOG": username or DEFAULT_FTP_USER,
            "P_PAS": password,
            "T_POR": str(port),
            "S_ANO": "Off" if username else "On",
            "S_PAS": "On",
            "S_PRX": "Off",
        }
        if token:
            form_fields["h_token"] = token

        encoded = urllib.parse.urlencode(form_fields).encode("utf-8")
        log(f"복합기 웹 컨트롤러({base_url}/wcd/scan.cgi)에 [{scan_name}] ({client_ip}:{port}) 주소록 자동 등록 중...")
        with opener.open(f"{base_url}/wcd/scan.cgi", data=encoded, timeout=4.0) as resp:
            result_html = resp.read().decode("utf-8", errors="ignore")
            if "SendOk" in result_html or "completed" in result_html.lower() or resp.status == 200:
                return True, f"복합기 주소록에 '{scan_name}' ({client_ip}:{port}) 원터치 스캔 버튼이 등록되었습니다."
    except Exception as e:
        return False, f"복합기 웹 주소록 자동 등록 응답 대기 ({e})"

    return False, "복합기 웹 응답을 확인할 수 없습니다."


def setup_windows_smb_share(scan_dir: Path, share_name: str = "sindohScan", log_cb: Optional[Callable[[str], None]] = None) -> bool:
    """Create or verify a Windows local SMB share for `scan_dir` (only used when SMB mode is explicitly selected)."""
    if platform.system().lower() != "windows":
        return False
    try:
        if log_cb:
            log_cb(f"Windows 스캔 공유 폴더 설정 중: \\\\localhost\\{share_name}")
        ps_cmd = f"""
if (-not (Get-SmbShare -Name '{share_name}' -ErrorAction SilentlyContinue)) {{
    New-SmbShare -Name '{share_name}' -Path '{scan_dir}' -FullAccess 'Everyone' -ErrorAction SilentlyContinue | Out-Null
}}
icacls '{scan_dir}' /grant Everyone:`(OI`)`(CI`)F /T /C /Q | Out-Null
"""
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except Exception:
        return False


def install_twain_driver_if_present(
    mfp_ip: str,
    log_cb: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    If the user placed Sindoh's TWAIN Driver installer inside `drivers/windows/`,
    install it silently and configure its target IP.
    """
    if platform.system().lower() != "windows":
        return None

    twain_dir = Path(__file__).resolve().parent.parent / "drivers" / "windows"
    setup_exes = [
        p for p in twain_dir.rglob("*.exe")
        if any(k in p.name.lower() for k in ("twain", "setup", "scan"))
    ]
    if not setup_exes:
        return None

    exe = setup_exes[0]
    if log_cb:
        log_cb(f"TWAIN 스캐너 드라이버 무인 설치 실행 중: {exe.name}")
    try:
        subprocess.run(
            [str(exe), "/S", f"/IP={mfp_ip}"],
            capture_output=True,
            timeout=45,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return exe.name
    except Exception:
        return None


def configure_scanner_cross_platform(
    mfp_ip: str,
    scan_name: str,
    protocol: str = "FTP_BUILTIN",  # "FTP_BUILTIN" (default) or "SMB"
    pc_username: str = "",
    pc_password: str = "",
    mfp_admin_password: str = "",
    ftp_port: int = DEFAULT_FTP_PORT,
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> ScanSetupResult:
    """
    Complete cross-platform scan setup:
    1. Creates `~/Downloads/sindohScan`
    2. When `protocol == "FTP_BUILTIN"` (Default, just like Sindoh Connect):
       - Starts the zero-config Built-in FTP Scan Receiver Daemon (no OS folder sharing or Windows/Mac account needed!)
       - Registers the FTP shortcut button (`PSL_C_A_FTP_PTR`) on the D410s/D420 MFP Web Connection
    3. When `protocol == "SMB"`:
       - Configures Windows SMB folder share and registers SMB shortcut on the MFP
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    scan_dir = get_default_scan_folder()
    client_ip = get_client_ip_for_mfp(mfp_ip)
    log(f"스캔 수신 폴더 준비 완료: {scan_dir} (내 PC IP: {client_ip})")

    is_builtin_ftp = protocol.upper() in ("FTP_BUILTIN", "FTP", "내장 FTP 수신 (권장)")

    if dry_run:
        mode_desc = f"내장 FTP 수신 서버(포트 {ftp_port}, 공유폴더 설정 불필요)" if is_builtin_ftp else "SMB 공유폴더"
        log(f"[테스트 모드] {mode_desc} 시작 및 복합기({mfp_ip}) 주소록에 '{scan_name}' 등록 시뮬레이션 완료")
        return ScanSetupResult(
            success=True,
            title="내장 FTP 스캔 수신기 및 주소록 등록 완료 (테스트 모드)",
            detail=f"복합기 스캔 버튼: [{scan_name}] → {scan_dir} ({mode_desc})",
            scan_folder=str(scan_dir),
        )

    if is_builtin_ftp:
        # 1. Start built-in background FTP receiver daemon (works on both Windows & macOS without sharing folders!)
        _, active_port = ensure_background_ftp_agent(scan_dir=scan_dir, port=ftp_port, log_cb=log_cb)
        target_proto = "FTP"
        target_folder = "/"
        target_user = DEFAULT_FTP_USER
        target_pass = DEFAULT_FTP_PASS
        target_port = active_port
    else:
        # Traditional SMB share mode
        if platform.system().lower() == "windows":
            setup_windows_smb_share(scan_dir, "sindohScan", log_cb=log_cb)
        target_proto = "SMB"
        target_folder = "sindohScan"
        target_user = pc_username or os.environ.get("USERNAME") or os.environ.get("USER") or ""
        target_pass = pc_password
        target_port = 445

    # 2. Optional TWAIN driver silent installation
    twain_installed = install_twain_driver_if_present(mfp_ip, log_cb=log_cb)
    if twain_installed:
        log(f"TWAIN 드라이버 설치 완료: {twain_installed}")

    # 3. Register scan shortcut button on the D410s / D420 MFP Web Connection
    ok, msg = register_km_wcd_address_book(
        mfp_ip=mfp_ip,
        scan_name=scan_name,
        client_ip=client_ip,
        protocol=target_proto,
        folder_name=target_folder,
        username=target_user,
        password=target_pass,
        port=target_port,
        admin_password=mfp_admin_password,
        log_cb=log_cb,
    )
    log(msg)

    return ScanSetupResult(
        success=True,
        title="내장 FTP 스캔 서버 가동 및 복합기 주소록 연동 완료" if ok else "내장 FTP 스캔 수신 서버 가동 완료",
        detail=f"스캔 이름: [{scan_name}] | 수신 포트: FTP {target_port} | 저장 폴더: {scan_dir}",
        scan_folder=str(scan_dir),
    )
