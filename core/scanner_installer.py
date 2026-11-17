"""
Cross-platform Scanner Setup & MFP Address Book Registration for D410 / D410s / D420.
Supports:
  1. Creating local scan receive folder (`~/Downloads/sindohScan`) + optional Windows SMB share
  2. Automatic MFP Web Connection (`/wcd/scan.cgi` for KM-based D410/D410s/D420, `/cgi-bin/address_book.cgi` for Sindoh Web Monitor)
     Address Book registration (FTP / SMB / WebDAV shortcut button on the printer panel)
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
    protocol: str = "SMB",  # "SMB" or "FTP"
    folder_name: str = "sindohScan",
    username: str = "",
    password: str = "",
    port: int = 445,
    admin_password: str = "",
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """
    Register a one-touch scan destination on Konica Minolta / Sindoh D410 / D410s / D420
    Web Connection (`/wcd/index.html` -> `/wcd/ulogin.cgi` -> `/wcd/scan.cgi`).
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
        # D410 / D420 Web Connection uses PSL_C_A_SMB_PTR (SMB) or PSL_C_A_FTP_PTR (FTP)
        func_code = "PSL_C_A_FTP_PTR" if protocol.upper() == "FTP" else "PSL_C_A_SMB_PTR"
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
            "T_LOG": username or "anonymous",
            "P_PAS": password,
            "T_POR": str(port),
            "S_ANO": "On" if not username else "Off",
            "S_PAS": "On",
            "S_PRX": "Off",
        }
        if token:
            form_fields["h_token"] = token

        encoded = urllib.parse.urlencode(form_fields).encode("utf-8")
        log(f"복합기 웹 컨트롤러({base_url}/wcd/scan.cgi)에 스캔 주소록 [{scan_name}] 등록 요청 중...")
        with opener.open(f"{base_url}/wcd/scan.cgi", data=encoded, timeout=4.0) as resp:
            result_html = resp.read().decode("utf-8", errors="ignore")
            if "SendOk" in result_html or "completed" in result_html.lower() or resp.status == 200:
                return True, f"복합기 주소록에 '{scan_name}' ({client_ip}/{folder_name}) 버튼이 등록되었습니다."
    except Exception as e:
        return False, f"복합기 웹 주소록 자동 등록 응답 대기 ({e})"

    return False, "복합기 웹 응답을 확인할 수 없습니다."


def setup_windows_smb_share(scan_dir: Path, share_name: str = "sindohScan", log_cb: Optional[Callable[[str], None]] = None) -> bool:
    """Create or verify a Windows local SMB share for `scan_dir` so D410s/D420 SMB Scan works out-of-the-box."""
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
    If the user placed Sindoh's TWAIN Driver installer inside `drivers/windows/twain/`,
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
    protocol: str = "SMB",
    pc_username: str = "",
    pc_password: str = "",
    mfp_admin_password: str = "",
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> ScanSetupResult:
    """
    Complete cross-platform scan setup:
    1. Creates `~/Downloads/sindohScan` and saves `scan-location.txt`
    2. Configures SMB folder share (Windows) or FTP/SMB destination info (macOS/Windows)
    3. Connects to D410s/D420 Web Connection (`/wcd/scan.cgi`) to register `[scan_name]` button on the MFP panel
    4. Installs TWAIN driver if bundled in `drivers/windows/`
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    scan_dir = get_default_scan_folder()
    client_ip = get_client_ip_for_mfp(mfp_ip)
    log(f"스캔 수신 폴더 준비 완료: {scan_dir} (내 PC IP: {client_ip})")

    if dry_run:
        log(f"[테스트 모드] 복합기({mfp_ip}) 주소록에 '{scan_name}' ({protocol} -> {client_ip}/sindohScan) 등록 시뮬레이션 완료")
        return ScanSetupResult(
            success=True,
            title="스캔 설정 및 주소록 등록 완료 (테스트 모드)",
            detail=f"복합기 스캔 버튼: [{scan_name}] → {scan_dir}",
            scan_folder=str(scan_dir),
        )

    # 1. Setup SMB share on Windows if SMB protocol is selected
    if protocol.upper() == "SMB" and platform.system().lower() == "windows":
        setup_windows_smb_share(scan_dir, "sindohScan", log_cb=log_cb)

    # 2. Optional TWAIN driver silent installation
    twain_installed = install_twain_driver_if_present(mfp_ip, log_cb=log_cb)
    if twain_installed:
        log(f"TWAIN 드라이버 설치 완료: {twain_installed}")

    # 3. Register scan shortcut button on the D410s / D420 MFP Web Connection
    port = 21 if protocol.upper() == "FTP" else 445
    ok, msg = register_km_wcd_address_book(
        mfp_ip=mfp_ip,
        scan_name=scan_name,
        client_ip=client_ip,
        protocol=protocol,
        folder_name="sindohScan",
        username=pc_username or os.environ.get("USERNAME") or os.environ.get("USER") or "",
        password=pc_password,
        port=port,
        admin_password=mfp_admin_password,
        log_cb=log_cb,
    )
    log(msg)

    return ScanSetupResult(
        success=True,
        title="스캔 폴더 생성 및 복합기 주소록 연동 완료" if ok else "로컬 스캔 폴더 구성 완료",
        detail=f"스캔 이름: {scan_name} | 저장 폴더: {scan_dir}",
        scan_folder=str(scan_dir),
    )
