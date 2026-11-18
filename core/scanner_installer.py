"""
Cross-platform Scanner Setup & MFP Address Book Registration for D410 / D410s / D420.
Supports:
  1. Built-in WebDAV Scan Receiver (`WEBDAV_BUILTIN`, Default, matching Sindoh Connect!):
     - Starts a lightweight local WebDAV HTTP receiver daemon on port 50080 (single port, no passive port range, no SMB sharing needed!)
     - Registers the PC's IP, port 50080, path `/`, and WebDAV credentials directly into the D410s/D420 Web Connection (`/wcd/scan.cgi`, `func=PSL_C_A_DAV_PTR`)
  2. Built-in FTP Scan Receiver (`FTP_BUILTIN`, port 2121, `func=PSL_C_A_FTP_PTR`)
  3. Traditional SMB Shared Folder (`SMB`) registration
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
    DEFAULT_WEBDAV_PORT,
    ensure_background_ftp_agent,
    get_default_scan_dir,
    save_scan_profile,
)


@dataclass
class ScanSetupResult:
    success: bool
    title: str
    detail: str
    scan_folder: str = ""


def get_default_scan_folder() -> Path:
    """Return `Desktop/sindohScan` on Windows (including OneDrive Desktop) & macOS."""
    return get_default_scan_dir()


def get_client_ip_for_mfp(mfp_ip: str) -> str:
    """Determine the local IPv4 address on the same interface that routes to `mfp_ip`."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect((mfp_ip, 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_search_key_for_name(scan_name: str) -> str:
    """Return the Konica Minolta / Sindoh WCD SearchKey tab (`Abc`, `Def`, ..., `Other`) for `scan_name`."""
    if not scan_name:
        return "Other"
    ch = scan_name.strip()[0].upper()
    if ch in "ABC":
        return "Abc"
    if ch in "DEF":
        return "Def"
    if ch in "GHI":
        return "Ghi"
    if ch in "JKL":
        return "Jkl"
    if ch in "MNO":
        return "Mno"
    if ch in "PQRS":
        return "Pqrs"
    if ch in "TUV":
        return "Tuv"
    if ch in "WXYZ":
        return "Wxyz"
    return "Other"


def find_existing_wcd_entry_ip(
    mfp_ip: str,
    scan_name: str,
    admin_password: str = "",
) -> Optional[str]:
    """
    Check if `scan_name` is already registered in `/wcd/abbr.xml` on `mfp_ip`.
    Returns the registered host/IP address string if found, or `None` if not found.
    """
    target = scan_name.strip().lower()
    if not mfp_ip or not target:
        return None

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
    try:
        opener.open(f"{base_url}/wcd/index.html", timeout=2.0).read()
        try:
            opener.open(f"{base_url}/wcd/system_device.xml", timeout=2.0).read()
        except Exception:
            pass
        if admin_password:
            login_payload = urllib.parse.urlencode(
                {"func": "PSL_LP0_LOG", "R_ADM": "Admin", "password": admin_password}
            ).encode("utf-8")
            try:
                opener.open(f"{base_url}/wcd/ulogin.cgi", data=login_payload, timeout=2.0).read()
            except Exception:
                pass

        abbr_xml = opener.open(f"{base_url}/wcd/abbr.xml", timeout=2.5).read().decode("utf-8", errors="ignore")
        for m in re.finditer(r"<Abbr>(.*?)</Abbr>", abbr_xml, re.DOTALL):
            block = m.group(1)
            nm = re.search(r"<Name>([^<]+)</Name>", block)
            if nm and nm.group(1).strip().lower() == target:
                addr = re.search(r"<(?:Address|Host)>([^<]+)</(?:Address|Host)>", block)
                return addr.group(1).strip() if addr else "알 수 없는 IP"
    except Exception:
        pass
    return None


def register_km_wcd_address_book(
    mfp_ip: str,
    scan_name: str,
    client_ip: str,
    protocol: str = "WEBDAV",  # "WEBDAV", "FTP", or "SMB"
    folder_name: str = "/",
    username: str = DEFAULT_FTP_USER,
    password: str = DEFAULT_FTP_PASS,
    port: int = DEFAULT_WEBDAV_PORT,
    admin_password: str = "",
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """
    Register a one-touch scan destination on Konica Minolta / Sindoh D410 / D410s / D420
    Web Connection:
      1. Establish session via `/wcd/index.html` -> `/wcd/system_device.xml` -> `/wcd/abbr.xml`
      2. Remove existing address book entry with the same name (if any) to prevent duplicates
      3. Enter New Registration state via `POST /wcd/scan.cgi` (`func=PSL_C_ABR_NEW`, `S_SMO=WebDav|Ftp|Smb`)
      4. Submit destination via `POST /wcd/scan.cgi` (`func=PSL_C_A_DAV_PTR`, `PSL_C_A_FTP_PTR`, or `PSL_C_A_SMB_PTR`)
      5. Verify in `/wcd/abbr.xml` that `<Name>{scan_name}</Name>` is registered
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
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("Accept-Language", "ko,en-US;q=0.7,en;q=0.3"),
    ]

    base_url = f"http://{mfp_ip}"
    try:
        # 1. Establish WCD session cookie via /wcd/index.html & /wcd/system_device.xml
        for scheme in ("http", "https"):
            test_url = f"{scheme}://{mfp_ip}/wcd/index.html"
            try:
                with opener.open(test_url, timeout=3.0) as resp:
                    if resp.status == 200:
                        resp.read()
                        base_url = f"{scheme}://{mfp_ip}"
                        break
            except Exception:
                continue

        try:
            opener.open(f"{base_url}/wcd/system_device.xml", timeout=3.0).read()
        except Exception:
            pass

        # Optional Admin login if admin_password was explicitly provided
        if admin_password:
            login_payload = urllib.parse.urlencode(
                {"func": "PSL_LP0_LOG", "R_ADM": "Admin", "password": admin_password}
            ).encode("utf-8")
            try:
                opener.open(f"{base_url}/wcd/ulogin.cgi", data=login_payload, timeout=3.0).read()
            except Exception:
                pass

        # 2. Read /wcd/abbr.xml and check if an entry with `scan_name` already exists (+ extract h_token if present)
        abbr_xml = ""
        token = ""
        try:
            with opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.5) as resp:
                abbr_xml = resp.read().decode("utf-8", errors="ignore")
                tm = re.search(r"<Token>([^<]+)</Token>", abbr_xml)
                if tm:
                    token = tm.group(1).strip()
        except Exception:
            pass

        for m in re.finditer(r"<Abbr>(.*?)</Abbr>", abbr_xml, re.DOTALL):
            block = m.group(1)
            no_m = re.search(r"<AbbrNo>(\d+)</AbbrNo>", block)
            nm_m = re.search(r"<Name>([^<]+)</Name>", block)
            if no_m and nm_m:
                existing_no, existing_name = no_m.group(1).strip(), nm_m.group(1).strip()
                if existing_name.lower() == scan_name.strip().lower():
                    log(f"기존 동일 이름 주소록 항목([{existing_name}], 번호 #{existing_no}) 갱신을 위해 정리 중...")
                    del_payload = urllib.parse.urlencode(
                        {
                            "func": "PSL_C_ABR_DEL",
                            "C_ABR_H_NUM": existing_no,
                            "C_ABR_H_AKI": "Public",
                            "C_ABR_H_FAV": "",
                        }
                    ).encode("utf-8")
                    try:
                        opener.open(f"{base_url}/wcd/scan.cgi", data=del_payload, timeout=4.0).read()
                    except Exception:
                        pass
        try:
            abbr_xml = opener.open(f"{base_url}/wcd/abbr.xml", timeout=3.5).read().decode("utf-8", errors="ignore")
        except Exception:
            pass

        # 3. Enter "New Registration" state (`PSL_C_ABR_NEW`) and load `/wcd/abbr_edit.xml`
        proto_upper = protocol.upper()
        is_webdav = "DAV" in proto_upper
        is_ftp = not is_webdav and proto_upper.startswith("FTP")

        if is_webdav:
            send_mode = "WebDav"
        elif is_ftp:
            send_mode = "Ftp"
        else:
            send_mode = "Smb"

        new_payload = urllib.parse.urlencode(
            {
                "func": "PSL_C_ABR_NEW",
                "H_NEW": "new",
                "S_SMO": send_mode,
                "H_AKI": "Public",
                "H_FAV": "",
            }
        ).encode("utf-8")
        opener.open(f"{base_url}/wcd/scan.cgi", data=new_payload, timeout=4.0).read()
        try:
            edit_xml = opener.open(f"{base_url}/wcd/abbr_edit.xml", timeout=3.5).read().decode("utf-8", errors="ignore")
            tm2 = re.search(r"<Token>([^<]+)</Token>", edit_xml)
            if tm2:
                token = tm2.group(1).strip()
        except Exception:
            pass

        # 4. Submit Address Book registration (`PSL_C_A_DAV_PTR`, `PSL_C_A_FTP_PTR`, or `PSL_C_A_SMB_PTR`)
        search_key = _get_search_key_for_name(scan_name)

        if is_webdav:
            # Exact parameter structure matching SindohConnect.Mfp.Core's PSL_C_A_DAV_PTR implementation
            dav_dir = folder_name if folder_name else "/"
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
                "S_SER": search_key,
                "C_WEL": "on",
                "T_HOS": client_ip,
                "T_DIR": dav_dir,
                "T_LOG": username or DEFAULT_FTP_USER,
                "P_PAS": password,
                "T_POR": str(port),
                "S_SSL": "Off",
                "S_PRX": "Off",
                "H_PEX": "false",
                "R_REF": "Level",
                "S_LEV": "0",
            }
        elif is_ftp:
            clean_dir = "." if folder_name in ("", "/") else (folder_name or ".")
            form_fields = {
                "func": "PSL_C_A_FTP_PTR",
                "H_NUM": "new",
                "H_AKI": "Public",
                "H_FAV": "",
                "H_Kind": "Ftp",
                "B_Name": "",
                "B_Dest": "",
                "R_NUM_": "Space",
                "T_NAM": scan_name,
                "H_Result": "SendOk",
                "C_LANG": "Other",
                "T_FURI": scan_name,
                "S_SER": search_key,
                "C_WEL": "WellUse",
                "T_HOS": client_ip,
                "T_DIR": clean_dir,
                "T_LOG": username or DEFAULT_FTP_USER,
                "P_PAS": password,
                "S_ANO": "false" if username else "true",
                "S_PAS": "true",
                "S_PRX": "false",
                "H_PEX": "false",
                "T_POR": str(port),
                "R_REF": "Level",
                "S_LEV": "0",
            }
        else:
            form_fields = {
                "func": "PSL_C_A_SMB_PTR",
                "H_NUM": "new",
                "H_AKI": "Public",
                "H_FAV": "",
                "R_NUM_": "Space",
                "T_NAM": scan_name,
                "C_LANG": "Other",
                "T_FURI": scan_name,
                "S_SER": search_key,
                "C_WEL": "WellUse",
                "T_HOS": client_ip,
                "T_DIR": folder_name or "sindohScan",
                "T_LOG": username,
                "P_PAS": password,
                "R_REF": "Level",
            }

        if token:
            form_fields["h_token"] = token

        encoded = urllib.parse.urlencode(form_fields).encode("utf-8")
        mode_label = "WebDAV" if is_webdav else ("FTP" if is_ftp else "SMB")
        log(f"복합기 웹 컨트롤러({base_url}/wcd/scan.cgi)에 {mode_label} 주소록 [{scan_name}] ({client_ip}:{port}) 등록 중...")
        with opener.open(f"{base_url}/wcd/scan.cgi", data=encoded, timeout=5.0) as resp:
            result_xml = resp.read().decode("utf-8", errors="ignore")

        # 5. Verify in /wcd/abbr.xml that the new entry exists
        verify_xml = ""
        try:
            with opener.open(f"{base_url}/wcd/abbr.xml", timeout=4.0) as resp:
                verify_xml = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            pass

        if f"<Name>{scan_name}</Name>" in verify_xml or "DeviceExportExec" in result_xml or "wait.xsl" in result_xml:
            return True, f"복합기 주소록(즐겨찾기 포함)에 {mode_label} '{scan_name}' ({client_ip}:{port}) 원터치 스캔 버튼이 등록되었습니다."
        return False, f"복합기 주소록 등록 응답 확인 필요: {result_xml[:160]}"
    except Exception as e:
        return False, f"복합기 웹 주소록 자동 등록 오류 ({e})"


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
    protocol: str = "WEBDAV_BUILTIN",  # "WEBDAV_BUILTIN" (default), "FTP_BUILTIN", or "SMB"
    pc_username: str = "",
    pc_password: str = "",
    mfp_admin_password: str = "",
    ftp_port: int = DEFAULT_FTP_PORT,
    webdav_port: int = DEFAULT_WEBDAV_PORT,
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> ScanSetupResult:
    """
    Complete cross-platform scan setup:
    1. Creates `Desktop/sindohScan`
    2. When `protocol` is WebDAV (Default, matching Sindoh Connect):
       - Starts the zero-config Built-in WebDAV + FTP Scan Receiver Daemon (port 50080)
       - Registers the WebDAV shortcut button (`PSL_C_A_DAV_PTR`) on the D410s/D420 MFP Web Connection
    3. When `protocol` is FTP:
       - Starts the Built-in WebDAV + FTP Scan Receiver Daemon (port 2121)
       - Registers the FTP shortcut button (`PSL_C_A_FTP_PTR`) on the MFP
    4. When `protocol` is SMB:
       - Configures Windows SMB folder share and registers SMB shortcut on the MFP
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    scan_dir = get_default_scan_folder()
    client_ip = get_client_ip_for_mfp(mfp_ip)
    log(f"스캔 수신 폴더 준비 완료: {scan_dir} (내 PC IP: {client_ip})")

    proto_u = protocol.upper()
    is_builtin_webdav = "DAV" in proto_u
    is_builtin_ftp = not is_builtin_webdav and "FTP" in proto_u

    if dry_run:
        if is_builtin_webdav:
            mode_desc = f"내장 WebDAV 수신 서버(포트 {webdav_port}, 신도 원클릭 방식)"
        elif is_builtin_ftp:
            mode_desc = f"내장 FTP 수신 서버(포트 {ftp_port})"
        else:
            mode_desc = "SMB 공유폴더"
        log(f"[테스트 모드] {mode_desc} 시작 및 복합기({mfp_ip}) 주소록에 '{scan_name}' 등록 시뮬레이션 완료")
        return ScanSetupResult(
            success=True,
            title=f"스캔 수신기 및 주소록 등록 완료 (테스트 모드)",
            detail=f"복합기 스캔 버튼: [{scan_name}] → {scan_dir} ({mode_desc})",
            scan_folder=str(scan_dir),
        )

    if is_builtin_webdav:
        # 1. Start built-in background WebDAV/FTP receiver daemon
        _, active_dav_port, _ = ensure_background_ftp_agent(
            scan_dir=scan_dir, port=ftp_port, webdav_port=webdav_port, log_cb=log_cb
        )
        target_proto = "WEBDAV"
        target_folder = "/"
        target_user = DEFAULT_FTP_USER
        target_pass = DEFAULT_FTP_PASS
        target_port = active_dav_port
    elif is_builtin_ftp:
        _, _, active_ftp_port = ensure_background_ftp_agent(
            scan_dir=scan_dir, port=ftp_port, webdav_port=webdav_port, log_cb=log_cb
        )
        target_proto = "FTP"
        target_folder = "."
        target_user = DEFAULT_FTP_USER
        target_pass = DEFAULT_FTP_PASS
        target_port = active_ftp_port
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

    # 4. Persist profile AFTER foreground registration completes so the background IP sync daemon never races with us
    if is_builtin_webdav or is_builtin_ftp:
        save_scan_profile(
            mfp_ip=mfp_ip,
            scan_name=scan_name,
            port=target_port,
            admin_password=mfp_admin_password,
            protocol=target_proto,
        )

    proto_display = "WebDAV" if is_builtin_webdav else ("FTP" if is_builtin_ftp else "SMB")
    return ScanSetupResult(
        success=True,
        title=f"내장 {proto_display} 스캔 서버 가동 및 복합기 주소록 연동 완료"
        if ok
        else f"내장 {proto_display} 스캔 수신 서버 가동 완료",
        detail=f"스캔 이름: [{scan_name}] | 수신 포트: {proto_display} {target_port} | 저장 폴더: {scan_dir}",
        scan_folder=str(scan_dir),
    )
