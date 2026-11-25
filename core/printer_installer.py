"""
Cross-platform Printer Driver & TCP/IP Port Installer for Windows and macOS.
Supports:
  1. Bundled or user-provided .inf / .zip driver folders (Windows) and .pkg / .dmg / .gz PPDs (macOS)
  2. Automatic Sindoh KM Universal Driver download or local SindohConnect cache reuse
  3. Built-in OS Class Driver fallback (Microsoft PCL6/PS Class Driver on Windows, Generic PCL/PS on macOS)
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional


SINDOH_DEFAULT_DRV_API_WIN = "https://sindohconnect.sindoh.com/api/public/files/download/1OkhnJ7zwhcqAKZp3TUJL5PnkUZA1sKB"
SINDOH_DEFAULT_DRV_API_MAC = "https://sindohconnect.sindoh.com/api/public/files/download/4g1wp37A6GtEWOAEbjFpY6LiVvTqQVpu"


@dataclass
class InstallStepResult:
    success: bool
    title: str
    detail: str
    driver_used: str = ""


def get_project_drivers_dir() -> Path:
    """
    Return the persistent `drivers/` directory.
    - When frozen (PyInstaller --onefile / --onedir): use `%LOCALAPPDATA%/SindohD410Connect/drivers`
      on Windows (or `~/Library/Application Support/SindohD410Connect/drivers` on macOS) so downloaded
      drivers are never written into ephemeral `_MEI` temp folders.
    - When running from source: use `<project>/drivers`.
    """
    if getattr(sys, "frozen", False):
        sys_name = platform.system().lower()
        if sys_name == "windows":
            base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "SindohD410Connect" / "drivers"
        elif sys_name == "darwin":
            base = Path.home() / "Library" / "Application Support" / "SindohD410Connect" / "drivers"
        else:
            base = Path.home() / ".local" / "share" / "SindohD410Connect" / "drivers"
    else:
        base = Path(__file__).resolve().parent.parent / "drivers"
    base.mkdir(parents=True, exist_ok=True)
    (base / "windows").mkdir(exist_ok=True)
    (base / "macos").mkdir(exist_ok=True)
    return base


def _get_candidate_driver_roots() -> List[Path]:
    """Return all driver search roots: next to the executable (if frozen) first, then persistent AppData/project drivers."""
    roots: List[Path] = []
    if getattr(sys, "frozen", False):
        exe_drivers = Path(sys.executable).resolve().parent / "drivers"
        if exe_drivers.is_dir():
            roots.append(exe_drivers)
    persistent = get_project_drivers_dir()
    if persistent not in roots:
        roots.append(persistent)
    return roots


def parse_inf_driver_names(inf_path: Path) -> List[str]:
    """Parse a Windows printer .inf file to extract candidate DriverName strings."""
    try:
        raw = inf_path.read_bytes()
        if b"\x00" in raw[:32]:
            text = raw.decode("utf-16le", errors="ignore")
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("cp949", errors="ignore")
    except Exception:
        return []

    names: List[str] = []
    # Match lines like: "SINDOH D410/D420 Series PCL" = KOAW...
    for m in re.finditer(r'^\s*"([^"]+)"\s*=\s*[A-Za-z0-9_.\-]+', text, re.MULTILINE):
        candidate = m.group(1).strip()
        if any(
            k in candidate.upper()
            for k in ("SINDOH", "D4", "N6", "CM", "PCL", "PS", "SERIES", "GENERIC", "KONICA", "MINOLTA")
        ):
            if candidate not in names:
                names.append(candidate)
    return names


def _filter_real_files(paths: List[Path]) -> List[Path]:
    """Filter out macOS resource fork files (`._*`) and `__MACOSX` metadata directories."""
    result: List[Path] = []
    for p in paths:
        if p.name.startswith("._") or "__MACOSX" in p.parts:
            continue
        if p.suffix.lower() == ".zip":
            if not zipfile.is_zipfile(p):
                if p.name == "KM_Default_Driver.zip":
                    try:
                        p.unlink()
                    except Exception:
                        pass
                continue
        result.append(p)
    return result


def find_local_driver_source(custom_path: Optional[str] = None) -> Optional[Path]:
    """
    Locate driver archive/folder:
    1. User-specified custom path (if provided)
    2. Project `drivers/windows` or `drivers/macos` directory
    3. Existing SindohConnect cache (`%LOCALAPPDATA%/SindohConnect/drivers-cache/KM.zip`)
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            if p.is_file() and p.suffix.lower() == ".zip" and not zipfile.is_zipfile(p):
                return None
            return p

    sys_name = platform.system().lower()

    if sys_name == "windows":
        for drv_root in _get_candidate_driver_roots():
            win_dir = drv_root / "windows"
            if not win_dir.is_dir():
                continue
            infs = _filter_real_files(list(win_dir.rglob("*.inf")))
            if infs:
                return infs[0].parent
            zips = _filter_real_files(list(win_dir.rglob("*.zip")))
            if zips:
                return zips[0]
        # Check SindohConnect local cache on Windows
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            km_cache = Path(local_appdata) / "SindohConnect" / "drivers-cache" / "KM.zip"
            if km_cache.exists() and zipfile.is_zipfile(km_cache):
                return km_cache
    elif sys_name == "darwin":
        for drv_root in _get_candidate_driver_roots():
            mac_dir = drv_root / "macos"
            if not mac_dir.is_dir():
                continue
            for ext in ("*.pkg", "*.gz", "*.ppd", "*.zip", "*.dmg"):
                found = _filter_real_files(list(mac_dir.rglob(ext)))
                if found:
                    return found[0]
        km_mac_cache = Path.home() / "Library" / "Application Support" / "SindohConnect" / "drivers-cache" / "KM.zip"
        if km_mac_cache.exists() and zipfile.is_zipfile(km_mac_cache):
            return km_mac_cache

    return None


def ensure_driver_package(
    custom_path: Optional[str] = None,
    log_cb: Optional[Callable[[str], None]] = None,
) -> Optional[Path]:
    """Find or download the KM/Sindoh PCL driver package."""
    existing = find_local_driver_source(custom_path)
    if existing:
        if log_cb:
            log_cb(f"로컬 드라이버 패키지 확인됨: {existing.name}")
        return existing

    drv_root = get_project_drivers_dir()
    sys_name = platform.system().lower()
    api_url = SINDOH_DEFAULT_DRV_API_WIN if sys_name == "windows" else SINDOH_DEFAULT_DRV_API_MAC
    target_sub = "windows" if sys_name == "windows" else "macos"
    target_zip = drv_root / target_sub / "KM_Default_Driver.zip"

    try:
        if log_cb:
            log_cb("신도리코 통합 드라이버 서버에서 KM 호환 드라이버를 다운로드하는 중...")
        with urllib.request.urlopen(api_url, timeout=30.0) as resp:
            raw_bytes = resp.read()

        # The Sindoh API endpoint returns a JSON metadata payload containing `content.downloadUrl`
        download_url = api_url
        try:
            meta = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(meta, dict) and "content" in meta and "downloadUrl" in meta["content"]:
                download_url = meta["content"]["downloadUrl"]
        except Exception:
            pass

        if download_url != api_url:
            if download_url.startswith("/"):
                download_url = "https://sindohconnect.sindoh.com" + download_url
            with urllib.request.urlopen(download_url, timeout=60.0) as dresp:
                target_zip.write_bytes(dresp.read())
        else:
            target_zip.write_bytes(raw_bytes)

        if target_zip.exists() and zipfile.is_zipfile(target_zip):
            if log_cb:
                log_cb(f"드라이버 다운로드 완료 ({target_zip.stat().st_size // (1024*1024)}MB)")
            return target_zip
        elif target_zip.exists():
            target_zip.unlink(missing_ok=True)
    except Exception as e:
        if target_zip.exists():
            target_zip.unlink(missing_ok=True)
        if log_cb:
            log_cb(f"온라인 드라이버 다운로드 생략 (OS 내장 호환 드라이버 사용 예정): {e}")

    return None


def _is_windows_admin() -> bool:
    if platform.system().lower() != "windows":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _find_installed_windows_driver() -> Optional[str]:
    """Check if a Sindoh / Konica Minolta PCL driver is already installed in Windows."""
    if platform.system().lower() != "windows":
        return None
    try:
        ps_check = (
            "Get-PrinterDriver -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -match 'SINDOH|KONICA MINOLTA' } | "
            "Select-Object -First 1 -ExpandProperty Name"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_check],
            capture_output=True,
            text=True,
            timeout=6,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        name = (proc.stdout or "").strip()
        return name if name else None
    except Exception:
        return None


def install_printer_windows(
    ip: str,
    printer_name: str,
    set_default: bool = False,
    custom_driver_path: Optional[str] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> InstallStepResult:
    """
    Install printer on Windows using pnputil + PowerShell PrintManagement cmdlets.
    Mirrors SindohConnect's exact Windows installation pipeline while adding D410/D410s/D420 support.
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    port_name = f"IP_{ip}"
    log(f"[Windows] 프린터 설치 준비: {printer_name} ({port_name})")

    existing_win_drv = _find_installed_windows_driver() if not custom_driver_path else None
    if existing_win_drv:
        log(f"이미 설치된 신도리코/KM 드라이버 확인됨: {existing_win_drv}")
        src = None
    else:
        src = ensure_driver_package(custom_driver_path, log_cb=log_cb)
    extracted_dir: Optional[Path] = None
    inf_files: List[Path] = []
    candidate_driver_names: List[str] = [existing_win_drv] if existing_win_drv else []

    try:
        if src:
            if src.is_file() and src.suffix.lower() == ".zip" and zipfile.is_zipfile(src):
                extracted_dir = Path(tempfile.mkdtemp(prefix="sindoh_d410_drv_"))
                log(f"드라이버 압축 해제 중: {src.name}")
                with zipfile.ZipFile(src, "r") as zf:
                    zf.extractall(extracted_dir)
                inf_files = _filter_real_files(list(extracted_dir.rglob("*.inf")))
            elif src.is_file() and src.suffix.lower() == ".inf":
                inf_files = [src]
            elif src.is_dir():
                inf_files = _filter_real_files(list(src.rglob("*.inf")))

        for inf in inf_files:
            parsed = parse_inf_driver_names(inf)
            for n in parsed:
                if n not in candidate_driver_names:
                    candidate_driver_names.append(n)

        # Prioritize color-capable D410 / D420 / D470 / Universal / PS Class Driver (avoid monochrome-only PCL6 Class Driver)
        for fallback_name in (
            "SINDOH D410/D420 Series PCL",
            "SINDOH D410/D420 PCL",
            "SINDOH D400 Series PCL",
            "SINDOH D470/D740/CM Series PCL",
            "KONICA MINOLTA Universal PCL",
            "Microsoft PS Class Driver",
            "Microsoft IPP Class Driver",
            "Microsoft PCL6 Class Driver",
        ):
            if fallback_name not in candidate_driver_names:
                candidate_driver_names.append(fallback_name)

        if dry_run:
            chosen = candidate_driver_names[0] if candidate_driver_names else "Microsoft PCL6 Class Driver"
            log(f"[테스트 모드] 포트 {port_name} 및 드라이버 '{chosen}' 매핑 시뮬레이션 완료")
            return InstallStepResult(
                success=True,
                title="프린터 드라이버 설치 완료 (테스트 모드)",
                detail=f"{printer_name} ({ip}) - 드라이버: {chosen}",
                driver_used=chosen,
            )

        # Step 1: Stage INF files via pnputil
        for inf in inf_files:
            log(f"윈도우 드라이버 저장소에 INF 등록 중: {inf.name}")
            subprocess.run(
                ["pnputil.exe", "/add-driver", str(inf), "/install"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        # Step 2: Run PowerShell script to register driver, TCP/IP port, and printer queue
        candidates_ps = ",".join(f"'{c.replace(chr(39), '')}'" for c in candidate_driver_names)
        ps_script = f"""
$ErrorActionPreference = 'Continue'
$ip = '{ip}'
$portName = '{port_name}'
$printerName = '{printer_name}'
$candidates = @({candidates_ps})
$chosenDriver = $null

foreach ($n in $candidates) {{
    $d = Get-PrinterDriver -Name $n -ErrorAction SilentlyContinue
    if (-not $d) {{
        Add-PrinterDriver -Name $n -ErrorAction SilentlyContinue | Out-Null
        $d = Get-PrinterDriver -Name $n -ErrorAction SilentlyContinue
    }}
    if ($d) {{
        $chosenDriver = $d.Name
        break
    }}
}}

if (-not $chosenDriver) {{
    $existing = Get-PrinterDriver | Where-Object {{ $_.Name -match 'SINDOH|KONICA|PS Class|IPP Class' }} | Select-Object -First 1
    if ($existing) {{
        $chosenDriver = $existing.Name
    }}
}}

if (-not $chosenDriver) {{
    & rundll32.exe printui.dll,PrintUIEntry /ia /m "Microsoft PS Class Driver" /h x64 /f "$env:windir\\inf\\ntprint.inf" | Out-Null
    Add-PrinterDriver -Name "Microsoft PS Class Driver" -ErrorAction SilentlyContinue | Out-Null
    $dPs = Get-PrinterDriver -Name "Microsoft PS Class Driver" -ErrorAction SilentlyContinue
    if ($dPs) {{
        $chosenDriver = $dPs.Name
    }} else {{
        & rundll32.exe printui.dll,PrintUIEntry /ia /m "Microsoft PCL6 Class Driver" /h x64 /f "$env:windir\\inf\\ntprint.inf" | Out-Null
        Add-PrinterDriver -Name "Microsoft PCL6 Class Driver" -ErrorAction SilentlyContinue | Out-Null
        $chosenDriver = "Microsoft PCL6 Class Driver"
    }}
}}

if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {{
    Add-PrinterPort -Name $portName -PrinterHostAddress $ip -ErrorAction Stop
}}

if (Get-Printer -Name $printerName -ErrorAction SilentlyContinue) {{
    Remove-Printer -Name $printerName -ErrorAction SilentlyContinue
}}

Add-Printer -Name $printerName -DriverName $chosenDriver -PortName $portName -ErrorAction Stop
try {{
    Set-PrintConfiguration -PrinterName $printerName -Color $true -DuplexingMode OneSided -ErrorAction SilentlyContinue
}} catch {{}}
try {{
    Set-PrintConfiguration -PrinterName $printerName -Color $true -ErrorAction SilentlyContinue
}} catch {{}}

if (${'true' if set_default else 'false'}) {{
    (New-Object -ComObject WScript.Network).SetDefaultPrinter($printerName)
}}

Write-Output "SUCCESS_DRIVER=$chosenDriver"
"""
        log("TCP/IP 포트 생성 및 프린터 큐 등록 실행 중...")
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        m = re.search(r"SUCCESS_DRIVER=(.+)", out)
        if proc.returncode == 0 and m:
            drv_used = m.group(1).strip()
            log(f"프린터 등록 완료: {printer_name} (드라이버: {drv_used})")
            return InstallStepResult(
                success=True,
                title="프린터 설치 성공",
                detail=f"이름: {printer_name} / 포트: {port_name} / 드라이버: {drv_used}",
                driver_used=drv_used,
            )
        else:
            err_summary = out.strip().splitlines()[-1] if out.strip() else "알 수 없는 오류"
            log(f"프린터 등록 오류: {err_summary}")
            return InstallStepResult(
                success=False,
                title="프린터 설치 실패 (관리자 권한 확인 필요)",
                detail=err_summary[:200],
            )
    finally:
        if extracted_dir and extracted_dir.exists():
            shutil.rmtree(extracted_dir, ignore_errors=True)


def _find_installed_macos_ppd(printer_name: str = "") -> Optional[Path]:
    """Check if a Sindoh / Konica Minolta PPD is already installed in `/Library/Printers/PPDs/Contents/Resources`."""
    ppd_root = Path("/Library/Printers/PPDs/Contents/Resources")
    if ppd_root.exists():
        # 1. Match specific model code in printer_name first (e.g. D450 -> *D450*, D410 -> *D410*)
        m = re.search(r"(D3[0-9]{2}|D4[0-9]{2}|D7[0-9]{2}|CM[0-9]{4})", printer_name.upper())
        if m:
            code = m.group(1)
            specific = sorted(ppd_root.glob(f"*{code}*"))
            if specific:
                return specific[0]

        for pat in ("*D410*", "*D420*", "*D450*", "*D470*", "*SINDOH*", "*224e*", "*284e*", "*KONICA*"):
            matches = sorted(ppd_root.glob(pat))
            if matches:
                return matches[0]
    return None


def install_printer_macos(
    ip: str,
    printer_name: str,
    set_default: bool = False,
    custom_driver_path: Optional[str] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> InstallStepResult:
    """
    Install printer on macOS with zero password prompts by default:
      1. First try native IPP Everywhere / AirPrint (`ipp://<ip>/ipp/print -m everywhere`), which queries
         the Sindoh D410/D420 directly to build an exact model-specific PPD (A3/A4/B4, Color, Duplex, Toner levels)
         in <0.5s without any `.pkg` download or administrator password popup!
      2. Or use an already-installed Sindoh PPD in `/Library/Printers/PPDs/Contents/Resources/` with `socket://<ip>:9100`.
      3. Only if the user explicitly provided a custom `.pkg` path (`custom_driver_path`), install that `.pkg`.
    """
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    queue_name = re.sub(r"[^A-Za-z0-9_]", "_", printer_name).strip("_") or "SINDOH_D410_D420"
    log(f"[macOS] CUPS 프린터 설치 준비: {printer_name} (Queue: {queue_name}, IP: {ip})")

    extracted_dir: Optional[Path] = None

    try:
        if dry_run:
            log(f"[테스트 모드] macOS lpadmin -p {queue_name} -v ipp://{ip}/ipp/print -m everywhere 시뮬레이션 완료")
            return InstallStepResult(
                success=True,
                title="macOS 프린터 설치 완료 (테스트 모드)",
                detail=f"CUPS 큐: {queue_name} (ipp://{ip}/ipp/print)",
                driver_used="SINDOH Native IPP Everywhere",
            )

        pkg_file: Optional[Path] = None
        ppd_file: Optional[Path] = None

        # Only use/install a custom driver package if the user explicitly specified `custom_driver_path`
        if custom_driver_path:
            src = find_local_driver_source(custom_driver_path)
            if src:
                if src.is_file() and src.suffix.lower() == ".zip" and zipfile.is_zipfile(src):
                    extracted_dir = Path(tempfile.mkdtemp(prefix="sindoh_mac_drv_"))
                    with zipfile.ZipFile(src, "r") as zf:
                        zf.extractall(extracted_dir)
                    pkgs = _filter_real_files(list(extracted_dir.rglob("*.pkg")))
                    ppds = _filter_real_files(list(extracted_dir.rglob("*.gz")) + list(extracted_dir.rglob("*.ppd")))
                    if pkgs:
                        pkg_file = pkgs[0]
                    if ppds:
                        ppd_file = ppds[0]
                elif src.is_file() and src.suffix.lower() == ".pkg":
                    pkg_file = src
                elif src.is_file() and src.suffix.lower() in (".gz", ".ppd"):
                    ppd_file = src

            if pkg_file and not ppd_file:
                log(f"지정된 macOS 드라이버 패키지 설치 중: {pkg_file.name}")
                osa_cmd = (
                    f'do shell script "installer -pkg \\"{pkg_file}\\" -target /" '
                    f'with prompt "신도리코 프린터 드라이버({pkg_file.name})를 설치하려면 맥 암호를 입력해 주세요." '
                    f'with administrator privileges'
                )
                subprocess.run(["osascript", "-e", osa_cmd], capture_output=True, text=True)
                ppd_file = _find_installed_macos_ppd(printer_name)

        # Remove any existing queue with the same name
        subprocess.run(["lpadmin", "-x", queue_name], capture_output=True)

        # Priority 1: If no custom PPD was forced, register via native IPP Everywhere (`ipp://<ip>/ipp/print -m everywhere`)
        # This queries the Sindoh MFP directly for its exact capabilities (A3/A4, Color, Duplex, Supplies) with ZERO password prompt!
        if not ppd_file:
            log("복합기에서 직접 기기 규격(A3/A4·컬러·양면·토너 정보)을 읽어 무설치(무암호) 등록 중...")
            cmd_ipp = [
                "lpadmin",
                "-p",
                queue_name,
                "-D",
                printer_name,
                "-L",
                ip,
                "-E",
                "-v",
                f"ipp://{ip}/ipp/print",
                "-m",
                "everywhere",
                "-o",
                "printer-is-shared=false",
            ]
            proc = subprocess.run(cmd_ipp, capture_output=True, text=True)
            if proc.returncode == 0:
                if set_default:
                    subprocess.run(["lpadmin", "-d", queue_name], capture_output=True)
                drv_label = "SINDOH Native IPP Everywhere (무암호 직결)"
                log(f"macOS 프린터 등록 완료: {printer_name} ({drv_label})")
                return InstallStepResult(
                    success=True,
                    title="macOS 프린터 설치 완료",
                    detail=f"{printer_name} ({ip}) - {drv_label}",
                    driver_used=drv_label,
                )

        # Priority 2: Socket 9100 with installed PPD or Generic PostScript/PCL fallback
        cmd = [
            "lpadmin",
            "-p",
            queue_name,
            "-D",
            printer_name,
            "-L",
            ip,
            "-E",
            "-v",
            f"socket://{ip}:9100",
        ]
        if ppd_file and ppd_file.exists():
            cmd.extend(["-P", str(ppd_file)])
            drv_label = ppd_file.name
        else:
            cmd.extend(["-m", "drv:///sample.drv/generic.ppd"])
            drv_label = "macOS Generic PostScript/PCL Driver"

        cmd.extend(["-o", "printer-is-shared=false"])
        log(f"CUPS lpadmin 포트 등록 실행 중 ({drv_label})...")
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            if set_default:
                subprocess.run(["lpadmin", "-d", queue_name], capture_output=True)
            log(f"macOS 프린터 등록 완료: {printer_name}")
            return InstallStepResult(
                success=True,
                title="macOS 프린터 설치 완료",
                detail=f"{printer_name} ({ip}) - {drv_label}",
                driver_used=drv_label,
            )
        else:
            err = (proc.stderr or proc.stdout or "lpadmin 실행 오류").strip()
            return InstallStepResult(success=False, title="macOS 프린터 등록 실패", detail=err)

    finally:
        if extracted_dir and extracted_dir.exists():
            shutil.rmtree(extracted_dir, ignore_errors=True)


def install_printer_cross_platform(
    ip: str,
    printer_name: str,
    set_default: bool = False,
    custom_driver_path: Optional[str] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> InstallStepResult:
    """Dispatch printer installation according to current OS (Windows vs macOS)."""
    sys_name = platform.system().lower()
    if sys_name == "windows":
        return install_printer_windows(
            ip=ip,
            printer_name=printer_name,
            set_default=set_default,
            custom_driver_path=custom_driver_path,
            log_cb=log_cb,
            dry_run=dry_run,
        )
    elif sys_name == "darwin":
        return install_printer_macos(
            ip=ip,
            printer_name=printer_name,
            set_default=set_default,
            custom_driver_path=custom_driver_path,
            log_cb=log_cb,
            dry_run=dry_run,
        )
    else:
        # Linux / CUPS fallback uses same lpadmin flow as macOS
        return install_printer_macos(
            ip=ip,
            printer_name=printer_name,
            set_default=set_default,
            custom_driver_path=custom_driver_path,
            log_cb=log_cb,
            dry_run=dry_run,
        )
