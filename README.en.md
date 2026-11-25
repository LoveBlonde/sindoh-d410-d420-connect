# D410 / D420 Connect — One-Click Printer & Scanner Installer (Windows & macOS)

**🌐 Language: [한국어](README.md) | [English](README.en.md) | [中文](README.zh.md) | [日本語](README.ja.md)**

> **Supported models**: SINDOH **D410 · D410s · D420** (also works with same-engine models such as D400 / D450 / CM series) — D410 driver install, D410s scan setup, D420 scan-to-PC

An open-source, cross-platform wizard that automatically finds **SINDOH D410 / D410s / D420 series** MFPs on your network and installs the **printer driver (TCP/IP port)** and **scan-to-PC (one-touch address-book button on the MFP panel + local receive folder)** with one click. These models are not supported by the official `sindoh Connect` one-click installer.

> **Copyright notice**: This repository does **not** contain any proprietary vendor binaries (DLLs, driver files, etc.). Everything is written from scratch in pure Python using standard SNMP / HTTP / WebDAV / CUPS / PrintManagement mechanisms.

---

## ✨ Features

1. **One-touch wizard GUI (`sindoh Connect` style)**
   - Left step sidebar: `Welcome` → `Choose install type` → `Find device` → `Choose components` → `Installing` → `Done`
   - Install types: **Printer + Scan** / **Printer driver only** / **Scan only**
   - All per-install options (printer name, scan button name, WebDAV/FTP/SMB mode, driver folder) are asked on the main screen.
2. **Automatic network discovery (SNMPv2c + WCD HTTP probe)**
   - Pure-Python UDP 161 (SNMP) scan plus the MFP web interface (`/wcd/common.xml`, `/wcd/top.xml`) to detect `D410`, `D410s`, `D420` and compatible models within seconds.
   - **Manual IP entry** is available for separate subnets / VLANs.
3. **Windows & macOS support**
   - **Windows**: `pnputil` + PowerShell `Add-PrinterDriver` / `Add-PrinterPort` / `Add-Printer` register a standard TCP/IP port (`IP_192.168.x.x`) and the driver.
   - **macOS**: password-free `IPP Everywhere` (`ipp://IP/ipp/print`) printing, with `.pkg` / CUPS `lpadmin` support.
4. **Built-in WebDAV / FTP scan receiver (no SMB sharing needed, same approach as `sindoh Connect`)**
   - A tiny built-in **WebDAV server (default port `50080`, `func=PSL_C_A_DAV_PTR`)** and **FTP server (port `2121`)** receive scans — no Windows/macOS folder sharing or account password required.
   - A background agent is registered to start automatically (Windows Run key / Task Scheduler / macOS LaunchAgents). The MFP's address book is registered through its web controller (`/wcd/scan.cgi`), and scans land in `Desktop/sindohScan`. If your PC's DHCP IP changes, the agent re-syncs the MFP address book automatically (checked every 15 seconds).

---

## 🚀 How to run

### Windows (easiest — `.exe` + `_internal` ZIP)
1. Download **`D410-D420-Connect-Windows.zip`** directly from the latest release (no GitHub login required):
   - 👉 **[Download latest Windows installer (`D410-D420-Connect-Windows.zip`)](https://github.com/LoveBlonde/sindoh-d410-d420-connect/releases/latest/download/D410-D420-Connect-Windows.zip)**
2. Extract the ZIP and double-click **`D410-D420-Connect.exe`** (keep `_internal` in the same folder; if Windows SmartScreen appears, click **More info → Run anyway**). No Python needed. You can delete the extracted folder after installation; the scan agent is copied to `%LOCALAPPDATA%\SindohD410Connect`.

Or run from source:
```powershell
git clone https://github.com/LoveBlonde/sindoh-d410-d420-connect.git
cd sindoh-d410-d420-connect
run_windows.bat
```

### macOS
```bash
git clone https://github.com/LoveBlonde/sindoh-d410-d420-connect.git
cd sindoh-d410-d420-connect
chmod +x run_macos.command
./run_macos.command
```

---

## 📦 Optional: use your own driver files

No driver files are required — the app uses a compatible KM/Sindoh PCL driver or the OS built-in PCL6/PS class driver. To use a model-specific driver downloaded from SINDOH:
- **Windows**: put the `PCL Driver` `.zip` (or the extracted `.inf` folder) into `drivers/windows/` (or next to the `.exe` in a `drivers/` folder), or pick it with `[Browse...]` on the options screen. A `TWAIN Driver` `Setup.exe` placed there is installed silently.
- **macOS**: put the `.pkg` or `.ppd.gz` into `drivers/macos/`.

---

## 🛠️ Building the executable

GitHub Actions (`.github/workflows/build.yml`) builds a single-file Windows `.exe` and a macOS `.app` on every push. To build locally:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "D410-D420-Connect" --collect-all customtkinter main.py
```

---

## ⚠️ Disclaimer

This is an unofficial community project and is not affiliated with SINDOH Co., Ltd. Use at your own risk. "SINDOH" and "Konica Minolta" are trademarks of their respective owners.
