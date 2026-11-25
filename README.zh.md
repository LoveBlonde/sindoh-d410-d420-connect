# D410 / D420 Connect — 打印机与扫描一键安装程序 (Windows & macOS)

**🌐 语言: [한국어](README.md) | [English](README.en.md) | [中文](README.zh.md) | [日本語](README.ja.md)**

> **支持机型**: SINDOH **D410 · D410s · D420**(同引擎的 D400 / D450 / CM 系列等机型也可使用)— D410 驱动安装、D410s 扫描设置、D420 扫描到电脑

这是一个开源的跨平台安装向导,可自动发现网络中的 **SINDOH(新道理科)D410 / D410s / D420 系列** 多功能一体机,并一键安装 **打印驱动(TCP/IP 端口)** 与 **扫描到电脑功能(在机器面板上添加一键地址簿按钮 + 本地接收文件夹)**。官方的 `sindoh Connect` 一键安装程序不支持这些机型。

> **版权声明**: 本仓库**不包含**任何厂商的专有二进制文件(DLL、驱动文件等)。所有代码均为从零编写的纯 Python 实现,仅使用标准的 SNMP / HTTP / WebDAV / CUPS / PrintManagement 机制。

---

## ✨ 主要功能

1. **一键式向导界面(仿 `sindoh Connect` 风格)**
   - 左侧步骤栏: `欢迎` → `选择安装类型` → `查找设备` → `选择安装组件` → `安装中` → `完成`
   - 安装类型: **打印机 + 扫描** / **仅打印驱动** / **仅扫描**
   - 每次安装需要设置的项目(打印机名称、扫描按钮名称、WebDAV/FTP/SMB 方式、驱动文件夹)都在主界面直接填写。
2. **自动网络设备发现(SNMPv2c + WCD HTTP 探测)**
   - 使用纯 Python 的 UDP 161(SNMP)扫描以及机器网页接口(`/wcd/common.xml`、`/wcd/top.xml`),几秒内找到 `D410`、`D410s`、`D420` 及兼容机型。
   - 针对不同网段 / VLAN 环境,也支持**手动输入 IP**。
3. **支持 Windows 与 macOS**
   - **Windows**: 通过 `pnputil` + PowerShell `Add-PrinterDriver` / `Add-PrinterPort` / `Add-Printer` 自动注册标准 TCP/IP 端口(`IP_192.168.x.x`)和驱动。
   - **macOS**: 无需密码的 `IPP Everywhere`(`ipp://IP/ipp/print`)直连打印,同时支持 `.pkg` / CUPS `lpadmin`。
4. **内置 WebDAV / FTP 扫描接收服务器(无需 SMB 共享,与 `sindoh Connect` 相同方式)**
   - 内置轻量 **WebDAV 服务器(默认端口 `50080`,`func=PSL_C_A_DAV_PTR`)** 与 **FTP 服务器(端口 `2121`)**,无需设置 Windows/macOS 共享文件夹,也不需要输入电脑登录密码。
   - 后台代理会自动注册为开机自启(Windows 注册表 Run / 任务计划程序 / macOS LaunchAgents)。通过机器的网页控制器(`/wcd/scan.cgi`)注册地址簿后,扫描文件会直接保存到 `Desktop/sindohScan`。电脑的 DHCP IP 变化时,代理每 15 秒检查一次并自动更新机器地址簿中的 IP。

---

## 🚀 使用方法

### Windows(最简单 — `.exe` + `_internal` 压缩包)
1. 直接从最新 Release 下载 **`D410-D420-Connect-Windows.zip`**(无需登录 GitHub):
   - 👉 **[下载最新 Windows 安装程序 (`D410-D420-Connect-Windows.zip`)](https://github.com/LoveBlonde/sindoh-d410-d420-connect/releases/latest/download/D410-D420-Connect-Windows.zip)**
2. 解压后双击文件夹内的 **`D410-D420-Connect.exe`**(请确保 `_internal` 文件夹在同一目录;如果弹出 Windows SmartScreen 蓝色提示框,点击 **更多信息 → 仍要运行**)。无需安装 Python,安装完成后可删除解压文件夹,扫描代理已被复制到 `%LOCALAPPDATA%\SindohD410Connect`。

或从源码运行:
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

## 📦 可选: 使用自备驱动文件

无需任何驱动文件即可使用 — 程序会使用兼容的 KM/Sindoh PCL 驱动或系统内置的 PCL6/PS 类驱动。若要使用从 SINDOH 官网下载的机型专用驱动:
- **Windows**: 将 `PCL Driver` 的 `.zip`(或解压后含 `.inf` 的文件夹)放入 `drivers/windows/`(或 `.exe` 旁边的 `drivers/` 文件夹),或在选项界面点击 `[浏览...]` 指定。放入的 `TWAIN Driver` `Setup.exe` 会被静默安装。
- **macOS**: 将 `.pkg` 或 `.ppd.gz` 放入 `drivers/macos/`。

---

## 🛠️ 构建可执行文件

GitHub Actions(`.github/workflows/build.yml`)会在每次推送时自动构建 Windows 单文件 `.exe` 与 macOS `.app`。本地构建:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "D410-D420-Connect" --collect-all customtkinter main.py
```

---

## ⚠️ 免责声明

本项目为非官方社区项目,与 SINDOH Co., Ltd. 无任何关联,使用风险自负。"SINDOH" 与 "Konica Minolta" 为其各自所有者的商标。
