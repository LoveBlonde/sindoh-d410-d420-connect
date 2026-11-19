# D410 / D420 Connect (Windows & macOS 원클릭 통합 설치 프로그램)

**🌐 Language: [한국어](README.md) | [English](README.en.md) | [中文](README.zh.md) | [日本語](README.ja.md)**

> **지원 기종**: 신도리코 **D410 · D410s · D420** (D400 · D450 · CM 시리즈 등 동일 엔진 기종 호환) — D410 드라이버 설치, D410s 스캔 설정, D420 스캔 to PC

신도리코 최신 원클릭 통합 설치 프로그램(`sindoh Connect`)의 지원 목록에서 제외된 **SINDOH D410 / D410s / D420 시리즈** 복합기를 네트워크에서 자동으로 탐색하고, **프린터 드라이버(TCP/IP 포트)** 및 **스캔(복합기 패널 주소록 원터치 버튼 + 로컬 수신 폴더)**을 원클릭으로 설치해 주는 오픈소스 크로스 플랫폼 위저드 프로그램입니다.

> **저작권 안내**: 본 저장소는 제조사의 독점 바이너리(DLL, 드라이버 파일 등)를 포함하지 않으며, 100% 자체 작성된 순수 Python 표준 SNMP/HTTP/WebDAV/CUPS/PrintManagement 코드로 동작하므로 퍼블릭(Public) 오픈소스로 안전하게 사용할 수 있습니다.

---

## ✨ 주요 기능

1. **원터치 위저드 GUI (`sindoh Connect` 스타일)**
   - 좌측 설치 단계 사이드바 (`환영합니다` → `설치 유형 선택하기` → `장치 탐색하기` → `설치 구성 요소 선택하기` → `설치 진행하기` → `설치 완료`)
   - 설치 유형 선택: **프린터 및 스캔 모두 설치** / **프린터 드라이버만 설치** / **스캔만 설치**
   - 설치에 필요한 옵션(프린터 이름, 스캔 버튼 이름, WebDAV/FTP/SMB 전송 방식, 드라이버 폴더 지정)을 메인 화면에서 한눈에 입력 가능
2. **네트워크 복합기 자동 탐색 (SNMPv2c + WCD HTTP 탐색)**
   - 외부 라이브러리 없이 순수 Python UDP 161번 포트(SNMP)와 복합기 웹 컨트롤러(`/wcd/common.xml`, `/wcd/top.xml`)를 스캔하여 `D410`, `D410s`, `D420` 및 호환 기종을 2초 내에 탐색합니다.
   - 서브넷/VLAN이 분리된 환경을 위해 **IP 주소 직접 입력** 기능도 함께 제공합니다.
3. **Windows & macOS 크로스 플랫폼 지원**
   - **Windows**: `pnputil` + PowerShell `Add-PrinterDriver` / `Add-PrinterPort` / `Add-Printer`로 표준 TCP/IP 포트(`IP_192.168.x.x`)와 드라이버를 자동 등록합니다.
   - **macOS**: 무암호/무설치 `IPP Everywhere` (`ipp://IP/ipp/print -m everywhere`) 직결 인쇄 및 `.pkg` / CUPS `lpadmin`을 지원합니다.
4. **내장 WebDAV / FTP 스캔 수신 서버 (공유폴더 설정 불필요, `sindoh Connect` 방식)**
   - Windows나 macOS에서 번거롭고 오류가 잦은 SMB 공유폴더/계정 암호 설정을 할 필요 없이, 신도 원클릭(`sindoh Connect`)과 동일하게 **초경량 내장 WebDAV 수신 서버(기본 포트 `50080`, `func=PSL_C_A_DAV_PTR`)** 및 **내장 FTP 수신 서버(포트 `2121`, `func=PSL_C_A_FTP_PTR`)**가 함께 탑재되어 있습니다.
   - 설치 시 백그라운드 스캔 수신 에이전트가 자동 실행 및 시작프로그램(Windows 레지스트리 Run / 작업 스케줄러 / macOS LaunchAgents)에 등록되며, D410s/D420 웹 컨트롤러(`/wcd/scan.cgi`)에 내 PC의 WebDAV 수신 정보가 원클릭으로 매핑되어 스캔 즉시 바탕화면(`Desktop/sindohScan`) 폴더로 파일이 들어옵니다. (PC 내부 IP가 바뀌어도 백그라운드 에이전트가 15초마다 확인하여 자동으로 복합기 주소록 IP를 갱신합니다.)

---

## 🚀 실행 방법 (현장 프린터 테스트용)

### 1. Windows에서 실행하기 (가장 쉬운 방법 — `.exe` 파일 1개)
1. 아래 최신 릴리즈 링크를 클릭해 **`D410-D420-Connect.exe`**를 다운로드합니다 (GitHub 로그인 불필요):
   - 👉 **[Windows용 최신 설치 파일 다운로드 (`D410-D420-Connect.exe`)](https://github.com/LoveBlonde/sindoh-d410-d420-connect/releases/latest/download/D410-D420-Connect.exe)**
2. 다운로드한 **`D410-D420-Connect.exe`**를 더블클릭합니다. (파란색 **Windows의 PC 보호** 창이 뜨면 **`추가 정보` → `실행`**을 누르세요.)
3. 파이썬 설치가 필요 없고, 설치가 끝나면 이 `.exe`는 지워도 됩니다. (스캔 수신 에이전트는 `%LOCALAPPDATA%\SindohD410Connect`에 복사되어 계속 동작합니다.)

소스코드로 직접 실행하려면:
```powershell
git clone https://github.com/LoveBlonde/sindoh-d410-d420-connect.git
cd sindoh-d410-d420-connect
run_windows.bat
```

### 2. macOS에서 실행하기
1. 터미널에서 클론 후 **`run_macos.command`**를 실행하거나 아래 명령어를 입력합니다:
   ```bash
   git clone https://github.com/LoveBlonde/sindoh-d410-d420-connect.git
   cd sindoh-d410-d420-connect
   chmod +x run_macos.command
   ./run_macos.command
   ```

---

## 📦 전용 드라이버 파일 추가 방법 (선택 사항)

본 프로그램은 별도의 드라이버 파일을 넣지 않아도 **KM/Sindoh 호환 통합 PCL 드라이버 자동 다운로드** 또는 **OS 내장 PCL6/PS 클래스 드라이버**로 즉시 인쇄가 가능하도록 설계되어 있습니다.

만약 신도리코 홈페이지에서 다운로드한 **D410 / D420 전용 드라이버**를 직접 적용하고 싶다면:
- **Windows**: 다운로드한 `PCL Driver` 압축 파일(`.zip`) 또는 압축을 푼 폴더(`.inf` 포함)를 `drivers/windows/` 폴더 안에 넣어두거나, 프로그램의 **[설치 구성 요소 선택하기]** 단계에서 `[폴더/파일 찾기...]`로 지정하면 자동으로 인식하여 설치합니다. (`TWAIN Driver`의 `Setup.exe`도 `drivers/windows/`에 넣어두면 무인 설치됩니다.)
- **macOS**: 다운로드한 `.pkg` 또는 `.ppd.gz` 파일을 `drivers/macos/` 폴더 안에 넣어두면 자동으로 인식하여 설치합니다.

---

## 🛠️ 단일 실행 파일(`.exe` / `.app`) 빌드 방법

GitHub Actions(`.github/workflows/build.yml`)가 포함되어 있어 코드를 푸시하면 Windows용 `.exe`와 macOS용 `.app`이 자동으로 빌드됩니다. 로컬에서 직접 빌드하려면:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "D410-D420-Connect" --collect-all customtkinter main.py
```
