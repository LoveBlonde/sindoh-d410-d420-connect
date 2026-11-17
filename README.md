# D410 / D420 Connect (Windows & macOS 원클릭 통합 설치 프로그램)

신도리코 최신 원클릭 통합 설치 프로그램(`sindoh Connect`)의 지원 목록에서 제외된 **SINDOH D410 / D410s / D420 시리즈** 복합기를 네트워크에서 자동으로 탐색하고, **프린터 드라이버(TCP/IP 포트)** 및 **스캔(복합기 패널 주소록 원터치 버튼 + 로컬 수신 폴더)**을 원클릭으로 설치해 주는 오픈소스 크로스 플랫폼 위저드 프로그램입니다.

> **저작권 안내**: 본 저장소는 제조사의 독점 바이너리(DLL, 드라이버 파일 등)를 포함하지 않으며, 100% 자체 작성된 순수 Python 표준 SNMP/HTTP/CUPS/PrintManagement 코드로 동작하므로 퍼블릭(Public) 오픈소스로 안전하게 사용할 수 있습니다.

---

## ✨ 주요 기능

1. **원터치 위저드 GUI (`sindoh Connect` 스타일)**
   - 좌측 설치 단계 사이드바 (`환영합니다` → `설치 유형 선택하기` → `장치 탐색하기` → `설치 구성 요소 선택하기` → `설치 진행하기` → `설치 완료`)
   - 설치 유형 선택: **프린터 및 스캔 모두 설치** / **프린터 드라이버만 설치** / **스캔만 설치**
   - 설치에 필요한 옵션(프린터 이름, 스캔 버튼 이름, SMB/FTP 전송 방식, PC 계정/암호, 드라이버 폴더 지정)을 메인 화면에서 한눈에 입력 가능
2. **네트워크 복합기 자동 탐색 (SNMPv2c + WCD HTTP 탐색)**
   - 외부 라이브러리 없이 순수 Python UDP 161번 포트(SNMP)와 복합기 웹 컨트롤러(`/wcd/common.xml`, `/wcd/top.xml`)를 스캔하여 `D410`, `D410s`, `D420` 및 호환 기종을 2초 내에 탐색합니다.
   - 서브넷/VLAN이 분리된 환경을 위해 **IP 주소 직접 입력** 기능도 함께 제공합니다.
3. **Windows & macOS 크로스 플랫폼 지원**
   - **Windows**: `pnputil` + PowerShell `Add-PrinterDriver` / `Add-PrinterPort` / `Add-Printer`로 표준 TCP/IP 포트(`IP_192.168.x.x`)와 드라이버를 자동 등록합니다.
   - **macOS**: `.pkg` 드라이버 무인 설치(`installer -pkg`) 및 CUPS `lpadmin` 명령어로 `socket://IP:9100` 또는 `ipp://IP/ipp/print` 프린터 큐를 즉시 생성합니다.
4. **스캔 자동 설정 (복합기 패널 주소록 원클릭 등록)**
   - 내 컴퓨터의 `Downloads/sindohScan` 폴더를 생성하고(Windows의 경우 SMB 공유 자동 구성), D410s/D420 웹 컨트롤러(`/wcd/scan.cgi`)에 접속해 **내 이름의 스캔 단축 버튼**을 자동으로 등록합니다.

---

## 🚀 실행 방법 (현장 프린터 테스트용)

### 1. Windows에서 실행하기
1. 저장소를 클론하거나 ZIP으로 다운로드합니다:
   ```powershell
   git clone https://github.com/LoveBlonde/sindoh-d410-d420-connect.git
   cd sindoh-d410-d420-connect
   ```
2. **`run_windows.bat`** 파일을 더블클릭합니다. (자동으로 관리자 권한을 요청하고 GUI 창이 실행됩니다.)
   - 또는 터미널에서 직접 실행:
     ```powershell
     pip install -r requirements.txt
     python main.py
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
pyinstaller --noconfirm --onedir --windowed --name "D410-D420-Connect" --collect-all customtkinter main.py
```
