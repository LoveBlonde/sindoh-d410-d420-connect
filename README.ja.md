# D410 / D420 Connect — プリンター&スキャナー ワンクリックインストーラー (Windows & macOS)

**🌐 Language: [한국어](README.md) | [English](README.en.md) | [中文](README.zh.md) | [日本語](README.ja.md)**

> **対応機種**: SINDOH **D410 · D410s · D420**(同じエンジンの D400 / D450 / CM シリーズなども利用可能)— D410 ドライバーインストール、D410s スキャン設定、D420 スキャン to PC

ネットワーク上の **SINDOH(シンドー)D410 / D410s / D420 シリーズ** 複合機を自動検出し、**プリンタードライバー(TCP/IP ポート)** と **スキャン to PC(複合機パネルのワンタッチ宛先ボタン + PC 側の受信フォルダー)** をワンクリックでセットアップする、オープンソースのクロスプラットフォーム ウィザードです。公式の `sindoh Connect` ワンクリックインストーラーが対応していない機種向けに作られています。

> **著作権について**: 本リポジトリにはメーカー独自のバイナリ(DLL、ドライバーファイルなど)を**一切含みません**。標準的な SNMP / HTTP / WebDAV / CUPS / PrintManagement の仕組みのみを用い、純粋な Python でゼロから実装しています。

---

## ✨ 主な機能

1. **ワンタッチ ウィザード GUI(`sindoh Connect` スタイル)**
   - 左側のステップ表示: `ようこそ` → `インストール種類の選択` → `デバイス検索` → `構成要素の選択` → `インストール中` → `完了`
   - インストール種類: **プリンター+スキャン** / **プリンタードライバーのみ** / **スキャンのみ**
   - インストールごとに必要な設定(プリンター名、スキャンボタン名、WebDAV/FTP/SMB 方式、ドライバーフォルダー)はメイン画面で入力できます。
2. **ネットワーク上の複合機を自動検出(SNMPv2c + WCD HTTP プローブ)**
   - 純粋な Python による UDP 161(SNMP)スキャンと複合機の Web インターフェース(`/wcd/common.xml`、`/wcd/top.xml`)で、`D410`、`D410s`、`D420` および互換機種を数秒で検出します。
   - 別サブネット / VLAN 環境向けに **IP アドレスの手動入力** にも対応しています。
3. **Windows と macOS に対応**
   - **Windows**: `pnputil` + PowerShell の `Add-PrinterDriver` / `Add-PrinterPort` / `Add-Printer` で標準 TCP/IP ポート(`IP_192.168.x.x`)とドライバーを自動登録します。
   - **macOS**: パスワード不要の `IPP Everywhere`(`ipp://IP/ipp/print`)で直接印刷でき、`.pkg` / CUPS `lpadmin` にも対応しています。
4. **内蔵 WebDAV / FTP スキャン受信サーバー(SMB 共有設定不要、`sindoh Connect` と同じ方式)**
   - 軽量な **WebDAV サーバー(デフォルトポート `50080`、`func=PSL_C_A_DAV_PTR`)** と **FTP サーバー(ポート `2121`)** を内蔵。Windows / macOS のフォルダー共有設定や PC のログインパスワード入力は不要です。
   - バックグラウンドエージェントが自動起動に登録されます(Windows のレジストリ Run / タスクスケジューラ / macOS LaunchAgents)。複合機の Web コントローラー(`/wcd/scan.cgi`)に宛先を登録し、スキャンしたファイルは `Desktop/sindohScan` に保存されます。PC の DHCP IP が変わっても、エージェントが 15 秒ごとに確認して複合機のアドレス帳の IP を自動更新します。

---

## 🚀 使い方

### Windows(最も簡単 — `.exe` 1 ファイル)
1. 最新リリースから **`D410-D420-Connect.exe`** を直接ダウンロードします(GitHub ログイン不要):
   - 👉 **[最新 Windows インストーラーをダウンロード (`D410-D420-Connect.exe`)](https://github.com/LoveBlonde/sindoh-d410-d420-connect/releases/latest/download/D410-D420-Connect.exe)**
2. **`D410-D420-Connect.exe`** をダブルクリックします(Windows SmartScreen の青い画面が出た場合は **詳細情報 → 実行** をクリック)。Python は不要で、インストール後は `.exe` を削除しても構いません(スキャンエージェントは `%LOCALAPPDATA%\SindohD410Connect` にコピーされます)。

ソースから実行する場合:
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

## 📦 任意: 独自のドライバーファイルを使う

ドライバーファイルがなくても、互換の KM/Sindoh PCL ドライバーまたは OS 標準の PCL6/PS クラスドライバーで印刷できます。SINDOH 公式サイトからダウンロードした機種専用ドライバーを使う場合:
- **Windows**: `PCL Driver` の `.zip`(または解凍した `.inf` を含むフォルダー)を `drivers/windows/`(または `.exe` と同じ場所の `drivers/` フォルダー)に置くか、オプション画面の `[参照...]` で指定します。同じ場所に置いた `TWAIN Driver` の `Setup.exe` はサイレントインストールされます。
- **macOS**: `.pkg` または `.ppd.gz` を `drivers/macos/` に置きます。

---

## 🛠️ 実行ファイルのビルド

GitHub Actions(`.github/workflows/build.yml`)が、プッシュのたびに Windows 用の単一ファイル `.exe` と macOS 用の `.app` を自動ビルドします。ローカルでビルドする場合:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "D410-D420-Connect" --collect-all customtkinter main.py
```

---

## ⚠️ 免責事項

本プロジェクトは非公式のコミュニティプロジェクトであり、SINDOH Co., Ltd. とは無関係です。ご利用は自己責任でお願いします。「SINDOH」および「Konica Minolta」はそれぞれの所有者の商標です。
