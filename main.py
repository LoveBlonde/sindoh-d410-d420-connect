#!/usr/bin/env python3
"""
D410/D420 Connect — One-Click Network Printer & Scanner Installer for Windows & macOS
Clean Wizard GUI modeled after Sindoh Connect.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Optional

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

if "--daemon" in sys.argv:
    import argparse
    import time
    from core.ftp_scan_server import BuiltinScanFtpServer, DEFAULT_FTP_PORT, get_default_scan_dir

    _parser = argparse.ArgumentParser(add_help=False)
    _parser.add_argument("--daemon", action="store_true")
    _parser.add_argument("--port", type=int, default=DEFAULT_FTP_PORT)
    _parser.add_argument("--dir", type=str, default=str(get_default_scan_dir()))
    _args, _ = _parser.parse_known_args()
    _srv = BuiltinScanFtpServer(root_dir=Path(_args.dir), port=_args.port)
    _ok, _ = _srv.start()
    if _ok:
        while True:
            time.sleep(3600)
    raise SystemExit(0)


def _ensure_runtime_environment() -> None:
    """
    If launched directly via `python3 main.py` on a Python that lacks `tkinter` (e.g. Homebrew Python
    without `python-tk`), has broken macOS system Tcl/Tk 8.5 (which renders a black window on macOS),
    or lacks `customtkinter` (e.g. PEP 668 externally-managed environment),
    automatically switch to or create the project `.venv` with a modern Tcl/Tk 8.6+ Python interpreter.
    """
    if getattr(sys, "frozen", False) or os.environ.get("SINDOH_BOOTSTRAPPED") == "1":
        return

    is_mac = platform.system().lower() == "darwin"
    try:
        import tkinter as _tk
        import customtkinter  # noqa: F401
        if not is_mac or float(_tk.TkVersion) >= 8.6:
            return
    except Exception:
        pass

    project_dir = Path(__file__).resolve().parent
    is_win = platform.system().lower() == "windows"
    venv_py = project_dir / ".venv" / ("Scripts/python.exe" if is_win else "bin/python3")

    def _can_run_gui(py_bin: str) -> bool:
        try:
            chk = "import tkinter, customtkinter; raise SystemExit(0 if float(tkinter.TkVersion) >= 8.6 else 1)" if is_mac else "import tkinter, customtkinter"
            r = subprocess.run([py_bin, "-c", chk], capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    # 1. If .venv is already ready with Tcl/Tk 8.6+, re-exec into it immediately
    if venv_py.exists() and _can_run_gui(str(venv_py)):
        os.environ["SINDOH_BOOTSTRAPPED"] = "1"
        os.execv(str(venv_py), [str(venv_py), str(Path(__file__).resolve()), *sys.argv[1:]])

    # 2. Delegate to run_macos.command on macOS/Linux if available
    runner_sh = project_dir / "run_macos.command"
    if not is_win and runner_sh.exists():
        os.environ["SINDOH_BOOTSTRAPPED"] = "1"
        os.execv("/bin/bash", ["/bin/bash", str(runner_sh), *sys.argv[1:]])


_ensure_runtime_environment()

import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from core.snmp_discovery import (
    DiscoveredDevice,
    get_local_ipv4_addresses,
    scan_network,
    verify_manual_ip,
)
from core.printer_installer import (
    find_local_driver_source,
    get_project_drivers_dir,
    install_printer_cross_platform,
)
from core.scanner_installer import (
    configure_scanner_cross_platform,
    get_default_scan_folder,
)


# ─────────────────────────────────────────────────────────────────────────────
# Theme & Color Palette (Exact match to clean white/gray/blue Wizard UI)
# ─────────────────────────────────────────────────────────────────────────────
COLOR_SIDEBAR_BG = "#F7F8FA"
COLOR_MAIN_BG = "#FFFFFF"
COLOR_PRIMARY = "#1E6BFF"
COLOR_PRIMARY_HOVER = "#1557D6"
COLOR_TEXT_DARK = "#191F28"
COLOR_TEXT_SUB = "#6B7684"
COLOR_TEXT_MUTED = "#ABB2B9"
COLOR_CARD_SELECTED_BG = "#F2F4F7"
COLOR_CARD_IDLE_BG = "#FFFFFF"
COLOR_CARD_BORDER = "#E5E8EB"
COLOR_CARD_SELECTED_BORDER = "#D1D6DB"
COLOR_SUCCESS = "#12B76A"
COLOR_WARN = "#F79009"

STEPS = [
    "환영합니다",
    "설치 유형 선택하기",
    "장치 탐색하기",
    "설치 구성 요소 선택하기",
    "설치 진행하기",
    "설치 완료",
]


def get_system_font() -> str:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        return "Malgun Gothic"
    elif sys_name == "darwin":
        return "Apple SD Gothic Neo"
    return "Sans"


class D410ConnectApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("light")
        self.font_family = get_system_font()

        self.title("D410/D420 Connect 설치")
        self.geometry("920x620")
        self.minsize(880, 580)
        self.configure(fg_color=COLOR_MAIN_BG)

        # Wizard State
        self.current_step: int = 1  # Start directly on Step 1 ("설치 유형 선택하기") or Step 0 ("환영합니다")
        self.install_mode: str = "both"  # "both" | "printer" | "scan"
        self.discovered_devices: List[DiscoveredDevice] = []
        self.selected_device: Optional[DiscoveredDevice] = None
        self.is_scanning: bool = False
        self.filter_d410_only: tk.BooleanVar = tk.BooleanVar(value=False)

        # Configuration State (Step 3)
        default_user = os.environ.get("USERNAME") or os.environ.get("USER") or "홍길동"
        self.printer_name_var = tk.StringVar(value="SINDOH D410/D420 Series")
        self.set_default_printer_var = tk.BooleanVar(value=True)
        self.scan_name_var = tk.StringVar(value=default_user)
        self.scan_protocol_var = tk.StringVar(value="내장 FTP 수신 (권장)")
        self.pc_username_var = tk.StringVar(value=default_user)
        self.pc_password_var = tk.StringVar(value="")
        self.mfp_admin_pw_var = tk.StringVar(value="")
        self.custom_driver_path_var = tk.StringVar(value="")
        self.dry_run_var = tk.BooleanVar(value=False)

        # Execution Logs & Results (Step 4 & 5)
        self.install_logs: List[str] = []
        self.printer_result_text: str = ""
        self.scan_result_text: str = ""
        self.install_running: bool = False

        self._build_layout()
        self._show_step(1)  # Start on "설치 유형 선택하기" just like the screenshot (and allow going back to 환영합니다)

    # ─────────────────────────────────────────────────────────────────────────
    # Base Layout (Left Sidebar + Right Main Content + Bottom Footer Bar)
    # ─────────────────────────────────────────────────────────────────────────
    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=0, minsize=220)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Left Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=COLOR_SIDEBAR_BG)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Brand Header
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=26, pady=(36, 32))

        brand_title = ctk.CTkLabel(
            brand_frame,
            text="sindoh Connect",
            font=ctk.CTkFont(family=self.font_family, size=20, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        brand_title.pack(fill="x")

        brand_badge = ctk.CTkLabel(
            brand_frame,
            text="D410s · D420 Edition",
            font=ctk.CTkFont(family=self.font_family, size=11, weight="bold"),
            text_color=COLOR_PRIMARY,
            anchor="w",
        )
        brand_badge.pack(fill="x", pady=(2, 0))

        # Step List Container
        self.step_labels_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.step_labels_frame.pack(fill="x", padx=20)

        self.step_row_widgets: List[tuple[ctk.CTkFrame, ctk.CTkLabel]] = []
        for idx, step_text in enumerate(STEPS):
            row = ctk.CTkFrame(self.step_labels_frame, fg_color="transparent", height=34)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            bar = ctk.CTkFrame(row, width=3, height=16, corner_radius=2, fg_color="transparent")
            bar.pack(side="left", padx=(4, 8))

            lbl = ctk.CTkLabel(
                row,
                text=step_text,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_MUTED,
                anchor="w",
            )
            lbl.pack(side="left", fill="x", expand=True)
            self.step_row_widgets.append((bar, lbl))

        # Version / OS Footer on Sidebar
        os_tag = "Windows" if platform.system().lower() == "windows" else "macOS"
        footer_lbl = ctk.CTkLabel(
            self.sidebar,
            text=f"v1.0.4 ({os_tag})\nD410s / D420 Open Installer",
            font=ctk.CTkFont(family=self.font_family, size=11),
            text_color="#8B95A1",
            justify="left",
            anchor="w",
        )
        footer_lbl.pack(side="bottom", fill="x", padx=26, pady=24)

        # 2. Right Panel (Content Area + Bottom Action Bar)
        self.right_panel = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_MAIN_BG)
        self.right_panel.grid(row=0, column=1, sticky="nsew")
        self.right_panel.grid_rowconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(1, weight=0)
        self.right_panel.grid_columnconfigure(0, weight=1)

        self.content_container = ctk.CTkFrame(self.right_panel, corner_radius=0, fg_color=COLOR_MAIN_BG)
        self.content_container.grid(row=0, column=0, sticky="nsew", padx=56, pady=(48, 16))

        # Bottom Navigation Bar
        self.nav_bar = ctk.CTkFrame(self.right_panel, height=76, corner_radius=0, fg_color=COLOR_MAIN_BG)
        self.nav_bar.grid(row=1, column=0, sticky="ew", padx=56, pady=(0, 20))

        self.reset_btn = ctk.CTkButton(
            self.nav_bar,
            text="↻  처음으로 돌아가기",
            font=ctk.CTkFont(family=self.font_family, size=13),
            fg_color="transparent",
            hover_color="#F2F4F7",
            text_color=COLOR_TEXT_SUB,
            width=140,
            height=38,
            anchor="w",
            command=self._on_reset_clicked,
        )
        self.reset_btn.pack(side="left")

        self.next_btn = ctk.CTkButton(
            self.nav_bar,
            text="다음  →",
            font=ctk.CTkFont(family=self.font_family, size=14, weight="bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            text_color="#FFFFFF",
            corner_radius=6,
            width=105,
            height=40,
            command=self._on_next_clicked,
        )
        self.next_btn.pack(side="right")

        self.prev_btn = ctk.CTkButton(
            self.nav_bar,
            text="←  이전",
            font=ctk.CTkFont(family=self.font_family, size=14),
            fg_color="transparent",
            hover_color="#F2F4F7",
            text_color=COLOR_TEXT_SUB,
            corner_radius=6,
            width=90,
            height=40,
            command=self._on_prev_clicked,
        )
        self.prev_btn.pack(side="right", padx=(0, 12))

    def _update_sidebar_indicators(self) -> None:
        for idx, (bar, lbl) in enumerate(self.step_row_widgets):
            if idx < self.current_step:
                bar.configure(fg_color="transparent")
                lbl.configure(
                    text_color="#B0B8C1",
                    font=ctk.CTkFont(family=self.font_family, size=13, weight="normal"),
                )
            elif idx == self.current_step:
                bar.configure(fg_color=COLOR_PRIMARY)
                lbl.configure(
                    text_color=COLOR_PRIMARY,
                    font=ctk.CTkFont(family=self.font_family, size=13, weight="bold"),
                )
            else:
                bar.configure(fg_color="transparent")
                lbl.configure(
                    text_color="#4E5968",
                    font=ctk.CTkFont(family=self.font_family, size=13, weight="normal"),
                )

    def _clear_content(self) -> None:
        for child in self.content_container.winfo_children():
            child.destroy()

    def _show_step(self, step_idx: int) -> None:
        self.current_step = step_idx
        self._update_sidebar_indicators()
        self._clear_content()

        # Configure footer buttons
        if step_idx == 0:
            self.reset_btn.pack_forget()
            self.prev_btn.pack_forget()
            self.next_btn.configure(text="시작하기  →", state="normal")
        elif step_idx == 1:
            self.reset_btn.pack(side="left")
            self.prev_btn.pack(side="right", padx=(0, 12))
            self.next_btn.configure(text="다음  →", state="normal")
        elif step_idx == 2:
            self.reset_btn.pack(side="left")
            self.prev_btn.pack(side="right", padx=(0, 12))
            self.next_btn.configure(
                text="다음  →",
                state="normal" if self.selected_device is not None else "disabled",
            )
        elif step_idx == 3:
            self.reset_btn.pack(side="left")
            self.prev_btn.pack(side="right", padx=(0, 12))
            self.next_btn.configure(text="설치 시작  →", state="normal")
        elif step_idx == 4:
            self.reset_btn.pack_forget()
            self.prev_btn.pack_forget()
            self.next_btn.configure(text="설치 중...", state="disabled")
        elif step_idx == 5:
            self.reset_btn.pack(side="left")
            self.prev_btn.pack_forget()
            self.next_btn.configure(text="종료", state="normal")

        # Render specific step view
        builders = {
            0: self._build_step0_welcome,
            1: self._build_step1_install_type,
            2: self._build_step2_device_discovery,
            3: self._build_step3_configure_options,
            4: self._build_step4_installing,
            5: self._build_step5_complete,
        }
        builders[step_idx]()

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 0: 환영합니다
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step0_welcome(self) -> None:
        title = ctk.CTkLabel(
            self.content_container,
            text="D410s / D420 통합 설치를 환영합니다",
            font=ctk.CTkFont(family=self.font_family, size=26, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(fill="x", pady=(10, 10))

        sub = ctk.CTkLabel(
            self.content_container,
            text="기존 신도리코 원클릭 설치기에서 제외된 D410, D410s, D420 시리즈 복합기를\n네트워크에서 자동으로 찾아 프린터 드라이버와 스캔 주소록을 한 번에 설치합니다.",
            font=ctk.CTkFont(family=self.font_family, size=14),
            text_color=COLOR_TEXT_SUB,
            justify="left",
            anchor="w",
        )
        sub.pack(fill="x", pady=(0, 28))

        info_card = ctk.CTkFrame(
            self.content_container,
            fg_color=COLOR_CARD_SELECTED_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        info_card.pack(fill="x", pady=8)

        local_ips = ", ".join(get_local_ipv4_addresses()) or "감지되지 않음"
        os_str = f"{platform.system()} {platform.release()} ({platform.machine()})"
        drv_src = find_local_driver_source(self.custom_driver_path_var.get())
        drv_status = f"준비됨 ({drv_src.name})" if drv_src else "자동 다운로드 / OS 내장 호환 드라이버 사용"

        details = [
            ("현재 운영체제", os_str),
            ("내 컴퓨터 네트워크 IP", local_ips),
            ("지원 대상 기종", "SINDOH D410 / D410s / D420 / D400 / CM 시리즈 전 기종"),
            ("드라이버 패키지 상태", drv_status),
        ]
        for k, v in details:
            row = ctk.CTkFrame(info_card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=8)
            ctk.CTkLabel(
                row,
                text=f"• {k}",
                width=170,
                font=ctk.CTkFont(family=self.font_family, size=13, weight="bold"),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=v,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_SUB,
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1: 설치 유형 선택하기 (Matches user's uploaded screenshot)
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step1_install_type(self) -> None:
        title = ctk.CTkLabel(
            self.content_container,
            text="무엇을 설치할까요?",
            font=ctk.CTkFont(family=self.font_family, size=26, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(fill="x", pady=(6, 8))

        sub = ctk.CTkLabel(
            self.content_container,
            text="필요한 설치 유형을 선택하세요. 선택에 따라 이후 단계가 달라집니다.",
            font=ctk.CTkFont(family=self.font_family, size=14),
            text_color=COLOR_TEXT_SUB,
            anchor="w",
        )
        sub.pack(fill="x", pady=(0, 28))

        options = [
            (
                "both",
                "🖨️",
                "프린터 및 스캔 모두 설치",
                "인쇄와 스캔을 모두 사용합니다. 드라이버 설치와 주소록 등록을 함께 진행합니다.",
            ),
            (
                "printer",
                "📄",
                "프린터 드라이버만 설치",
                "인쇄 기능만 사용합니다. 문서 출력을 위한 드라이버를 설치합니다.",
            ),
            (
                "scan",
                "📠",
                "스캔만 설치",
                "스캔 기능만 사용합니다. 출력 장비에 PC 주소록을 등록합니다.",
            ),
        ]

        self.mode_cards: dict[str, tuple[ctk.CTkFrame, ctk.CTkLabel]] = {}

        for mode_key, icon_txt, title_txt, desc_txt in options:
            is_sel = self.install_mode == mode_key
            card = ctk.CTkFrame(
                self.content_container,
                fg_color=COLOR_CARD_SELECTED_BG if is_sel else COLOR_CARD_IDLE_BG,
                corner_radius=6,
                border_width=1 if is_sel else 0,
                border_color=COLOR_CARD_SELECTED_BORDER if is_sel else COLOR_MAIN_BG,
                height=86,
            )
            card.pack(fill="x", pady=6)
            card.pack_propagate(False)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=18, pady=14)

            radio_lbl = ctk.CTkLabel(
                inner,
                text="◉" if is_sel else "○",
                font=ctk.CTkFont(family=self.font_family, size=20),
                text_color=COLOR_TEXT_DARK if is_sel else "#C4CDD5",
                width=28,
            )
            radio_lbl.pack(side="left", padx=(2, 10))

            icon_lbl = ctk.CTkLabel(
                inner,
                text=icon_txt,
                font=ctk.CTkFont(family=self.font_family, size=26),
                width=40,
            )
            icon_lbl.pack(side="left", padx=(0, 14))

            text_box = ctk.CTkFrame(inner, fg_color="transparent")
            text_box.pack(side="left", fill="both", expand=True)

            t_lbl = ctk.CTkLabel(
                text_box,
                text=title_txt,
                font=ctk.CTkFont(family=self.font_family, size=15, weight="bold"),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            )
            t_lbl.pack(fill="x", pady=(2, 2))

            d_lbl = ctk.CTkLabel(
                text_box,
                text=desc_txt,
                font=ctk.CTkFont(family=self.font_family, size=12),
                text_color=COLOR_TEXT_SUB,
                anchor="w",
            )
            d_lbl.pack(fill="x")

            self.mode_cards[mode_key] = (card, radio_lbl)

            # Bind click across all widgets inside the card
            for w in (card, inner, radio_lbl, icon_lbl, text_box, t_lbl, d_lbl):
                w.bind("<Button-1>", lambda e, m=mode_key: self._select_install_mode(m))

    def _select_install_mode(self, mode_key: str) -> None:
        self.install_mode = mode_key
        for k, (card, radio_lbl) in self.mode_cards.items():
            is_sel = k == mode_key
            card.configure(
                fg_color=COLOR_CARD_SELECTED_BG if is_sel else COLOR_CARD_IDLE_BG,
                border_width=1 if is_sel else 0,
                border_color=COLOR_CARD_SELECTED_BORDER if is_sel else COLOR_MAIN_BG,
            )
            radio_lbl.configure(
                text="◉" if is_sel else "○",
                text_color=COLOR_TEXT_DARK if is_sel else "#C4CDD5",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2: 장치 탐색하기 (SNMP Auto-Discovery + Manual IP Addition)
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step2_device_discovery(self) -> None:
        header_row = ctk.CTkFrame(self.content_container, fg_color="transparent")
        header_row.pack(fill="x", pady=(6, 4))

        title = ctk.CTkLabel(
            header_row,
            text="설치할 복합기를 선택하세요",
            font=ctk.CTkFont(family=self.font_family, size=24, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(side="left")

        self.rescan_btn = ctk.CTkButton(
            header_row,
            text="↻  다시 검색",
            font=ctk.CTkFont(family=self.font_family, size=13, weight="bold"),
            fg_color="#EEF3FF",
            hover_color="#DCE7FF",
            text_color=COLOR_PRIMARY,
            width=105,
            height=34,
            corner_radius=6,
            command=self._start_network_scan,
        )
        self.rescan_btn.pack(side="right")

        self.scan_status_lbl = ctk.CTkLabel(
            self.content_container,
            text="동일 네트워크(SNMP / WCD)에 연결된 신도리코 복합기를 탐색합니다.",
            font=ctk.CTkFont(family=self.font_family, size=13),
            text_color=COLOR_TEXT_SUB,
            anchor="w",
        )
        self.scan_status_lbl.pack(fill="x", pady=(0, 12))

        # Device List Scrollable Area
        self.device_list_frame = ctk.CTkScrollableFrame(
            self.content_container,
            fg_color="#F9FAFB",
            corner_radius=8,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=240,
        )
        self.device_list_frame.pack(fill="both", expand=True, pady=(0, 14))

        # Manual IP Input Bar (Essential when across VLANs or testing offline)
        manual_bar = ctk.CTkFrame(
            self.content_container,
            fg_color=COLOR_CARD_SELECTED_BG,
            corner_radius=8,
        )
        manual_bar.pack(fill="x", pady=(4, 0))

        ctk.CTkLabel(
            manual_bar,
            text="IP로 직접 추가:",
            font=ctk.CTkFont(family=self.font_family, size=13, weight="bold"),
            text_color=COLOR_TEXT_DARK,
        ).pack(side="left", padx=(14, 8), pady=10)

        self.manual_ip_entry = ctk.CTkEntry(
            manual_bar,
            placeholder_text="예: 192.168.0.200 (D410s / D420 IP 주소)",
            font=ctk.CTkFont(family=self.font_family, size=13),
            width=260,
            height=32,
        )
        self.manual_ip_entry.pack(side="left", padx=(0, 8), pady=10)

        add_ip_btn = ctk.CTkButton(
            manual_bar,
            text="장치 연결 확인",
            font=ctk.CTkFont(family=self.font_family, size=12, weight="bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            width=110,
            height=32,
            command=self._on_add_manual_ip,
        )
        add_ip_btn.pack(side="left", padx=(0, 8), pady=10)

        sim_btn = ctk.CTkButton(
            manual_bar,
            text="+ 테스트용 D410s 추가",
            font=ctk.CTkFont(family=self.font_family, size=12),
            fg_color="#E5E8EB",
            hover_color="#D1D6DB",
            text_color=COLOR_TEXT_DARK,
            width=145,
            height=32,
            command=self._on_add_demo_device,
        )
        sim_btn.pack(side="right", padx=12, pady=10)

        if not self.discovered_devices and not self.is_scanning:
            self._start_network_scan()
        else:
            self._render_device_list()

    def _start_network_scan(self) -> None:
        if self.is_scanning:
            return
        self.is_scanning = True
        if hasattr(self, "rescan_btn") and self.rescan_btn.winfo_exists():
            self.rescan_btn.configure(state="disabled", text="탐색 중...")
        if hasattr(self, "scan_status_lbl") and self.scan_status_lbl.winfo_exists():
            self.scan_status_lbl.configure(text="네트워크 대역에서 D410s / D420 장치를 검색하고 있습니다... (0%)")

        def progress_cb(done: int, total: int) -> None:
            pct = int((done / max(total, 1)) * 100)
            self.after(
                0,
                lambda: self.scan_status_lbl.configure(
                    text=f"네트워크 대역에서 장치를 검색하고 있습니다... ({pct}%)"
                )
                if hasattr(self, "scan_status_lbl") and self.scan_status_lbl.winfo_exists()
                else None,
            )

        def worker() -> None:
            devs = scan_network(progress_callback=progress_cb, only_d410_d420=False)
            self.after(0, lambda: self._on_scan_finished(devs))

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_finished(self, devs: List[DiscoveredDevice]) -> None:
        self.is_scanning = False
        # Merge keeping any manually added devices
        existing_ips = {d.ip for d in devs}
        for old in self.discovered_devices:
            if old.ip not in existing_ips:
                devs.append(old)
        self.discovered_devices = devs

        if self.selected_device is None and self.discovered_devices:
            self.selected_device = self.discovered_devices[0]
            self._sync_default_printer_name(self.selected_device)

        if hasattr(self, "rescan_btn") and self.rescan_btn.winfo_exists():
            self.rescan_btn.configure(state="normal", text="↻  다시 검색")
        if hasattr(self, "scan_status_lbl") and self.scan_status_lbl.winfo_exists():
            if devs:
                self.scan_status_lbl.configure(
                    text=f"총 {len(devs)}대의 복합기/프린터가 발견되었습니다. 설치할 장치를 선택해 주세요."
                )
            else:
                self.scan_status_lbl.configure(
                    text="자동 검색된 장치가 없습니다. 아래에 복합기 IP 주소를 직접 입력하거나 다시 검색해 보세요."
                )
        self._render_device_list()

    def _on_add_manual_ip(self) -> None:
        ip = self.manual_ip_entry.get().strip()
        if not ip:
            return
        self.scan_status_lbl.configure(text=f"{ip} 장치 연결을 확인하고 있습니다...")

        def worker() -> None:
            dev = verify_manual_ip(ip)
            if dev is None:
                # Even if offline right now, allow adding so user can pre-stage driver/port
                dev = DiscoveredDevice(
                    ip=ip,
                    model="SINDOH D410s / D420 Series",
                    sys_descr="수동 IP 지정 (오프라인/대기 중)",
                    is_target_series=True,
                    supports_scan=True,
                )
            self.after(0, lambda: self._add_and_select_device(dev))

        threading.Thread(target=worker, daemon=True).start()

    def _on_add_demo_device(self) -> None:
        demo = DiscoveredDevice(
            ip="192.168.0.210",
            model="SINDOH D410s / D420 Series",
            sys_descr="KONICA MINOLTA / SINDOH D410s MFP (시뮬레이션 모드)",
            serial="D410S-DEMO01",
            hostname="SINDOH-D410S",
            is_target_series=True,
            supports_scan=True,
        )
        self.dry_run_var.set(True)
        self._add_and_select_device(demo)

    def _add_and_select_device(self, dev: DiscoveredDevice) -> None:
        self.discovered_devices = [d for d in self.discovered_devices if d.ip != dev.ip]
        self.discovered_devices.insert(0, dev)
        self.selected_device = dev
        self._sync_default_printer_name(dev)
        if hasattr(self, "scan_status_lbl") and self.scan_status_lbl.winfo_exists():
            self.scan_status_lbl.configure(text=f"장치가 선택되었습니다: {dev.model} ({dev.ip})")
        self._render_device_list()

    def _sync_default_printer_name(self, dev: DiscoveredDevice) -> None:
        if "D410" in dev.model.upper() or "D420" in dev.model.upper():
            self.printer_name_var.set(dev.model)
        else:
            self.printer_name_var.set(f"SINDOH D410/D420 ({dev.ip})")

    def _render_device_list(self) -> None:
        if not hasattr(self, "device_list_frame") or not self.device_list_frame.winfo_exists():
            return
        for child in self.device_list_frame.winfo_children():
            child.destroy()

        if not self.discovered_devices:
            empty_lbl = ctk.CTkLabel(
                self.device_list_frame,
                text="\n검색된 복합기가 없습니다.\n\n프린터 전원과 네트워크 연결을 확인하거나,\n아래 입력창에 복합기 IP 주소(예: 192.168.0.x)를 직접 입력해 주세요.",
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_SUB,
                justify="center",
            )
            empty_lbl.pack(fill="both", expand=True, pady=35)
            self.next_btn.configure(state="disabled")
            return

        for dev in self.discovered_devices:
            is_sel = self.selected_device is not None and self.selected_device.ip == dev.ip
            card = ctk.CTkFrame(
                self.device_list_frame,
                fg_color="#EEF3FF" if is_sel else COLOR_MAIN_BG,
                corner_radius=6,
                border_width=2 if is_sel else 1,
                border_color=COLOR_PRIMARY if is_sel else COLOR_CARD_BORDER,
                height=68,
            )
            card.pack(fill="x", padx=6, pady=4)
            card.pack_propagate(False)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=14, pady=8)

            radio = ctk.CTkLabel(
                inner,
                text="◉" if is_sel else "○",
                font=ctk.CTkFont(family=self.font_family, size=18),
                text_color=COLOR_PRIMARY if is_sel else "#C4CDD5",
                width=26,
            )
            radio.pack(side="left", padx=(0, 8))

            info_col = ctk.CTkFrame(inner, fg_color="transparent")
            info_col.pack(side="left", fill="both", expand=True)

            t_lbl = ctk.CTkLabel(
                info_col,
                text=dev.display_title,
                font=ctk.CTkFont(family=self.font_family, size=14, weight="bold"),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            )
            t_lbl.pack(fill="x")

            s_lbl = ctk.CTkLabel(
                info_col,
                text=dev.display_subtitle,
                font=ctk.CTkFont(family=self.font_family, size=12),
                text_color=COLOR_TEXT_SUB,
                anchor="w",
            )
            s_lbl.pack(fill="x")

            if dev.is_target_series:
                badge = ctk.CTkLabel(
                    inner,
                    text="D410/D420 호환",
                    font=ctk.CTkFont(family=self.font_family, size=11, weight="bold"),
                    fg_color="#E0EAFF",
                    text_color=COLOR_PRIMARY,
                    corner_radius=4,
                    padx=8,
                    pady=2,
                )
                badge.pack(side="right", padx=6)

            for w in (card, inner, radio, info_col, t_lbl, s_lbl):
                w.bind("<Button-1>", lambda e, d=dev: self._on_device_card_clicked(d))

        self.next_btn.configure(state="normal" if self.selected_device else "disabled")

    def _on_device_card_clicked(self, dev: DiscoveredDevice) -> None:
        self.selected_device = dev
        self._sync_default_printer_name(dev)
        self._render_device_list()

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3: 설치 구성 요소 선택하기 (Main Screen prompts for Printer/Scan settings)
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step3_configure_options(self) -> None:
        title = ctk.CTkLabel(
            self.content_container,
            text="설치 세부 옵션을 확인하세요",
            font=ctk.CTkFont(family=self.font_family, size=24, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(fill="x", pady=(4, 6))

        dev_ip = self.selected_device.ip if self.selected_device else "미선택"
        dev_model = self.selected_device.model if self.selected_device else ""
        sub = ctk.CTkLabel(
            self.content_container,
            text=f"대상 장비: {dev_model} ({dev_ip})  —  설치에 필요한 항목을 아래에서 바로 설정할 수 있습니다.",
            font=ctk.CTkFont(family=self.font_family, size=13),
            text_color=COLOR_TEXT_SUB,
            anchor="w",
        )
        sub.pack(fill="x", pady=(0, 14))

        scroll = ctk.CTkScrollableFrame(
            self.content_container,
            fg_color="transparent",
            corner_radius=0,
        )
        scroll.pack(fill="both", expand=True)

        # 1. Printer Settings Section (if mode is "both" or "printer")
        if self.install_mode in ("both", "printer"):
            p_card = ctk.CTkFrame(
                scroll,
                fg_color=COLOR_CARD_SELECTED_BG,
                corner_radius=8,
                border_width=1,
                border_color=COLOR_CARD_BORDER,
            )
            p_card.pack(fill="x", pady=(0, 12))

            ctk.CTkLabel(
                p_card,
                text="🖨️  프린터 드라이버 설정",
                font=ctk.CTkFont(family=self.font_family, size=15, weight="bold"),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(fill="x", padx=18, pady=(14, 8))

            row1 = ctk.CTkFrame(p_card, fg_color="transparent")
            row1.pack(fill="x", padx=18, pady=4)
            ctk.CTkLabel(
                row1,
                text="프린터 표시 이름:",
                width=140,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkEntry(
                row1,
                textvariable=self.printer_name_var,
                font=ctk.CTkFont(family=self.font_family, size=13),
                width=300,
                height=32,
            ).pack(side="left", padx=(4, 12))
            ctk.CTkCheckBox(
                row1,
                text="기본 프린터로 설정",
                variable=self.set_default_printer_var,
                font=ctk.CTkFont(family=self.font_family, size=12),
                text_color=COLOR_TEXT_DARK,
                fg_color=COLOR_PRIMARY,
            ).pack(side="left")

            # Custom Driver Folder/File Picker (for D410/D420 PCL Driver .inf or macOS .pkg)
            row2 = ctk.CTkFrame(p_card, fg_color="transparent")
            row2.pack(fill="x", padx=18, pady=(4, 14))
            ctk.CTkLabel(
                row2,
                text="드라이버 경로 (선택):",
                width=140,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkEntry(
                row2,
                textvariable=self.custom_driver_path_var,
                placeholder_text="비워두면 drivers/ 폴더 또는 KM 통합 PCL 드라이버 자동 사용",
                font=ctk.CTkFont(family=self.font_family, size=12),
                width=310,
                height=32,
            ).pack(side="left", padx=(4, 8))
            ctk.CTkButton(
                row2,
                text="폴더/파일 찾기...",
                font=ctk.CTkFont(family=self.font_family, size=12),
                fg_color="#E5E8EB",
                hover_color="#D1D6DB",
                text_color=COLOR_TEXT_DARK,
                width=110,
                height=32,
                command=self._browse_driver_path,
            ).pack(side="left")

        # 2. Scanner Settings Section (if mode is "both" or "scan")
        if self.install_mode in ("both", "scan"):
            s_card = ctk.CTkFrame(
                scroll,
                fg_color=COLOR_CARD_SELECTED_BG,
                corner_radius=8,
                border_width=1,
                border_color=COLOR_CARD_BORDER,
            )
            s_card.pack(fill="x", pady=(0, 12))

            ctk.CTkLabel(
                s_card,
                text="📠  스캔 주소록 및 수신 폴더 설정",
                font=ctk.CTkFont(family=self.font_family, size=15, weight="bold"),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(fill="x", padx=18, pady=(14, 8))

            s_row1 = ctk.CTkFrame(s_card, fg_color="transparent")
            s_row1.pack(fill="x", padx=18, pady=4)
            ctk.CTkLabel(
                s_row1,
                text="복합기 주소록 이름:",
                width=140,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkEntry(
                s_row1,
                textvariable=self.scan_name_var,
                placeholder_text="복합기 스캔 화면에 표시될 내 이름 (예: 홍길동)",
                font=ctk.CTkFont(family=self.font_family, size=13),
                width=220,
                height=32,
            ).pack(side="left", padx=(4, 14))

            ctk.CTkLabel(
                s_row1,
                text="전송 방식:",
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
            ).pack(side="left", padx=(0, 6))
            ctk.CTkSegmentedButton(
                s_row1,
                values=["내장 FTP 수신 (권장)", "SMB 공유폴더"],
                variable=self.scan_protocol_var,
                font=ctk.CTkFont(family=self.font_family, size=12, weight="bold"),
                selected_color=COLOR_PRIMARY,
                command=self._on_scan_protocol_changed,
            ).pack(side="left")

            self.ftp_notice_lbl = ctk.CTkLabel(
                s_card,
                text="✓ 신도 원터치 방식과 동일하게 내장 FTP 스캔 수신 서버(포트 2121)가 백그라운드에서 자동 작동하므로,\n   별도의 Windows/Mac 공유폴더 설정이나 PC 로그인 비밀번호 입력 없이 Downloads/sindohScan 으로 스캔됩니다.",
                font=ctk.CTkFont(family=self.font_family, size=12),
                text_color=COLOR_PRIMARY,
                justify="left",
                anchor="w",
            )

            self.smb_auth_row = ctk.CTkFrame(s_card, fg_color="transparent")
            ctk.CTkLabel(
                self.smb_auth_row,
                text="PC 계정 / 비밀번호:",
                width=140,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkEntry(
                self.smb_auth_row,
                textvariable=self.pc_username_var,
                placeholder_text="PC 사용자 ID",
                font=ctk.CTkFont(family=self.font_family, size=12),
                width=150,
                height=32,
            ).pack(side="left", padx=(4, 8))
            ctk.CTkEntry(
                self.smb_auth_row,
                textvariable=self.pc_password_var,
                placeholder_text="PC 로그인 암호 (SMB 스캔 시 필요)",
                show="•",
                font=ctk.CTkFont(family=self.font_family, size=12),
                width=220,
                height=32,
            ).pack(side="left")

            self.s_row3 = ctk.CTkFrame(s_card, fg_color="transparent")
            ctk.CTkLabel(
                self.s_row3,
                text="복합기 관리자 암호:",
                width=140,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
            ).pack(side="left")
            ctk.CTkEntry(
                self.s_row3,
                textvariable=self.mfp_admin_pw_var,
                placeholder_text="기본값(Public 등록) 사용 시 비워두세요 (예: 12345678 / sindoh#123)",
                show="•",
                font=ctk.CTkFont(family=self.font_family, size=12),
                width=378,
                height=32,
            ).pack(side="left", padx=(4, 0))

            self._on_scan_protocol_changed(self.scan_protocol_var.get())

        # Test Mode Checkbox
        sim_row = ctk.CTkFrame(scroll, fg_color="transparent")
        sim_row.pack(fill="x", padx=4, pady=(2, 4))
        ctk.CTkCheckBox(
            sim_row,
            text="시뮬레이션(Dry-Run) 모드로 실행 (실제 프린터가 없는 환경에서 설치 UI 및 흐름만 테스트할 때 체크)",
            variable=self.dry_run_var,
            font=ctk.CTkFont(family=self.font_family, size=12),
            text_color=COLOR_TEXT_SUB,
            fg_color=COLOR_PRIMARY,
        ).pack(side="left")

    def _on_scan_protocol_changed(self, value: str) -> None:
        if not hasattr(self, "ftp_notice_lbl") or not hasattr(self, "smb_auth_row"):
            return
        self.ftp_notice_lbl.pack_forget()
        self.smb_auth_row.pack_forget()
        self.s_row3.pack_forget()
        if "FTP" in value.upper():
            self.ftp_notice_lbl.pack(fill="x", padx=18, pady=(6, 4))
        else:
            self.smb_auth_row.pack(fill="x", padx=18, pady=4)
        self.s_row3.pack(fill="x", padx=18, pady=(4, 14))

    def _browse_driver_path(self) -> None:
        folder = filedialog.askdirectory(
            title="D410s / D420 드라이버 압축 해제 폴더 선택 (취소 시 파일 선택 가능)",
            initialdir=str(get_project_drivers_dir()),
        )
        if folder:
            self.custom_driver_path_var.set(folder)
            return
        file_path = filedialog.askopenfilename(
            title="드라이버 파일 선택 (.inf, .zip, .pkg, .ppd)",
            filetypes=[("Driver Files", "*.inf *.zip *.pkg *.gz *.ppd"), ("All Files", "*.*")],
        )
        if file_path:
            self.custom_driver_path_var.set(file_path)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4: 설치 진행하기
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step4_installing(self) -> None:
        title = ctk.CTkLabel(
            self.content_container,
            text="설치를 진행하고 있습니다...",
            font=ctk.CTkFont(family=self.font_family, size=24, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(fill="x", pady=(6, 8))

        sub = ctk.CTkLabel(
            self.content_container,
            text="잠시만 기다려 주세요. 선택한 구성 요소를 자동으로 설정하고 있습니다.",
            font=ctk.CTkFont(family=self.font_family, size=14),
            text_color=COLOR_TEXT_SUB,
            anchor="w",
        )
        sub.pack(fill="x", pady=(0, 20))

        self.progress_bar = ctk.CTkProgressBar(
            self.content_container,
            mode="indeterminate",
            progress_color=COLOR_PRIMARY,
            height=10,
        )
        self.progress_bar.pack(fill="x", pady=(0, 18))
        self.progress_bar.start()

        self.log_textbox = ctk.CTkTextbox(
            self.content_container,
            font=ctk.CTkFont(family=self.font_family, size=12),
            fg_color="#F8F9FA",
            text_color=COLOR_TEXT_DARK,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            corner_radius=8,
            height=280,
        )
        self.log_textbox.pack(fill="both", expand=True)

        self.install_logs.clear()
        self._start_installation_worker()

    def _append_log(self, msg: str) -> None:
        self.install_logs.append(msg)
        if hasattr(self, "log_textbox") and self.log_textbox.winfo_exists():
            self.log_textbox.insert("end", f"• {msg}\n")
            self.log_textbox.see("end")

    def _start_installation_worker(self) -> None:
        if self.install_running:
            return
        self.install_running = True

        dev = self.selected_device or DiscoveredDevice(ip="192.168.0.200", model="SINDOH D410/D420 Series")
        mode = self.install_mode
        printer_name = self.printer_name_var.get().strip() or "SINDOH D410/D420 Series"
        set_default = self.set_default_printer_var.get()
        custom_drv = self.custom_driver_path_var.get().strip() or None
        scan_name = self.scan_name_var.get().strip() or "SindohScan"
        protocol = self.scan_protocol_var.get()
        pc_user = self.pc_username_var.get().strip()
        pc_pw = self.pc_password_var.get()
        admin_pw = self.mfp_admin_pw_var.get()
        dry_run = self.dry_run_var.get()

        def log_safe(m: str) -> None:
            self.after(0, lambda: self._append_log(m))

        def worker() -> None:
            self.printer_result_text = ""
            self.scan_result_text = ""

            if mode in ("both", "printer"):
                res_p = install_printer_cross_platform(
                    ip=dev.ip,
                    printer_name=printer_name,
                    set_default=set_default,
                    custom_driver_path=custom_drv,
                    log_cb=log_safe,
                    dry_run=dry_run,
                )
                self.printer_result_text = f"{res_p.title} — {res_p.detail}"

            if mode in ("both", "scan"):
                res_s = configure_scanner_cross_platform(
                    mfp_ip=dev.ip,
                    scan_name=scan_name,
                    protocol=protocol,
                    pc_username=pc_user,
                    pc_password=pc_pw,
                    mfp_admin_password=admin_pw,
                    log_cb=log_safe,
                    dry_run=dry_run,
                )
                self.scan_result_text = f"{res_s.title} — {res_s.detail}"

            self.install_running = False
            self.after(600, lambda: self._show_step(5))

        threading.Thread(target=worker, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5: 설치 완료
    # ─────────────────────────────────────────────────────────────────────────
    def _build_step5_complete(self) -> None:
        title = ctk.CTkLabel(
            self.content_container,
            text="설치가 완료되었습니다!",
            font=ctk.CTkFont(family=self.font_family, size=26, weight="bold"),
            text_color=COLOR_TEXT_DARK,
            anchor="w",
        )
        title.pack(fill="x", pady=(6, 8))

        sub = ctk.CTkLabel(
            self.content_container,
            text="요청하신 D410s / D420 프린터 및 스캔 구성이 정상적으로 처리되었습니다.",
            font=ctk.CTkFont(family=self.font_family, size=14),
            text_color=COLOR_TEXT_SUB,
            anchor="w",
        )
        sub.pack(fill="x", pady=(0, 24))

        summary_card = ctk.CTkFrame(
            self.content_container,
            fg_color=COLOR_CARD_SELECTED_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        summary_card.pack(fill="x", pady=6)

        if self.printer_result_text:
            row_p = ctk.CTkFrame(summary_card, fg_color="transparent")
            row_p.pack(fill="x", padx=20, pady=(16, 8))
            ctk.CTkLabel(
                row_p,
                text="✓ 프린터 설치:",
                font=ctk.CTkFont(family=self.font_family, size=14, weight="bold"),
                text_color=COLOR_SUCCESS,
                width=120,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row_p,
                text=self.printer_result_text,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
                wraplength=460,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

        if self.scan_result_text:
            row_s = ctk.CTkFrame(summary_card, fg_color="transparent")
            row_s.pack(fill="x", padx=20, pady=(8, 16))
            ctk.CTkLabel(
                row_s,
                text="✓ 스캔 설정:",
                font=ctk.CTkFont(family=self.font_family, size=14, weight="bold"),
                text_color=COLOR_SUCCESS,
                width=120,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row_s,
                text=self.scan_result_text,
                font=ctk.CTkFont(family=self.font_family, size=13),
                text_color=COLOR_TEXT_DARK,
                anchor="w",
                wraplength=460,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

        # Quick action buttons (Open Scan Folder / Open Printer Web UI)
        btn_row = ctk.CTkFrame(self.content_container, fg_color="transparent")
        btn_row.pack(fill="x", pady=20)

        ctk.CTkButton(
            btn_row,
            text="📂  스캔 수신 폴더 열기 (Downloads/sindohScan)",
            font=ctk.CTkFont(family=self.font_family, size=13, weight="bold"),
            fg_color="#EEF3FF",
            hover_color="#DCE7FF",
            text_color=COLOR_PRIMARY,
            height=38,
            command=self._open_scan_folder,
        ).pack(side="left", padx=(0, 12))

        if self.selected_device:
            ctk.CTkButton(
                btn_row,
                text=f"🌐  복합기 웹 설정 페이지 열기 ({self.selected_device.ip})",
                font=ctk.CTkFont(family=self.font_family, size=13),
                fg_color="#F2F4F7",
                hover_color="#E5E8EB",
                text_color=COLOR_TEXT_DARK,
                height=38,
                command=self._open_mfp_webpage,
            ).pack(side="left")

    def _open_scan_folder(self) -> None:
        folder = get_default_scan_folder()
        sys_name = platform.system().lower()
        if sys_name == "windows":
            os.startfile(str(folder))
        elif sys_name == "darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])

    def _open_mfp_webpage(self) -> None:
        if not self.selected_device:
            return
        import webbrowser

        webbrowser.open(f"http://{self.selected_device.ip}")

    # ─────────────────────────────────────────────────────────────────────────
    # Navigation Handlers
    # ─────────────────────────────────────────────────────────────────────────
    def _on_reset_clicked(self) -> None:
        if self.install_running:
            return
        self._show_step(1)

    def _on_prev_clicked(self) -> None:
        if self.install_running:
            return
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    def _on_next_clicked(self) -> None:
        if self.current_step == 5:
            self.destroy()
            return
        if self.current_step == 2 and self.selected_device is None:
            messagebox.showwarning("장치 선택 필요", "설치할 복합기를 목록에서 선택하거나 IP 주소를 직접 추가해 주세요.")
            return
        if self.current_step < 5:
            self._show_step(self.current_step + 1)


if __name__ == "__main__":
    app = D410ConnectApp()
    if "--self-test" in sys.argv:
        app.after(250, app.destroy)
    app.mainloop()
    if "--self-test" in sys.argv:
        print("SELF_TEST_OK")
