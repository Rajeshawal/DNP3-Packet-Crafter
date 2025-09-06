#!/usr/bin/env python3
"""
DNP3 Link + Transport + Application (single-fragment) Byte Picker GUI (v0.9)

What's new in v0.9
- **TCP Sender now lets you set the port** (default 20000). Input validation for 1–65535.
- Status text shows IP:port. Everything else works as before.

Note: This sends whatever hex you compose (Link+Transport+Application) as raw bytes over TCP.
For real outstations, you usually need correct per-block CRCs for the Link user data too.
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

HEX_VALUES = [f"{i:02X}" for i in range(256)]

# ---------------- Link layer (manual grid) ----------------
LINK_FIELDS = [
    ("Start 0", "05"),
    ("Start 1", "64"),
    ("Length",  "0A"),
    ("Control", "C4"),
    ("Dest LSB", "0A"),
    ("Dest MSB", "00"),
    ("Src LSB",  "01"),
    ("Src MSB",  "00"),
    ("CRC LSB",  "00"),
    ("CRC MSB",  "00"),
]

# ---------------- Application: Function codes ----------------
APP_FUNC_OPTIONS = [
    ("01", "READ"), ("02", "WRITE"), ("03", "SELECT"), ("04", "OPERATE"),
    ("05", "DIRECT OPERATE"), ("06", "DIRECT OPERATE NO ACK"), ("07", "FREEZE"),
    ("08", "FREEZE NO ACK"), ("09", "FREEZE CLEAR"), ("0A", "FREEZE CLEAR NO ACK"),
    ("0B", "FREEZE AT TIME"), ("0C", "FREEZE AT TIME NO ACK"), ("0D", "COLD RESTART"),
    ("0E", "WARM RESTART"), ("0F", "INITIALIZE DATA"), ("10", "INITIALIZE APPLICATION"),
    ("11", "START APPLICATION"), ("12", "STOP APPLICATION"), ("14", "ENABLE UNSOLICITED"),
    ("15", "DISABLE UNSOLICITED"), ("16", "ASSIGN CLASS"), ("17", "DELAY MEASURE"),
    ("18", "RECORD CURRENT TIME"), ("81", "RESPONSE"), ("82", "UNSOLICITED RESPONSE"),
]

# ---------------- Application: Object groups & variations ----------------
OBJ_GROUPS = [
    ("01", "G1 Binary Input"), ("02", "G2 Binary Output Status"), ("03", "G3 Double-bit BI"),
    ("04", "G4 Double-bit BO Status"), ("12", "G12 Control Relay Output Block (CROB)"),
    ("20", "G20 Counter"), ("21", "G21 Frozen Counter"), ("22", "G22 Counter Event"),
    ("30", "G30 Analog Input"), ("32", "G32 Analog Input Event"), ("40", "G40 Analog Output"),
    ("41", "G41 Analog Output Event"), ("50", "G50 Time / Date"), ("60", "G60 Class Data"),
]

OBJ_VARIATIONS = {
    "01": [("01","V1 packed"), ("02","V2 flags"), ("03","V3 flags+time")],
    "02": [("01","V1 flags"), ("02","V2 flags+time")],
    "03": [("01","V1"), ("02","V2"), ("03","V3 time")],
    "04": [("01","V1 flags"), ("02","V2 flags+time")],
    "12": [("01","V1 CROB")],
    "20": [("01","V1 32b+flags"), ("02","V2 16b+flags"), ("05","V5 32b+flags+time"), ("06","V6 16b+flags+time")],
    "21": [("01","V1 32b+flags"), ("02","V2 16b+flags"), ("05","V5 32b+flags+time"), ("06","V6 16b+flags+time")],
    "22": [("01","V1 32b+flags+time"), ("02","V2 16b+flags+time")],
    "30": [("01","V1 32b"), ("02","V2 16b"), ("03","V3 32b+time"), ("04","V4 16b+time")],
    "32": [("01","V1 32b+flags+time"), ("02","V2 16b+flags+time"), ("03","V3 short float+flags+time")],
    "40": [("01","V1 32b"), ("02","V2 16b")],
    "41": [("01","V1 32b+time"), ("02","V2 16b+time")],
    "50": [("01","V1 time & date"), ("02","V2 interval"), ("03","V3 absolute time"), ("04","V4 delay meas")],
    "60": [("01","V1 class 0"), ("02","V2 class 1"), ("03","V3 class 2"), ("04","V4 class 3")],
}

QUALIFIERS = [
    ("00", "Range: 1-octet start/stop"), ("01", "Range: 2-octet start/stop"), ("06", "All objects"),
    ("07", "Count+Index: 1-octet each"), ("08", "Count+Index: 2-octet each"), ("17", "Count only: 1-octet"), ("28", "Count only: 2-octet"),
]

# ---------------- Link Easy Builder options ----------------
PRIMARY_FUNCS = [
    (0,  "Reset Link"), (1,  "Reset of User Process"), (2,  "Test Link (with data)"),
    (3,  "User Data (confirm req)"), (4,  "User Data (no confirm)"), (9,  "Request Link Status"),
]
SECONDARY_FUNCS = [
    (0,  "ACK"), (1,  "NACK"), (11, "Link Status"), (15, "Not Supported"),
]

TEMPLATES = [
    ("Master User Data (no confirm)",  {"dir":1, "prm":1, "fcv":1, "fcb":0, "func":4}),
    ("Master User Data (confirm req)", {"dir":1, "prm":1, "fcv":1, "fcb":0, "func":3}),
    ("Master Request Link Status",     {"dir":1, "prm":1, "fcv":0, "fcb":0, "func":9}),
    ("Master Reset Link",              {"dir":1, "prm":1, "fcv":0, "fcb":0, "func":0}),
    ("Outstation ACK",                 {"dir":0, "prm":0, "fcv":0, "fcb":0, "func":0}),
    ("Outstation Link Status",         {"dir":0, "prm":0, "fcv":0, "fcb":0, "func":11}),
]

# ---------------- CRC (DNP3 16-bit, poly 0x3D65; reflected 0xA6BC) ----------------

def dnp3_crc16(data_bytes):
    crc = 0x0000
    for b in data_bytes:
        crc ^= b & 0xFF
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc

# ---------------- Simple tooltip helper ----------------
class Tooltip:
    def __init__(self, widget, text, wrap=320):
        self.widget = widget
        self.text = text
        self.wrap = wrap
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _evt=None):
        if self.tip: return
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, justify="left", relief="solid", borderwidth=1,
                       font=("Segoe UI", 9), wraplength=self.wrap, bg="#ffffe0")
        lbl.pack(ipadx=6, ipady=4)

    def _hide(self, _evt=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None

# ---------------- GUI ----------------
class BytePickerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DNP3 Link + Transport + Application (single fragment) – Byte Picker v0.9")
        # Small-laptop friendly defaults
        self.geometry("980x720")
        try:
            self.minsize(800, 560)
        except Exception:
            pass
        self.sock = None
        self._make_ui()
        self.bind_all("<Return>", lambda e: self.join_bytes())

    def _make_ui(self):
        # ---- Scrollable root (Canvas + both scrollbars) ----
        scroller = ttk.Frame(self)
        scroller.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(scroller, highlightthickness=0)
        vbar = ttk.Scrollbar(scroller, orient=tk.VERTICAL, command=self._canvas.yview)
        hbar = ttk.Scrollbar(scroller, orient=tk.HORIZONTAL, command=self._canvas.xview)
        self._canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)

        self._canvas.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        scroller.rowconfigure(0, weight=1)
        scroller.columnconfigure(0, weight=1)

        content = ttk.Frame(self._canvas)
        self._canvas_window = self._canvas.create_window((0, 0), window=content, anchor="nw")

        def _on_content_configure(event=None):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        content.bind("<Configure>", _on_content_configure)

        # Mouse wheel bindings
        def _on_mousewheel(event):
            delta = event.delta
            if delta == 0:
                return
            steps = int(-1 * (delta / 120))
            self._canvas.yview_scroll(steps, "units")
        def _on_shift_mousewheel(event):
            delta = event.delta
            steps = int(-1 * (delta / 120))
            self._canvas.xview_scroll(steps, "units")
        self._canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._canvas.bind_all("<Shift-MouseWheel>", _on_shift_mousewheel)
        self._canvas.bind_all("<Button-4>", lambda e: self._canvas.yview_scroll(-3, "units"))
        self._canvas.bind_all("<Button-5>", lambda e: self._canvas.yview_scroll(3, "units"))

        root = ttk.Frame(content, padding=12)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text="Select DNP3 Link, Transport, and Application (single fragment) Bytes", font=("Segoe UI", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(root, text="Tip: Use the Easy Link Builder to auto-compose Link header; hover any field for hints.").pack(anchor=tk.W, pady=(0,10))

        panels = ttk.Frame(root)
        panels.pack(fill=tk.BOTH, expand=False)

        # ---- Link Easy Builder ----
        easyf = ttk.LabelFrame(panels, text="Link Layer – Easy Builder")
        easyf.grid(row=0, column=0, sticky=tk.NW, padx=(0,10), pady=(0,10))

        self.use_easy = tk.BooleanVar(value=True)
        ttk.Checkbutton(easyf, text="Use Easy Link Builder (override manual 10 bytes)", variable=self.use_easy, command=self._on_easy_toggle).pack(anchor=tk.W, padx=8, pady=(6,0))

        easyg = ttk.Frame(easyf)
        easyg.pack(padx=8, pady=8)

        # Start bytes (fixed)
        ttk.Label(easyg, text="Start0").grid(row=0, column=0, sticky=tk.W)
        s0 = ttk.Label(easyg, text="05", relief=tk.SUNKEN, padding=(6,2))
        s0.grid(row=1, column=0, sticky=tk.W)
        Tooltip(s0, "Start delimiter byte 0 (0x05)")
        ttk.Label(easyg, text="Start1").grid(row=0, column=1, sticky=tk.W, padx=(8,0))
        s1 = ttk.Label(easyg, text="64", relief=tk.SUNKEN, padding=(6,2))
        s1.grid(row=1, column=1, sticky=tk.W, padx=(8,0))
        Tooltip(s1, "Start delimiter byte 1 (0x64)")

        # DIR / PRM
        ttk.Label(easyg, text="DIR").grid(row=0, column=2, sticky=tk.W, padx=(12,0))
        self.easy_dir = tk.StringVar(value="Master → Outstation (DIR=1)")
        dir_opts = ["Master → Outstation (DIR=1)", "Outstation → Master (DIR=0)"]
        dir_cb = ttk.Combobox(easyg, textvariable=self.easy_dir, values=dir_opts, width=28, state="readonly")
        dir_cb.grid(row=1, column=2, sticky=tk.W, padx=(12,0))
        Tooltip(dir_cb, "Link DIR (bit7): 1=Master→Outstation, 0=Outstation→Master")

        ttk.Label(easyg, text="PRM").grid(row=0, column=3, sticky=tk.W, padx=(8,0))
        self.easy_prm = tk.StringVar(value="Primary / Initiator (PRM=1)")
        prm_opts = ["Primary / Initiator (PRM=1)", "Secondary / Responder (PRM=0)"]
        prm_cb = ttk.Combobox(easyg, textvariable=self.easy_prm, values=prm_opts, width=28, state="readonly")
        prm_cb.grid(row=1, column=3, sticky=tk.W, padx=(8,0))
        prm_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_link_funcs())
        Tooltip(prm_cb, "Link PRM (bit6): 1=Primary (initiator), 0=Secondary (responder)")

        # Function list depends on PRM
        ttk.Label(easyg, text="Link Function").grid(row=0, column=4, sticky=tk.W, padx=(8,0))
        self.easy_func = tk.StringVar()
        self.easy_func_cb = ttk.Combobox(easyg, values=[], width=28, state="readonly", textvariable=self.easy_func)
        self.easy_func_cb.grid(row=1, column=4, sticky=tk.W, padx=(8,0))
        Tooltip(self.easy_func_cb, "Link-layer function code (bits0-3). Choices depend on PRM=1 (primary) or PRM=0 (secondary).")

        # FCB/FCV
        flagg = ttk.Frame(easyf)
        flagg.pack(padx=8, pady=(0,6), anchor=tk.W)
        self.easy_fcb = tk.BooleanVar(value=False)
        self.easy_fcv = tk.BooleanVar(value=True)
        cb_fcb = ttk.Checkbutton(flagg, text="FCB (Frame Count Bit)", variable=self.easy_fcb, command=self._update_easy_link)
        cb_fcb.pack(side=tk.LEFT)
        Tooltip(cb_fcb, "Link FCB (bit5). Toggles to detect repeats when FCV=1.")
        cb_fcv = ttk.Checkbutton(flagg, text="FCV (Frame Count Valid)", variable=self.easy_fcv, command=self._update_easy_link)
        cb_fcv.pack(side=tk.LEFT, padx=(10,0))
        Tooltip(cb_fcv, "Link FCV (bit4). 1=FCB is meaningful; 0=ignore FCB.")

        # Addresses
        addr = ttk.Frame(easyf)
        addr.pack(padx=8, pady=(0,6), anchor=tk.W)
        ttk.Label(addr, text="Destination (0–65521)").pack(side=tk.LEFT)
        self.dest_addr = tk.IntVar(value=10)
        dest_sp = ttk.Spinbox(addr, from_=0, to=65521, width=8, textvariable=self.dest_addr, command=self._update_easy_link)
        dest_sp.pack(side=tk.LEFT, padx=(6,12))
        Tooltip(dest_sp, "Link destination address (LSB/MSB emitted little-endian)")
        ttk.Label(addr, text="Source (0–65521)").pack(side=tk.LEFT)
        self.src_addr = tk.IntVar(value=1)
        src_sp = ttk.Spinbox(addr, from_=0, to=65521, width=8, textvariable=self.src_addr, command=self._update_easy_link)
        src_sp.pack(side=tk.LEFT, padx=(6,12))
        Tooltip(src_sp, "Link source address (LSB/MSB emitted little-endian)")
        swap_btn = ttk.Button(addr, text="Swap", command=self._swap_addrs)
        swap_btn.pack(side=tk.LEFT)
        Tooltip(swap_btn, "Swap destination and source addresses")

        # Templates
        tplf = ttk.Frame(easyf)
        tplf.pack(padx=8, pady=(0,6), anchor=tk.W)
        ttk.Label(tplf, text="Template:").pack(side=tk.LEFT)
        self.tpl_var = tk.StringVar(value=TEMPLATES[0][0])
        tpl_values = [name for name, _ in TEMPLATES]
        tpl_cb = ttk.Combobox(tplf, values=tpl_values, textvariable=self.tpl_var, width=28, state="readonly")
        tpl_cb.pack(side=tk.LEFT, padx=(6,0))
        ttk.Button(tplf, text="Apply", command=self._apply_template).pack(side=tk.LEFT, padx=(6,0))

        # Computed fields
        show = ttk.Frame(easyf)
        show.pack(padx=8, pady=(0,8), anchor=tk.W)
        ttk.Label(show, text="Control").grid(row=0, column=0, sticky=tk.W)
        self.easy_ctrl_hex = tk.StringVar(value="C4")
        ctrl_ent = ttk.Entry(show, textvariable=self.easy_ctrl_hex, width=8, state="readonly")
        ctrl_ent.grid(row=1, column=0, sticky=tk.W)
        Tooltip(ctrl_ent, "Composed Link Control byte: DIR|PRM|FCB|FCV|FUNC")
        ttk.Label(show, text="Length (auto)").grid(row=0, column=1, sticky=tk.W, padx=(8,0))
        self.easy_len_hex = tk.StringVar(value="0A")
        ln_ent = ttk.Entry(show, textvariable=self.easy_len_hex, width=8, state="readonly")
        ln_ent.grid(row=1, column=1, sticky=tk.W, padx=(8,0))
        Tooltip(ln_ent, "Link Length: octets from Control through end of user data")
        ttk.Label(show, text="Header CRC LSB").grid(row=0, column=2, sticky=tk.W, padx=(8,0))
        self.easy_crc_lsb = tk.StringVar(value="00")
        crc_l_ent = ttk.Entry(show, textvariable=self.easy_crc_lsb, width=8, state="readonly")
        crc_l_ent.grid(row=1, column=2, sticky=tk.W, padx=(8,0))
        Tooltip(crc_l_ent, "Link header CRC (LSB)")
        ttk.Label(show, text="Header CRC MSB").grid(row=0, column=3, sticky=tk.W, padx=(8,0))
        self.easy_crc_msb = tk.StringVar(value="00")
        crc_h_ent = ttk.Entry(show, textvariable=self.easy_crc_msb, width=8, state="readonly")
        crc_h_ent.grid(row=1, column=3, sticky=tk.W, padx=(8,0))
        Tooltip(crc_h_ent, "Link header CRC (MSB)")

        self.easy_bytes_label = ttk.Label(easyf, text="Link bytes (easy): 05 64 0A C4 0A 00 01 00 00 00")
        self.easy_bytes_label.pack(anchor=tk.W, padx=8, pady=(4,6))

        # ---- Link Manual Grid ----
        linkf = ttk.LabelFrame(panels, text="Link Layer – Manual 10 bytes")
        linkf.grid(row=0, column=1, sticky=tk.NW, padx=(0,10), pady=(0,10))
        self.link_byte_vars = []
        link_grid = ttk.Frame(linkf)
        link_grid.pack(padx=8, pady=8)
        for idx, (label, default) in enumerate(LINK_FIELDS):
            row = idx // 5
            col = idx % 5
            cell = ttk.Frame(link_grid, padding=(4,6))
            cell.grid(row=row, column=col, sticky=tk.W)
            ttk.Label(cell, text=f"[{idx}] {label}").pack(anchor=tk.W)
            var = tk.StringVar(value=default)
            cb = ttk.Combobox(cell, textvariable=var, values=HEX_VALUES, width=6, state="readonly")
            cb.pack(anchor=tk.W)
            self.link_byte_vars.append(var)

        # ---- Transport Layer ----
        transf = ttk.LabelFrame(root, text="Transport Layer (single fragment)")
        transf.pack(fill=tk.X, pady=(6,6))
        grid = ttk.Frame(transf)
        grid.pack(padx=8, pady=8)
        ttk.Label(grid, text="FIR (First fragment)").grid(row=0, column=0, sticky=tk.W)
        self.fir_var = tk.StringVar(value="1")
        fir_cb = ttk.Combobox(grid, textvariable=self.fir_var, values=["0","1"], width=4, state="readonly")
        fir_cb.grid(row=1, column=0)
        Tooltip(fir_cb, "Transport FIR (bit7): 1 for the first fragment of this on-the-wire sequence")

        ttk.Label(grid, text="FIN (Final fragment)").grid(row=0, column=1, sticky=tk.W, padx=(10,0))
        self.fin_var = tk.StringVar(value="1")
        fin_cb = ttk.Combobox(grid, textvariable=self.fin_var, values=["0","1"], width=4, state="readonly")
        fin_cb.grid(row=1, column=1, padx=(10,0))
        Tooltip(fin_cb, "Transport FIN (bit6): 1 for the last fragment; 0 if more fragments follow")

        ttk.Label(grid, text="SEQ (0–63, per fragment)").grid(row=0, column=2, sticky=tk.W, padx=(10,0))
        self.seq_var = tk.StringVar(value="0")
        seq_entry = ttk.Entry(grid, textvariable=self.seq_var, width=6)
        seq_entry.grid(row=1, column=2, padx=(10,0))
        Tooltip(seq_entry, "Transport SEQ (6 bits): increments each fragment, independent of Application SEQ")

        ttk.Label(grid, text="Transport Byte").grid(row=0, column=3, sticky=tk.W, padx=(16,0))
        self.trans_hex_var = tk.StringVar(value="C0")
        trans_hex = ttk.Entry(grid, textvariable=self.trans_hex_var, width=8, state="readonly")
        trans_hex.grid(row=1, column=3, padx=(16,0))
        Tooltip(trans_hex, "Computed: (FIR<<7)|(FIN<<6)|(SEQ&0x3F)")

        self.trans_desc = tk.StringVar(value="C0 = FIR=1 FIN=1 SEQ=0")
        ttk.Label(transf, textvariable=self.trans_desc, foreground="#555").pack(anchor=tk.W, padx=8, pady=(0,6))

        # ---- Application Layer ----
        appf = ttk.LabelFrame(root, text="Application Layer (single fragment)")
        appf.pack(fill=tk.X, pady=(6,6))

        app_top = ttk.Frame(appf)
        app_top.pack(fill=tk.X, padx=8, pady=8)

        ac = ttk.LabelFrame(app_top, text="Application Control")
        ac.pack(side=tk.LEFT, padx=(0,12))
        acg = ttk.Frame(ac)
        acg.pack(padx=8, pady=8)
        ttk.Label(acg, text="FIR (first APDU fragment)").grid(row=0, column=0, sticky=tk.W)
        self.ac_fir = tk.StringVar(value="1")
        ac_fir_cb = ttk.Combobox(acg, textvariable=self.ac_fir, values=["0","1"], width=4, state="readonly")
        ac_fir_cb.grid(row=1, column=0)
        Tooltip(ac_fir_cb, "Application FIR (bit7): 1 on the first fragment of this APDU")

        ttk.Label(acg, text="FIN (final APDU fragment)").grid(row=0, column=1, sticky=tk.W, padx=(8,0))
        self.ac_fin = tk.StringVar(value="1")
        ac_fin_cb = ttk.Combobox(acg, textvariable=self.ac_fin, values=["0","1"], width=4, state="readonly")
        ac_fin_cb.grid(row=1, column=1, padx=(8,0))
        Tooltip(ac_fin_cb, "Application FIN (bit6): 1 on the last fragment of this APDU")

        ttk.Label(acg, text="CON (confirm required)").grid(row=0, column=2, sticky=tk.W, padx=(8,0))
        self.ac_con = tk.StringVar(value="0")
        ac_con_cb = ttk.Combobox(acg, textvariable=self.ac_con, values=["0","1"], width=4, state="readonly")
        ac_con_cb.grid(row=1, column=2, padx=(8,0))
        Tooltip(ac_con_cb, "Application CON (bit5): 1 means peer should send Application CONFIRM")

        ttk.Label(acg, text="UNS (unsolicited)").grid(row=0, column=3, sticky=tk.W, padx=(8,0))
        self.ac_uns = tk.StringVar(value="0")
        ac_uns_cb = ttk.Combobox(acg, textvariable=self.ac_uns, values=["0","1"], width=4, state="readonly")
        ac_uns_cb.grid(row=1, column=3, padx=(8,0))
        Tooltip(ac_uns_cb, "Application UNS (bit4): set by outstation on unsolicited responses")

        ttk.Label(acg, text="SEQ (0–15, per APDU)").grid(row=0, column=4, sticky=tk.W, padx=(8,0))
        self.ac_seq = tk.StringVar(value="0")
        ac_seq_ent = ttk.Entry(acg, textvariable=self.ac_seq, width=6)
        ac_seq_ent.grid(row=1, column=4, padx=(8,0))
        Tooltip(ac_seq_ent, "Application SEQ (4 bits): stable across all fragments of the same APDU; echoed in responses")

        ttk.Label(acg, text="AppCtrl Byte").grid(row=0, column=5, sticky=tk.W, padx=(12,0))
        self.ac_hex = tk.StringVar(value="C0")
        ac_hex_ent = ttk.Entry(acg, textvariable=self.ac_hex, width=8, state="readonly")
        ac_hex_ent.grid(row=1, column=5, padx=(12,0))
        Tooltip(ac_hex_ent, "Computed: (FIR<<7)|(FIN<<6)|(CON<<5)|(UNS<<4)|(SEQ&0x0F)")

        fc = ttk.LabelFrame(app_top, text="Function Code")
        fc.pack(side=tk.LEFT, padx=(0,12))
        self.fc_var = tk.StringVar()
        fc_values = [f"{code}  —  {name}" for code, name in APP_FUNC_OPTIONS]
        self.fc_combo = ttk.Combobox(fc, values=fc_values, width=34, state="readonly", textvariable=self.fc_var)
        self.fc_combo.pack(padx=8, pady=8)
        self.fc_combo.set("01  —  READ")
        Tooltip(self.fc_combo, "Application Function Code: request/response operation")

        obj = ttk.LabelFrame(appf, text="Object (one header)")
        obj.pack(fill=tk.X, padx=8, pady=(0,8))
        objg = ttk.Frame(obj)
        objg.pack(padx=8, pady=8)

        ttk.Label(objg, text="Group").grid(row=0, column=0, sticky=tk.W)
        self.obj_group = tk.StringVar(value="01  —  G1 Binary Input")
        group_values = [f"{code}  —  {name}" for code, name in OBJ_GROUPS]
        self.group_combo = ttk.Combobox(objg, values=group_values, width=28, state="readonly", textvariable=self.obj_group)
        self.group_combo.grid(row=1, column=0, sticky=tk.W)
        self.group_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_variations())
        Tooltip(self.group_combo, "Object Group: selects the data type family (e.g., Binary Input, Analog Input)")

        ttk.Label(objg, text="Variation").grid(row=0, column=1, sticky=tk.W, padx=(10,0))
        self.obj_variation = tk.StringVar()
        self.variation_combo = ttk.Combobox(objg, values=[], width=24, state="readonly", textvariable=self.obj_variation)
        self.variation_combo.grid(row=1, column=1, sticky=tk.W, padx=(10,0))
        Tooltip(self.variation_combo, "Variation within the Group (encoding: with/without flags/time, size)")

        ttk.Label(objg, text="Qualifier").grid(row=0, column=2, sticky=tk.W, padx=(10,0))
        qual_values = [f"{code}  —  {name}" for code, name in QUALIFIERS]
        self.obj_qual = tk.StringVar(value="06  —  All objects")
        self.qual_combo = ttk.Combobox(objg, values=qual_values, width=28, state="readonly", textvariable=self.obj_qual)
        self.qual_combo.grid(row=1, column=2, sticky=tk.W, padx=(10,0))
        Tooltip(self.qual_combo, "Qualifier specifies addressing style: All, Range, or Count+Index (sizes vary)")

        ttk.Label(objg, text="Extra bytes (hex, space-separated)").grid(row=0, column=3, sticky=tk.W, padx=(10,0))
        self.obj_extra = tk.StringVar(value="")
        extra_ent = ttk.Entry(objg, textvariable=self.obj_extra, width=28)
        extra_ent.grid(row=1, column=3, sticky=tk.W, padx=(10,0))
        Tooltip(extra_ent, "Optional range/count bytes for the chosen Qualifier (e.g., start/stop, count/index)")

        ttk.Label(objg, text="Object Bytes").grid(row=0, column=4, sticky=tk.W, padx=(14,0))
        self.obj_hex = tk.StringVar(value="01 02 06")
        obj_hex_ent = ttk.Entry(objg, textvariable=self.obj_hex, width=18, state="readonly")
        obj_hex_ent.grid(row=1, column=4, sticky=tk.W, padx=(14,0))
        Tooltip(obj_hex_ent, "Computed: Group Variation Qualifier [Extra bytes]")

        # ---- TCP Sender Panel ----
        tcpf = ttk.LabelFrame(root, text="TCP Sender (DNP3 over TCP)")
        tcpf.pack(fill=tk.X, pady=(6,6))
        tcp_row = ttk.Frame(tcpf)
        tcp_row.pack(fill=tk.X, padx=8, pady=8)

        ttk.Label(tcp_row, text="IP Address").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ip_entry = ttk.Entry(tcp_row, textvariable=self.ip_var, width=18)
        ip_entry.pack(side=tk.LEFT, padx=(6,10))
        Tooltip(ip_entry, "Target outstation/master IP.")

        ttk.Label(tcp_row, text="Port").pack(side=tk.LEFT)
        self.port_var = tk.IntVar(value=20000)
        port_sp = ttk.Spinbox(tcp_row, from_=1, to=65535, width=8, textvariable=self.port_var)
        port_sp.pack(side=tk.LEFT, padx=(4,10))
        Tooltip(port_sp, "TCP port (1–65535). Default DNP3 over TCP is 20000.")

        self.connect_btn = ttk.Button(tcp_row, text="Connect", command=self._connect_tcp)
        self.connect_btn.pack(side=tk.LEFT)
        self.send_btn = ttk.Button(tcp_row, text="Send", command=self._send_tcp, state="disabled")
        self.send_btn.pack(side=tk.LEFT, padx=(8,0))

        # Status dot + text
        stat = ttk.Frame(tcpf)
        stat.pack(fill=tk.X, padx=8, pady=(0,6))
        self.status_canvas = tk.Canvas(stat, width=14, height=14, highlightthickness=0)
        self.status_canvas.pack(side=tk.LEFT)
        self._status_dot = self.status_canvas.create_oval(2,2,12,12, fill="#888", outline="")
        self.tcp_status_text = tk.StringVar(value="Disconnected")
        ttk.Label(stat, textvariable=self.tcp_status_text).pack(side=tk.LEFT, padx=(6,0))

        # Buttons & Output
        btns = ttk.Frame(root)
        btns.pack(fill=tk.X, pady=(4,6))
        ttk.Button(btns, text="Join (Enter)", command=self.join_bytes).pack(side=tk.LEFT)
        ttk.Button(btns, text="Copy", command=self.copy_output).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Clear", command=self.clear_output).pack(side=tk.LEFT)

        out = ttk.LabelFrame(root, text="Combined Bytes (Hex, space-separated)")
        out.pack(fill=tk.BOTH, expand=True)
        self.output = tk.Text(out, height=10, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.insert("1.0", self._current_combined())

        # Live bindings
        for var_name in ["easy_dir", "easy_prm"]:
            getattr(self, var_name).trace_add("write", lambda *args: self._refresh_link_funcs())
        self.easy_func.trace_add("write", lambda *args: self._update_easy_link())

        for var in ("ac_fir","ac_fin","ac_con","ac_uns"):
            getattr(self, var).trace_add("write", lambda *args: self._update_app_bytes())
        self.ac_seq.trace_add("write", lambda *args: self._update_app_bytes())
        self.obj_extra.trace_add("write", lambda *args: self._update_object_hex())
        self.group_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_variations())
        self.variation_combo.bind("<<ComboboxSelected>>", lambda e: self._update_object_hex())
        self.qual_combo.bind("<<ComboboxSelected>>", lambda e: self._update_object_hex())

        # Initialize
        self._refresh_link_funcs()
        self._update_easy_link()
        self._update_transport_hex()
        self._refresh_variations()
        self._update_app_bytes()

    # ---- Easy Link helpers ----
    def _on_easy_toggle(self):
        self.join_bytes()

    def _refresh_link_funcs(self):
        prm_is_primary = self.easy_prm.get().startswith("Primary")
        funcs = PRIMARY_FUNCS if prm_is_primary else SECONDARY_FUNCS
        values = [f"{code:02d} — {name}" for code, name in funcs]
        self.easy_func_cb.configure(values=values)
        if not self.easy_func.get() or self.easy_func.get() not in values:
            self.easy_func.set(values[0])
        self._update_easy_link()

    def _apply_template(self):
        name = self.tpl_var.get()
        found = next((cfg for n, cfg in TEMPLATES if n == name), None)
        if not found:
            return
        self.easy_dir.set("Master → Outstation (DIR=1)" if found["dir"] else "Outstation → Master (DIR=0)")
        self.easy_prm.set("Primary / Initiator (PRM=1)" if found["prm"] else "Secondary / Responder (PRM=0)")
        self._refresh_link_funcs()
        funcs = PRIMARY_FUNCS if found["prm"] else SECONDARY_FUNCS
        for code, fname in funcs:
            if code == found["func"]:
                self.easy_func.set(f"{code:02d} — {fname}")
                break
        self.easy_fcv.set(bool(found.get("fcv", 0)))
        self.easy_fcb.set(bool(found.get("fcb", 0)))
        self._update_easy_link()

    def _addr_to_bytes(self, val):
        if val < 0: val = 0
        if val > 65521: val = 65521
        lsb = val & 0xFF
        msb = (val >> 8) & 0xFF
        return f"{lsb:02X}", f"{msb:02X}"

    def _compute_control_easy(self):
        dir_bit = 1 if self.easy_dir.get().startswith("Master") else 0
        prm_bit = 1 if self.easy_prm.get().startswith("Primary") else 0
        fcb_bit = 1 if self.easy_fcb.get() else 0
        fcv_bit = 1 if self.easy_fcv.get() else 0
        func_code = int(self.easy_func.get().split(" ")[0]) if self.easy_func.get() else 4
        val = (dir_bit << 7) | (prm_bit << 6) | (fcb_bit << 5) | (fcv_bit << 4) | (func_code & 0x0F)
        return f"{val:02X}"

    def _hex_list(self, s):
        tokens = [t for t in s.strip().split() if t]
        out = []
        for t in tokens:
            t = t.strip().upper()
            if len(t) == 1:
                t = "0" + t
            out.append(t)
        return out

    def _compute_len_from_user_data(self):
        trans = [self.trans_hex_var.get().upper()]
        app = self._hex_list(getattr(self, 'app_hex', ''))
        return 5 + len(trans + app)

    def _update_easy_link(self):
        ctrl = self._compute_control_easy()
        self.easy_ctrl_hex.set(ctrl)
        dlsb, dmsb = self._addr_to_bytes(self.dest_addr.get())
        slsb, smsb = self._addr_to_bytes(self.src_addr.get())
        ln = self._compute_len_from_user_data()
        if ln < 5: ln = 5
        if ln > 255: ln = 255
        self.easy_len_hex.set(f"{ln:02X}")
        data = [int(self.easy_len_hex.get(),16), int(ctrl,16), int(dlsb,16), int(dmsb,16), int(slsb,16), int(smsb,16)]
        crc = dnp3_crc16(data)
        self.easy_crc_lsb.set(f"{crc & 0xFF:02X}")
        self.easy_crc_msb.set(f"{(crc>>8) & 0xFF:02X}")
        link_bytes = ["05","64", self.easy_len_hex.get(), ctrl, dlsb, dmsb, slsb, smsb, self.easy_crc_lsb.get(), self.easy_crc_msb.get()]
        self.easy_bytes_label.config(text=f"Link bytes (easy): {' '.join(link_bytes)}")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", self._current_combined())

    # ---- Transport + App helpers ----
    def _update_transport_hex(self):
        try:
            fir = 1 if self.fir_var.get() == "1" else 0
            fin = 1 if self.fin_var.get() == "1" else 0
            try:
                seq = int(self.seq_var.get().strip())
            except Exception:
                seq = 0
            if seq < 0: seq = 0
            if seq > 63: seq = 63
            val = (fir << 7) | (fin << 6) | (seq & 0x3F)
            hexv = f"{val:02X}"
        except Exception:
            fir = fin = seq = 0
            hexv = "00"
        self.trans_hex_var.set(hexv)
        if hasattr(self, 'trans_desc'):
            self.trans_desc.set(f"{hexv} = FIR={fir} FIN={fin} SEQ={seq}")
        self._update_easy_link()

    def _compute_app_ctrl(self):
        try:
            fir = 1 if self.ac_fir.get() == "1" else 0
            fin = 1 if self.ac_fin.get() == "1" else 0
            con = 1 if self.ac_con.get() == "1" else 0
            uns = 1 if self.ac_uns.get() == "1" else 0
            try:
                seq = int(self.ac_seq.get().strip())
            except Exception:
                seq = 0
            if seq < 0: seq = 0
            if seq > 15: seq = 15
            val = (fir << 7) | (fin << 6) | (con << 5) | (uns << 4) | (seq & 0x0F)
            return val, fir, fin, con, uns, seq
        except Exception:
            return 0,0,0,0,0,0

    def _update_app_bytes(self):
        val, fir, fin, con, uns, seq = self._compute_app_ctrl()
        hexv = f"{val:02X}"
        self.ac_hex.set(hexv)
        if hasattr(self, 'app_desc'):
            self.app_desc.set(f"{hexv} = FIR={fir} FIN={fin} CON={con} UNS={uns} SEQ={seq}")
        fc_code = self.fc_var.get().split()[0] if self.fc_var.get() else "01"
        self._update_object_hex()
        self.app_hex = f"{self.ac_hex.get()} {fc_code} {self.obj_hex.get()}".strip()
        self._update_easy_link()

    def _refresh_variations(self):
        code = self.obj_group.get().split()[0]
        options = OBJ_VARIATIONS.get(code, [("01","V1")])
        values = [f"{v}  —  {label}" for v, label in options]
        self.variation_combo.configure(values=values)
        self.obj_variation.set(values[0] if values else "01  —  V1")
        self._update_object_hex()

    def _update_object_hex(self):
        g_code = self.obj_group.get().split()[0]
        v_code = (self.obj_variation.get().split()[0] if self.obj_variation.get() else "01")
        q_code = self.obj_qual.get().split()[0]
        extras = self.obj_extra.get().strip()
        extras = " ".join([b.upper() for b in extras.split() if b])
        combined = f"{g_code} {v_code} {q_code}" + (f" {extras}" if extras else "")
        self.obj_hex.set(combined)
        fc_code = self.fc_var.get().split()[0] if self.fc_var.get() else "01"
        self.app_hex = f"{self.ac_hex.get()} {fc_code} {self.obj_hex.get()}".strip()
        self._update_easy_link()

    # ---- Output ----
    def _easy_link_bytes(self):
        ctrl = self._compute_control_easy()
        dlsb, dmsb = self._addr_to_bytes(self.dest_addr.get())
        slsb, smsb = self._addr_to_bytes(self.src_addr.get())
        ln = self._compute_len_from_user_data()
        if ln < 5: ln = 5
        if ln > 255: ln = 255
        data = [ln, int(ctrl,16), int(dlsb,16), int(dmsb,16), int(slsb,16), int(smsb,16)]
        crc = dnp3_crc16(data)
        crc_l = f"{crc & 0xFF:02X}"
        crc_h = f"{(crc>>8) & 0xFF:02X}"
        return ["05","64", f"{ln:02X}", ctrl, dlsb, dmsb, slsb, smsb, crc_l, crc_h]

    def _current_combined(self):
        if getattr(self, 'use_easy', None) and self.use_easy.get():
            link = self._easy_link_bytes()
        else:
            link = [v.get().upper() for v in self.link_byte_vars]
        trans = getattr(self, 'trans_hex_var', tk.StringVar(value="C0")).get().upper()
        app = getattr(self, 'app_hex', '')
        if not app:
            self._update_app_bytes()
            app = self.app_hex
        return " ".join(link + [trans] + app.split())

    def join_bytes(self):
        self._update_transport_hex()
        self._update_app_bytes()
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", self._current_combined())

    def copy_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.output.get("1.0", tk.END).strip())

    def clear_output(self):
        self.output.delete("1.0", tk.END)

    # ---- TCP helpers ----
    def _set_status(self, color="#888", text=""):
        try:
            self.status_canvas.itemconfig(self._status_dot, fill=color)
            self.tcp_status_text.set(text)
        except Exception:
            pass

    def _connect_tcp(self):
        ip = self.ip_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            port = 0
        if not ip:
            messagebox.showerror("TCP", "Please enter an IP address")
            return
        if not (1 <= port <= 65535):
            messagebox.showerror("TCP", "Please enter a valid TCP port (1–65535)")
            return
        self._set_status("#f0ad4e", f"Connecting to {ip}:{port}…")
        self.connect_btn.configure(state="disabled")
        def worker():
            try:
                s = socket.create_connection((ip, port), timeout=3.0)
                s.settimeout(3.0)
                self.sock = s
                self.after(0, lambda: self._on_connected(ip, port))
            except Exception as e:
                self.after(0, lambda: self._on_connect_error(ip, port, str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _on_connected(self, ip, port):
        self._set_status("#5cb85c", f"Connected to {ip}:{port}")
        self.send_btn.configure(state="normal")
        self.connect_btn.configure(state="normal")

    def _on_connect_error(self, ip, port, err):
        self._set_status("#d9534f", f"Connect to {ip}:{port} failed: {err}")
        self.send_btn.configure(state="disabled")
        self.connect_btn.configure(state="normal")

    def _send_tcp(self):
        if not self.sock:
            messagebox.showerror("TCP", "Not connected")
            self._set_status("#d9534f", "Not connected")
            return
        # ensure bytes reflect latest UI
        self.join_bytes()
        hexline = self.output.get("1.0", tk.END).strip()
        try:
            payload = bytes(int(b, 16) for b in hexline.split())
        except Exception:
            messagebox.showerror("TCP", "Hex parse error – check your bytes")
            self._set_status("#d9534f", "Hex parse error")
            return
        self._set_status("#5bc0de", f"Sending {len(payload)} bytes…")
        def worker():
            try:
                self.sock.sendall(payload)
                self.after(0, lambda: self._set_status("#5cb85c", f"Sent {len(payload)} bytes successfully"))
            except Exception as e:
                self.after(0, lambda: self._set_status("#d9534f", f"Send failed: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _swap_addrs(self):
        a = self.dest_addr.get(); b = self.src_addr.get()
        self.dest_addr.set(b); self.src_addr.set(a)
        self._update_easy_link()

if __name__ == "__main__":
    BytePickerGUI().mainloop()
