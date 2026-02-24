#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║       ADVANCED PORT SCANNER — Tkinter GUI Application                ║
║       Version 2.0                                                    ║
║                                                                      ║
║       Features:                                                      ║
║         • Scan TCP ports 1-65535                                     ║
║         • Service & version detection via banner grabbing            ║
║         • Multithreaded scanning (ThreadPoolExecutor)                ║
║         • Color-coded results with scrollable output                 ║
║         • Progress bar + live status                                 ║
║         • Save results to TXT / JSON / CSV                          ║
║         • Non-blocking GUI (background thread for scanning)          ║
║                                                                      ║
║  ⚠  WARNING: This tool is for EDUCATIONAL USE and AUTHORIZED         ║
║     TESTING ONLY. Unauthorized port scanning is ILLEGAL.             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
from datetime import datetime

# ── Make sure parent directory is in path so 'core' imports work ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.port_scanner import PortScanner
from core.service_detector import ServiceDetector
from core.utils import (
    validate_ip,
    resolve_hostname,
    parse_ports,
    format_results,
    format_results_for_gui,
    save_results_json,
    save_results_csv,
    save_results_txt,
    get_local_ip,
)


# ══════════════════════════════════════════════════════════════════
#  Colour / Theme constants
# ══════════════════════════════════════════════════════════════════
BG_DARK      = "#1e1e2e"   # Main background
BG_PANEL     = "#252540"   # Panel / frame background
FG_TEXT      = "#cdd6f4"   # Normal text colour
FG_HEADER    = "#89b4fa"   # Headers, titles
FG_GREEN     = "#a6e3a1"   # Open ports
FG_YELLOW    = "#f9e2af"   # Warnings / version unknown
FG_RED       = "#f38ba8"   # Errors
FG_CYAN      = "#94e2d5"   # Dividers, accents
FG_BANNER    = "#b4befe"   # Banner text
FG_BUTTON    = "#ffffff"   # Button text
BG_BUTTON    = "#7c3aed"   # Button background (purple)
BG_BUTTON_HV = "#6d28d9"   # Button hover
BG_STOP      = "#ef4444"   # Stop button
BG_ENTRY     = "#313244"   # Input field background
FONT_MONO    = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)
FONT_TITLE   = ("Segoe UI", 14, "bold")
FONT_LABEL   = ("Segoe UI", 10)
FONT_BUTTON  = ("Segoe UI", 10, "bold")


class PortScannerGUI:
    """
    Main GUI class for the Advanced Port Scanner.
    All scanning operations run in background threads so the
    Tkinter main loop never freezes.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Advanced Port Scanner v2.0")
        self.root.geometry("920x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG_DARK)

        # State variables
        self.scanner = None
        self.scan_results = None
        self.services_results = None
        self.is_scanning = False

        # Build the UI
        self._build_menu()
        self._build_header()
        self._build_input_panel()
        self._build_progress_panel()
        self._build_output_panel()
        self._build_status_bar()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ──────────────────────────────────────────────────────────
    #  Menu bar
    # ──────────────────────────────────────────────────────────
    def _build_menu(self):
        menubar = tk.Menu(self.root, bg=BG_PANEL, fg=FG_TEXT,
                          activebackground=BG_BUTTON, activeforeground=FG_BUTTON)

        file_menu = tk.Menu(menubar, tearoff=0, bg=BG_PANEL, fg=FG_TEXT)
        file_menu.add_command(label="Save as TXT", command=lambda: self._save_results('txt'))
        file_menu.add_command(label="Save as JSON", command=lambda: self._save_results('json'))
        file_menu.add_command(label="Save as CSV", command=lambda: self._save_results('csv'))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=BG_PANEL, fg=FG_TEXT)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    # ──────────────────────────────────────────────────────────
    #  Header / Title
    # ──────────────────────────────────────────────────────────
    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_DARK, pady=8)
        header.pack(fill=tk.X)

        tk.Label(
            header, text="🔍  Advanced Port Scanner",
            font=FONT_TITLE, bg=BG_DARK, fg=FG_HEADER
        ).pack()

        tk.Label(
            header,
            text="⚠  For educational and authorized testing only",
            font=("Segoe UI", 8), bg=BG_DARK, fg=FG_YELLOW
        ).pack()

    # ──────────────────────────────────────────────────────────
    #  Input panel (Target, Ports, Threads, Timeout, Buttons)
    # ──────────────────────────────────────────────────────────
    def _build_input_panel(self):
        frame = tk.LabelFrame(
            self.root, text=" Scan Configuration ",
            bg=BG_PANEL, fg=FG_HEADER, font=FONT_LABEL,
            padx=12, pady=8
        )
        frame.pack(fill=tk.X, padx=12, pady=(4, 4))

        # Row 0 — Target IP
        tk.Label(frame, text="Target IP / Hostname:", bg=BG_PANEL, fg=FG_TEXT,
                 font=FONT_LABEL).grid(row=0, column=0, sticky='w', padx=4, pady=4)
        self.entry_target = tk.Entry(
            frame, width=30, font=FONT_MONO,
            bg=BG_ENTRY, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief='flat', bd=2
        )
        self.entry_target.grid(row=0, column=1, padx=4, pady=4, sticky='w')
        self.entry_target.insert(0, get_local_ip())

        # Row 0 — Port range
        tk.Label(frame, text="Ports:", bg=BG_PANEL, fg=FG_TEXT,
                 font=FONT_LABEL).grid(row=0, column=2, sticky='w', padx=(16, 4), pady=4)
        self.entry_ports = tk.Entry(
            frame, width=22, font=FONT_MONO,
            bg=BG_ENTRY, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief='flat', bd=2
        )
        self.entry_ports.grid(row=0, column=3, padx=4, pady=4, sticky='w')
        self.entry_ports.insert(0, "1-65535")

        # Row 1 — Threads
        tk.Label(frame, text="Threads:", bg=BG_PANEL, fg=FG_TEXT,
                 font=FONT_LABEL).grid(row=1, column=0, sticky='w', padx=4, pady=4)
        self.entry_threads = tk.Entry(
            frame, width=10, font=FONT_MONO,
            bg=BG_ENTRY, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief='flat', bd=2
        )
        self.entry_threads.grid(row=1, column=1, padx=4, pady=4, sticky='w')
        self.entry_threads.insert(0, "500")

        # Row 1 — Timeout
        tk.Label(frame, text="Timeout (s):", bg=BG_PANEL, fg=FG_TEXT,
                 font=FONT_LABEL).grid(row=1, column=2, sticky='w', padx=(16, 4), pady=4)
        self.entry_timeout = tk.Entry(
            frame, width=10, font=FONT_MONO,
            bg=BG_ENTRY, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief='flat', bd=2
        )
        self.entry_timeout.grid(row=1, column=3, padx=4, pady=4, sticky='w')
        self.entry_timeout.insert(0, "1.0")

        # Row 1 — Service detection checkbox
        self.var_detect_services = tk.BooleanVar(value=True)
        self.chk_services = tk.Checkbutton(
            frame, text="Detect Services & Versions",
            variable=self.var_detect_services,
            bg=BG_PANEL, fg=FG_GREEN, font=FONT_LABEL,
            selectcolor=BG_ENTRY, activebackground=BG_PANEL,
            activeforeground=FG_GREEN
        )
        self.chk_services.grid(row=1, column=4, padx=12, pady=4, sticky='w')

        # Row 2 — Buttons
        btn_frame = tk.Frame(frame, bg=BG_PANEL)
        btn_frame.grid(row=2, column=0, columnspan=5, pady=(8, 4))

        self.btn_scan = tk.Button(
            btn_frame, text="▶  Start Scan", font=FONT_BUTTON,
            bg=BG_BUTTON, fg=FG_BUTTON, activebackground=BG_BUTTON_HV,
            relief='flat', padx=20, pady=6, cursor='hand2',
            command=self._start_scan
        )
        self.btn_scan.pack(side=tk.LEFT, padx=6)

        self.btn_stop = tk.Button(
            btn_frame, text="■  Stop", font=FONT_BUTTON,
            bg=BG_STOP, fg=FG_BUTTON, activebackground="#dc2626",
            relief='flat', padx=20, pady=6, cursor='hand2',
            state=tk.DISABLED, command=self._stop_scan
        )
        self.btn_stop.pack(side=tk.LEFT, padx=6)

        self.btn_clear = tk.Button(
            btn_frame, text="🗑  Clear", font=FONT_BUTTON,
            bg="#475569", fg=FG_BUTTON, activebackground="#334155",
            relief='flat', padx=20, pady=6, cursor='hand2',
            command=self._clear_output
        )
        self.btn_clear.pack(side=tk.LEFT, padx=6)

        self.btn_save = tk.Button(
            btn_frame, text="💾  Save Results", font=FONT_BUTTON,
            bg="#0ea5e9", fg=FG_BUTTON, activebackground="#0284c7",
            relief='flat', padx=20, pady=6, cursor='hand2',
            state=tk.DISABLED, command=lambda: self._save_results('txt')
        )
        self.btn_save.pack(side=tk.LEFT, padx=6)

    # ──────────────────────────────────────────────────────────
    #  Progress panel
    # ──────────────────────────────────────────────────────────
    def _build_progress_panel(self):
        frame = tk.Frame(self.root, bg=BG_DARK, padx=12, pady=2)
        frame.pack(fill=tk.X)

        self.lbl_status = tk.Label(
            frame, text="Ready", font=FONT_LABEL,
            bg=BG_DARK, fg=FG_CYAN, anchor='w'
        )
        self.lbl_status.pack(side=tk.LEFT, padx=4)

        self.progress = ttk.Progressbar(frame, mode='determinate', length=400)
        self.progress.pack(side=tk.RIGHT, padx=4)

        # Style the progress bar
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar",
                        troughcolor=BG_ENTRY,
                        background=FG_GREEN,
                        thickness=18)

    # ──────────────────────────────────────────────────────────
    #  Scrollable output panel (Text widget with colour tags)
    # ──────────────────────────────────────────────────────────
    def _build_output_panel(self):
        frame = tk.LabelFrame(
            self.root, text=" Scan Output ",
            bg=BG_PANEL, fg=FG_HEADER, font=FONT_LABEL,
            padx=4, pady=4
        )
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 4))

        self.txt_output = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, font=FONT_MONO,
            bg="#11111b", fg=FG_TEXT,
            insertbackground=FG_TEXT,
            relief='flat', bd=2, state=tk.DISABLED
        )
        self.txt_output.pack(fill=tk.BOTH, expand=True)

        # Define colour tags
        self.txt_output.tag_configure('header',    foreground=FG_HEADER, font=("Consolas", 10, "bold"))
        self.txt_output.tag_configure('info',      foreground=FG_TEXT)
        self.txt_output.tag_configure('port_open', foreground=FG_GREEN,  font=("Consolas", 10, "bold"))
        self.txt_output.tag_configure('version',   foreground=FG_YELLOW)
        self.txt_output.tag_configure('banner',    foreground=FG_BANNER)
        self.txt_output.tag_configure('divider',   foreground=FG_CYAN)
        self.txt_output.tag_configure('error',     foreground=FG_RED)
        self.txt_output.tag_configure('warning',   foreground=FG_YELLOW)
        self.txt_output.tag_configure('success',   foreground=FG_GREEN)

    # ──────────────────────────────────────────────────────────
    #  Status bar
    # ──────────────────────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_PANEL, height=24)
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_port_count = tk.Label(
            bar, text="Open: 0", font=FONT_MONO_SM,
            bg=BG_PANEL, fg=FG_GREEN, padx=8
        )
        self.lbl_port_count.pack(side=tk.LEFT)

        self.lbl_time = tk.Label(
            bar, text="", font=FONT_MONO_SM,
            bg=BG_PANEL, fg=FG_TEXT, padx=8
        )
        self.lbl_time.pack(side=tk.RIGHT)

    # ══════════════════════════════════════════════════════════
    #  Output helper (thread-safe via root.after)
    # ══════════════════════════════════════════════════════════
    def _append_output(self, text, tag='info'):
        """Append a line to the output Text widget (thread-safe)."""
        def _do():
            self.txt_output.configure(state=tk.NORMAL)
            self.txt_output.insert(tk.END, text + "\n", tag)
            self.txt_output.see(tk.END)
            self.txt_output.configure(state=tk.DISABLED)
        self.root.after(0, _do)

    def _clear_output(self):
        """Clear the output Text widget."""
        self.txt_output.configure(state=tk.NORMAL)
        self.txt_output.delete('1.0', tk.END)
        self.txt_output.configure(state=tk.DISABLED)
        self.lbl_port_count.configure(text="Open: 0")
        self.lbl_time.configure(text="")
        self.progress['value'] = 0
        self.lbl_status.configure(text="Ready", fg=FG_CYAN)
        self.btn_save.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════
    #  Scan logic (runs in a background thread)
    # ══════════════════════════════════════════════════════════
    def _start_scan(self):
        """Validate inputs and launch the scan in a background thread."""
        if self.is_scanning:
            return

        # ── Validate target ──
        target_raw = self.entry_target.get().strip()
        if not target_raw:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return

        target = target_raw
        if not validate_ip(target):
            self._append_output(f"[*] Resolving hostname '{target}'...", 'warning')
            resolved = resolve_hostname(target)
            if resolved:
                target = resolved
                self._append_output(f"[+] Resolved to {target}", 'success')
            else:
                messagebox.showerror("Error", f"Cannot resolve hostname: {target_raw}")
                return

        # ── Validate ports ──
        port_str = self.entry_ports.get().strip()
        if not port_str:
            port_str = "1-65535"
        ports = parse_ports(port_str)
        if not ports:
            messagebox.showerror("Error", "No valid ports specified.")
            return

        # ── Validate threads ──
        try:
            threads = int(self.entry_threads.get().strip())
            if threads < 1 or threads > 5000:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Threads must be a number between 1 and 5000.")
            return

        # ── Validate timeout ──
        try:
            timeout = float(self.entry_timeout.get().strip())
            if timeout <= 0 or timeout > 30:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Timeout must be a number between 0.1 and 30.")
            return

        detect_services = self.var_detect_services.get()

        # ── Prepare UI ──
        self._clear_output()
        self.is_scanning = True
        self.scan_results = None
        self.services_results = None
        self.btn_scan.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_save.configure(state=tk.DISABLED)
        self.progress['maximum'] = len(ports)
        self.progress['value'] = 0

        self._append_output("═" * 62, 'divider')
        self._append_output(f"  Scanning {target}  ({len(ports)} ports, {threads} threads)", 'header')
        self._append_output(f"  Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'info')
        self._append_output("═" * 62, 'divider')
        self._append_output("", 'info')

        # ── Launch background thread ──
        thread = threading.Thread(
            target=self._scan_worker,
            args=(target, ports, threads, timeout, detect_services),
            daemon=True
        )
        thread.start()

    def _scan_worker(self, target, ports, threads, timeout, detect_services):
        """Background worker that performs the actual scan."""
        open_port_count = 0

        try:
            # ── Phase 1: Port Scanning ──
            self._update_status("Phase 1: Port Scanning...")
            scanner = PortScanner(target, ports, timeout=timeout, threads=threads)
            self.scanner = scanner

            # Progress callback
            def on_progress(scanned, total):
                self.root.after(0, lambda: self._update_progress(scanned, total))

            # Port found callback
            def on_port_found(port):
                nonlocal open_port_count
                open_port_count += 1
                self._append_output(f"  [+] Port {port} is OPEN", 'port_open')
                self.root.after(0, lambda: self.lbl_port_count.configure(
                    text=f"Open: {open_port_count}"
                ))

            scanner.set_on_progress(on_progress)
            scanner.set_on_port_found(on_port_found)

            scan_results = scanner.scan()
            self.scan_results = scan_results

            if scanner.is_stopped:
                self._append_output("\n  [!] Scan stopped by user.", 'warning')
                self._scan_finished()
                return

            # ── Phase 2: Service Detection ──
            services_results = None
            if detect_services and scan_results['open_ports']:
                self._update_status("Phase 2: Detecting services & versions...")
                self._append_output("", 'info')
                self._append_output("═" * 62, 'divider')
                self._append_output("  SERVICE & VERSION DETECTION", 'header')
                self._append_output("═" * 62, 'divider')
                self._append_output("", 'info')
                self._append_output("  PORT       SERVICE              VERSION", 'header')
                self._append_output("  " + "─" * 56, 'divider')

                detector = ServiceDetector()

                def svc_callback(info):
                    version_str = info.get('version', 'Version Unknown')
                    line = f"  {str(info['port']):<10} {info['service']:<20} {version_str}"
                    self._append_output(line, 'port_open')
                    if info.get('banner'):
                        banner_preview = info['banner'][:70]
                        if len(info['banner']) > 70:
                            banner_preview += '...'
                        self._append_output(f"             └─ {banner_preview}", 'banner')

                services_results = detector.detect_services(
                    target,
                    scan_results['open_ports'],
                    timeout=3,
                    threads=min(10, len(scan_results['open_ports'])),
                    callback=svc_callback
                )
                self.services_results = services_results

            # ── Final summary ──
            self._append_output("", 'info')
            self._append_output("═" * 62, 'divider')
            self._append_output("  SCAN COMPLETE", 'header')
            self._append_output("═" * 62, 'divider')
            self._append_output(f"  Target           : {scan_results['target']}", 'info')
            self._append_output(f"  Ports Scanned    : {scan_results['total_ports_scanned']}", 'info')
            self._append_output(f"  Open Ports       : {len(scan_results['open_ports'])}", 'success')
            self._append_output(f"  Duration         : {scan_results['duration']:.2f} seconds", 'info')
            self._append_output("═" * 62, 'divider')

            if scan_results['open_ports']:
                self.root.after(0, lambda: self.btn_save.configure(state=tk.NORMAL))

        except Exception as e:
            self._append_output(f"\n  [ERROR] {str(e)}", 'error')

        finally:
            self._scan_finished()

    # ──────────────────────────────────────────────────────────
    #  UI update helpers (called from background thread via after)
    # ──────────────────────────────────────────────────────────
    def _update_status(self, text):
        self.root.after(0, lambda: self.lbl_status.configure(text=text, fg=FG_CYAN))

    def _update_progress(self, scanned, total):
        self.progress['value'] = scanned
        pct = (scanned / total * 100) if total else 0
        self.lbl_status.configure(
            text=f"Scanning... {scanned}/{total} ports ({pct:.1f}%)",
            fg=FG_CYAN
        )

    def _scan_finished(self):
        """Reset UI state after scan completes or is stopped."""
        def _do():
            self.is_scanning = False
            self.scanner = None
            self.btn_scan.configure(state=tk.NORMAL)
            self.btn_stop.configure(state=tk.DISABLED)
            self.lbl_status.configure(text="Scan finished", fg=FG_GREEN)
            self.lbl_time.configure(
                text=datetime.now().strftime('%H:%M:%S')
            )
            self.progress['value'] = self.progress['maximum']
        self.root.after(0, _do)

    def _stop_scan(self):
        """Stop the running scan."""
        if self.scanner:
            self.scanner.stop()
            self._update_status("Stopping scan...")
            self.btn_stop.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════
    #  Save results
    # ══════════════════════════════════════════════════════════
    def _save_results(self, fmt='txt'):
        """Save scan results to a file. Supports txt, json, csv."""
        if not self.scan_results:
            messagebox.showinfo("Info", "No scan results to save. Run a scan first.")
            return

        ext_map = {'txt': '.txt', 'json': '.json', 'csv': '.csv'}
        ext = ext_map.get(fmt, '.txt')

        filetypes = [
            ("Text files", "*.txt"),
            ("JSON files", "*.json"),
            ("CSV files", "*.csv"),
            ("All files", "*.*"),
        ]

        default_name = f"scan_{self.scan_results['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        filepath = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=default_name,
            initialdir=os.path.join(os.path.dirname(__file__), 'results')
        )

        if not filepath:
            return

        try:
            if filepath.endswith('.json'):
                import json as _json
                data = {
                    'scan_info': self.scan_results,
                    'services': self.services_results or []
                }
                with open(filepath, 'w') as f:
                    _json.dump(data, f, indent=4)
            elif filepath.endswith('.csv'):
                import csv as _csv
                with open(filepath, 'w', newline='') as f:
                    if self.services_results:
                        writer = _csv.DictWriter(
                            f,
                            fieldnames=['port', 'service', 'description', 'version', 'banner']
                        )
                        writer.writeheader()
                        for svc in self.services_results:
                            writer.writerow({
                                'port': svc['port'],
                                'service': svc['service'],
                                'description': svc.get('description', ''),
                                'version': svc.get('version', ''),
                                'banner': svc.get('banner', '') or '',
                            })
                    else:
                        writer = _csv.writer(f)
                        writer.writerow(['Port'])
                        for p in self.scan_results['open_ports']:
                            writer.writerow([p])
            else:
                report = format_results(self.scan_results, self.services_results)
                with open(filepath, 'w') as f:
                    f.write(report)

            self._append_output(f"\n  [+] Results saved to: {filepath}", 'success')
            messagebox.showinfo("Saved", f"Results saved to:\n{filepath}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results:\n{e}")

    # ──────────────────────────────────────────────────────────
    #  About dialog
    # ──────────────────────────────────────────────────────────
    def _show_about(self):
        messagebox.showinfo(
            "About",
            "Advanced Port Scanner v2.0\n\n"
            "Features:\n"
            "• TCP port scanning (1-65535)\n"
            "• Service & version detection\n"
            "• Multithreaded (ThreadPoolExecutor)\n"
            "• Banner grabbing\n"
            "• Save results (TXT/JSON/CSV)\n\n"
            "⚠ For educational & authorized use only.\n"
            "Unauthorized scanning is ILLEGAL."
        )

    def _on_close(self):
        """Handle window close — stop any running scan first."""
        if self.is_scanning and self.scanner:
            self.scanner.stop()
        self.root.destroy()


# ══════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════
def main():
    root = tk.Tk()

    # Set app icon (if available)
    try:
        root.iconbitmap(default='')
    except Exception:
        pass

    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
