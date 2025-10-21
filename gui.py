# gui.py
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from tkinter import StringVar

from core.analyzer import analyze, result_to_json
from core.utils.history_manager import init_db, save_entry, load_history, clear_history
from core.utils.pdf_exporter import export_report_pdf

ASSETS_DIR = os.path.join(os.getcwd(), "assets")
LOGO = os.path.join(ASSETS_DIR, "logo_small.png") if os.path.exists(ASSETS_DIR) else None

# neon palette
BG = "#0b1220"
CARD = "#071829"
ACCENT = "#00ffd5"
SAFE = "#19ff91"
WARNING = "#ffd24a"
DANGER = "#ff6b6b"
TEXT = "#e6f7ff"

class SentinelURLApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SentinelURL v4.0 — Neon Cyber")
        self.geometry("1100x760")
        self.minsize(1000, 700)
        self.configure(bg=BG)

        init_db()

        self.last_result_text = ""
        self.current_result = None

        self.setup_style()
        self.create_header()
        self.create_main()
        self.create_footer()
        self.load_history()

    def setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=CARD)
        style.configure("Accent.TButton", background=ACCENT, foreground="#002323")
        style.map("Accent.TButton", background=[("active", "#00e6c0")])

    def create_header(self):
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=18, pady=(12, 6))
        ttk.Label(header, text="🛡 SentinelURL — Neon Threat Analyzer", font=("Segoe UI", 18, "bold"), foreground=ACCENT).pack(side="left")
        self.api_status = ttk.Label(header, text="Ready", font=("Segoe UI", 10, "italic"), foreground=ACCENT)
        self.api_status.pack(side="right")

    def create_main(self):
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=18, pady=6)

        left = ttk.Frame(container)
        left.pack(side="left", fill="both", expand=True)

        # input card
        card = ttk.Frame(left, style="Card.TFrame", padding=10)
        card.pack(fill="x", padx=6, pady=6)
        ttk.Label(card, text="Enter URL (http optional):").pack(anchor="w")
        self.url_var = StringVar()
        self.url_entry = ttk.Entry(card, textvariable=self.url_var, width=80)
        self.url_entry.pack(side="left", padx=(0,10))
        self.scan_btn = ttk.Button(card, text="Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left")

        # progress + gauge
        bar_frame = ttk.Frame(left)
        bar_frame.pack(fill="x", padx=6, pady=8)
        self.progress = ttk.Progressbar(bar_frame, mode="indeterminate", length=420)
        self.progress.pack(side="left", padx=(0,12))
        self.gauge = tk.Canvas(bar_frame, width=140, height=140, bg=CARD, highlightthickness=0)
        self.gauge.pack(side="left")
        self.draw_gauge(0)

        # result card
        res_card = ttk.Frame(left, style="Card.TFrame", padding=10)
        res_card.pack(fill="both", expand=True, padx=6, pady=(6,0))
        ttk.Label(res_card, text="Latest Result", foreground=ACCENT).pack(anchor="w")
        self.result_text = tk.Text(res_card, height=18, wrap="word", bg="#04121a", fg=TEXT, insertbackground=TEXT)
        self.result_text.pack(fill="both", expand=True, pady=6)
        btns = ttk.Frame(res_card)
        btns.pack(anchor="e")
        ttk.Button(btns, text="Copy Result", command=self.copy_result).pack(side="left", padx=6)
        ttk.Button(btns, text="Export PDF (current)", command=self.export_pdf_current).pack(side="left", padx=6)

        # right side
        right = ttk.Frame(container, width=420)
        right.pack(side="left", fill="both", padx=(12,0))
        table_card = ttk.Frame(right, style="Card.TFrame", padding=10)
        table_card.pack(fill="both", expand=True, pady=6)
        ttk.Label(table_card, text="Recent Scans", foreground=ACCENT).pack(anchor="w")
        cols = ("time","url","verdict","score")
        self.tree = ttk.Treeview(table_card, columns=cols, show="headings", height=16)
        self.tree.heading("time", text="Time")
        self.tree.heading("url", text="URL")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("score", text="Score")
        self.tree.column("time", width=140)
        self.tree.column("url", width=260)
        self.tree.column("verdict", width=100, anchor="center")
        self.tree.column("score", width=60, anchor="center")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_history_double)
        hbtns = ttk.Frame(right)
        hbtns.pack(fill="x", pady=(8,0))
        ttk.Button(hbtns, text="Refresh", command=self.load_history).pack(side="left", padx=6)
        ttk.Button(hbtns, text="Clear History", command=self.confirm_clear_history).pack(side="left", padx=6)

    def create_footer(self):
        footer = ttk.Frame(self)
        footer.pack(fill="x", padx=18, pady=(6,18))
        ttk.Label(footer, text="SentinelURL v4.0 — Neon Cyber UI", font=("Segoe UI", 9)).pack(side="left")
        ttk.Label(footer, text="©").pack(side="right")

    # gauge drawing
    def draw_gauge(self, score: int):
        self.gauge.delete("all")
        w,h = 140,140
        cx,cy = w/2, h/2+10
        r = 56
        start = 180
        extent = - (score / 10.0) * 180
        # background track
        self.gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=180, style="arc", outline="#0b3a3a", width=12)
        color = SAFE if score<=3 else WARNING if score<=6 else DANGER
        self.gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=start, extent=extent, style="arc", outline=color, width=12)
        self.gauge.create_text(cx, cy-10, text=f"{score}/10", fill=TEXT, font=("Segoe UI", 12, "bold"))
        self.gauge.create_text(cx, cy+16, text="Risk", fill="#a8cbd1", font=("Segoe UI", 8))

    # start scanning
    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input required", "Please enter a URL.")
            return
        if not url.lower().startswith(("http://","https://")):
            url = "https://" + url
            self.url_var.set(url)
        self.result_text.delete("1.0", tk.END)
        self.progress.start(12)
        self.scan_btn.state(["disabled"])
        self.result_text.insert("end", f"🔍 Scanning {url}...\n\n")
        thread = threading.Thread(target=self._scan_thread, args=(url,), daemon=True)
        thread.start()

    def _scan_thread(self, url):
        try:
            res = analyze(url, run_apis=True, include_urlscan=True, include_abuseipdb=True)
            text = result_to_json(res, indent=2)
            self.current_result = res
            self.last_result_text = text
            save_entry(res["timestamp"], res["normalized"], res["verdict"], res["risk_score"], text)
            self.after(10, lambda: self.on_scan_complete(res, text))
        except Exception as e:
            self.after(10, lambda: self.on_scan_error(str(e)))

    def on_scan_complete(self, res, text):
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("end", text)
        score = int(res.get("risk_score",0))
        self.draw_gauge(score)
        self.api_status.config(text=f"Completed — Verdict: {res.get('verdict')} | Score: {score}")
        self.load_history()

    def on_scan_error(self, err):
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        self.result_text.insert("end", f"\n❌ Error: {err}")
        self.api_status.config(text="Error during scan")

    def copy_result(self):
        if not self.last_result_text:
            messagebox.showinfo("No Data", "Run a scan first")
            return
        self.clipboard_clear()
        self.clipboard_append(self.last_result_text)
        messagebox.showinfo("Copied", "Analysis JSON copied to clipboard")

    def export_pdf_current(self):
        if not self.last_result_text:
            messagebox.showinfo("No Data", "Run a scan first")
            return
        r = self.current_result or {}
        summary = {
            "verdict": r.get("verdict"),
            "score": r.get("risk_score"),
            "positives": r.get("intelligence",{}).get("positives"),
            "total_engines": r.get("intelligence",{}).get("total"),
            "reputation": r.get("intelligence",{}).get("reputation"),
            "categories": ", ".join(r.get("intelligence",{}).get("categories",[])) if r.get("intelligence") else "N/A"
        }
        title = f"SentinelURL Report — {r.get('normalized','')}"
        path = export_report_pdf(title, summary, self.last_result_text, logo_path=LOGO)
        messagebox.showinfo("Exported", f"PDF saved to:\n{path}")

    # history
    def load_history(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        rows = load_history(limit=200)
        for ts, url, verdict, score, data in rows:
            tag = verdict.upper() if verdict else ""
            self.tree.insert("", "end", values=(ts, url, verdict, score), tags=(tag,))

    def on_history_double(self, event):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        ts,url,verdict,score = item["values"]
        # fetch detail by matching
        rows = load_history(limit=200)
        detail = None
        for a_ts,a_url,a_verdict,a_score,a_data in rows:
            if str(a_ts) == str(ts) and str(a_url)==str(url):
                detail = a_data
                break
        if detail:
            top = tk.Toplevel(self)
            top.title(f"Details — {url}")
            txt = tk.Text(top, wrap="word", height=40, width=120)
            txt.pack(fill="both", expand=True)
            txt.insert("end", detail)
            txt.config(state="disabled")

    def confirm_clear_history(self):
        if messagebox.askyesno("Clear history", "Permanently delete stored history?"):
            clear_history()
            self.load_history()
            messagebox.showinfo("Cleared", "History cleared.")


if __name__ == "__main__":
    app = SentinelURLApp()
    app.mainloop()
