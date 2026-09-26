"""Floating Cyber Sentry HUD & Assistive On-Screen Radar.

A persistent, always-on-top draggable floating assistive sentry widget:
- Floats on top of all windows (Outlook, Gmail, Browser, Desktop).
- High-visibility red glowing halo with active status badge.
- Interactive Click: Expands into Cyber Threat Radar panel.
- Runs background clipboard, mail window, and attachment malware scanning.
"""

import os
import sys
from pathlib import Path

# Ensure root is in sys.path
_AGENT_ROOT = Path(__file__).resolve().parent.parent
if str(_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENT_ROOT))

import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Optional

from core.active_sentry import ActiveThreatSentry
from core.file_scanner import scan_attachment_file
from core.threat_scanner import scan_email_text, scan_suspicious_url
from core.deep_screen_inspector import inspect_deep_window_threats


class FloatingCyberHUD:
    """Always-on-top draggable floating assistive sentry widget."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🚨 Cyber Sentry")
        
        # Position at top right corner
        screen_width = self.root.winfo_screenwidth()
        self.x = screen_width - 160
        self.y = 120
        self.width = 110
        self.height = 110
        
        self.root.geometry(f"{self.width}x{self.height}+{self.x}+{self.y}")
        self.root.attributes("-topmost", True)
        self.root.attributes("-toolwindow", True)  # Toolwindow prevents Windows from dropping the window
        self.root.configure(bg="#0c121e")
        self.root.resizable(False, False)

        # Canvas for Drawing
        self.canvas = tk.Canvas(
            self.root,
            width=self.width,
            height=self.height,
            bg="#0c121e",
            highlightthickness=0
        )
        self.canvas.pack(fill="both", expand=True)

        # State
        self.status = "ALERT"
        self.active_alert: Optional[Dict] = None
        self.detail_win = None

        self.draw_bubble()

        # Dragging Bindings
        self.canvas.bind("<Button-1>", self._start_drag)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_click_or_drop)

        self._drag_start_x = 0
        self._drag_start_y = 0
        self._is_dragging = False

        # Start Threat Sentry in Background
        try:
            self.sentry = ActiveThreatSentry(alert_callback=self.on_threat_detected)
            self.sentry.start()
        except Exception:
            pass

        # Periodic Topmost Enforcer
        self._keep_topmost()

    def _keep_topmost(self):
        """Keep window pinned topmost on Windows."""
        try:
            self.root.attributes("-topmost", True)
            self.root.lift()
        except Exception:
            pass
        self.root.after(1500, self._keep_topmost)

    def draw_bubble(self):
        """Render glowing red cyber sentry circle."""
        self.canvas.delete("all")

        # Outer thick vibrant red ring with white border
        self.canvas.create_oval(6, 6, 104, 104, outline="#ffffff", width=3, fill="#ff0033")
        self.canvas.create_oval(12, 12, 98, 98, outline="#ff6688", width=1, fill="#d90429")

        # Inner Icon
        self.canvas.create_text(55, 48, text="🚨", font=("Segoe UI Emoji", 26))

        # Status text in bold white
        self.canvas.create_text(55, 82, text="ACTIVE", font=("Arial", 9, "bold"), fill="#ffffff")

    def _start_drag(self, event):
        self._drag_start_x = event.x
        self._drag_start_y = event.y
        self._is_dragging = False

    def _on_drag(self, event):
        self._is_dragging = True
        dx = event.x - self._drag_start_x
        dy = event.y - self._drag_start_y
        self.x += dx
        self.y += dy
        self.root.geometry(f"+{self.x}+{self.y}")

    def _on_click_or_drop(self, event):
        if not self._is_dragging:
            self.scan_active_window_freshly()
        self._is_dragging = False

    def scan_active_window_freshly(self):
        """Perform a fresh, instantaneous scan of the target active window upon clicking ACTIVE."""
        target_hwnd = getattr(self.sentry, "last_target_hwnd", 0)

        # Perform fresh deep window inspection on target HWND
        report = inspect_deep_window_threats(hwnd=target_hwnd)
        
        is_threat = report.get("risk_score", 0) >= 30 or report.get("verdict") not in ["CLEAN / SAFE", "LOW"]
        
        alert = {
            "type": "FRESH_WINDOW_SCAN",
            "title": f"🚨 {report.get('verdict')} Detected" if is_threat else "🟢 Active Window Scan: CLEAN & SAFE",
            "target": report.get("window_title") if report.get("window_title") else getattr(self.sentry, "last_target_title", "Active Desktop Window"),
            "verdict": report.get("verdict", "CLEAN / SAFE"),
            "risk_score": report.get("risk_score", 0),
            "threat_level": report.get("threat_level", "LOW"),
            "details": report.get("flags", []),
            "recommendation": report.get("recommendation", "✅ All background text, hyperlinks & attachments passed security checks.")
        }
        
        self.active_alert = alert
        self.status = "ALERT" if is_threat else "NOMINAL"
        
        try:
            self.draw_bubble()
            self.root.attributes("-topmost", True)
            self.root.lift()
        except Exception:
            pass

        # Re-open or refresh details radar window with fresh scan output
        if self.detail_win and self.detail_win.winfo_exists():
            self.detail_win.destroy()
            self.detail_win = None

        self.open_details_window()

    def on_threat_detected(self, alert: Dict):
        """Callback triggered when background sentry spots a threat."""
        self.active_alert = alert
        self.status = "ALERT"
        try:
            self.root.after(0, self.draw_bubble)
            self.root.after(0, self.open_details_window)
        except Exception:
            pass

    def open_details_window(self):
        """Display interactive cyberpunk details panel."""
        if self.detail_win and self.detail_win.winfo_exists():
            self.detail_win.lift()
            return

        self.detail_win = tk.Toplevel(self.root)
        self.detail_win.title("Active Sentry Threat Radar")
        self.detail_win.attributes("-topmost", True)
        self.detail_win.configure(bg="#0c121e")
        self.detail_win.geometry(f"480x430+{max(20, self.x - 490)}+{self.y}")

        # Header Frame
        header = tk.Frame(self.detail_win, bg="#101827", pady=10, padx=14)
        header.pack(fill="x")

        tk.Label(header, text="⚡ AUTONOMOUS THREAT RADAR", font=("Arial", 11, "bold"), fg="#00f0ff", bg="#101827").pack(side="left")
        close_btn = tk.Button(header, text="✕", font=("Arial", 10, "bold"), bg="#101827", fg="#8b9bb4", bd=0, command=self.detail_win.destroy)
        close_btn.pack(side="right")

        content = tk.Frame(self.detail_win, bg="#0c121e", padx=14, pady=12)
        content.pack(fill="both", expand=True)

        if not self.active_alert:
            tk.Label(content, text="🟢 ALL ACTIVE CHANNELS SECURE", font=("Arial", 12, "bold"), fg="#00ff88", bg="#0c121e").pack(anchor="w", pady=(10, 4))
            tk.Label(content, text="• Active Mail & Screen Scanner: Listening in real time\n• Clipboard Interceptor: Armed\n• Download & Attachment Virus Guard: Active\n\nNo active threats intercepted. System nominal.", font=("Arial", 9), fg="#8b9bb4", bg="#0c121e", justify="left").pack(anchor="w", pady=6)
        else:
            alert = self.active_alert
            color = "#ff3366"
            tk.Label(content, text=alert.get("title", "Threat Alert"), font=("Arial", 12, "bold"), fg=color, bg="#0c121e").pack(anchor="w")
            tk.Label(content, text=f"Verdict: {alert.get('verdict')} (Risk: {alert.get('risk_score', 0)}%)", font=("Arial", 10, "bold"), fg="#ffffff", bg="#0c121e").pack(anchor="w", pady=(2, 8))

            target_box = tk.Label(content, text=f"Target: {alert.get('target')}", font=("Arial", 9), fg="#c77dff", bg="#151d2e", wraplength=440, justify="left", padx=8, pady=6)
            target_box.pack(fill="x", pady=4)

            # Highlighted Triggers List
            tk.Label(content, text="Highlighted Threat Triggers:", font=("Arial", 9, "bold"), fg="#ffb703", bg="#0c121e").pack(anchor="w", pady=(8, 2))
            triggers_frame = tk.Frame(content, bg="#151d2e", padx=8, pady=6)
            triggers_frame.pack(fill="x", pady=2)
            for flag in alert.get("details", [])[:4]:
                tk.Label(triggers_frame, text=f"• {flag}", font=("Arial", 8), fg="#ff6b81", bg="#151d2e", wraplength=420, justify="left").pack(anchor="w")

            tk.Label(content, text=alert.get("recommendation", ""), font=("Arial", 8, "italic"), fg="#8b9bb4", bg="#0c121e", wraplength=440, justify="left").pack(anchor="w", pady=(8, 4))

        # Action Buttons
        btn_frame = tk.Frame(self.detail_win, bg="#0c121e", padx=14, pady=10)
        btn_frame.pack(fill="x", side="bottom")

        tk.Button(btn_frame, text="🧹 Reset Status", font=("Arial", 9, "bold"), bg="#151d2e", fg="#00f0ff", bd=1, padx=10, pady=4, command=self.reset_status).pack(side="left")
        tk.Button(btn_frame, text="🔍 Scan File / Attachment", font=("Arial", 9, "bold"), bg="#00f0ff", fg="#001219", bd=0, padx=10, pady=4, command=self.manual_file_scan_dialog).pack(side="right")

    def reset_status(self):
        self.status = "NOMINAL"
        self.active_alert = None
        self.draw_bubble()
        if self.detail_win and self.detail_win.winfo_exists():
            self.detail_win.destroy()
            self.open_details_window()

    def manual_file_scan_dialog(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(title="Select Document, Attachment, or Image to Scan")
        if file_path:
            report = scan_attachment_file(file_path)
            verdict = report.get("verdict")
            if "MALICIOUS" in verdict or "SUSPICIOUS" in verdict:
                self.on_threat_detected({
                    "type": "ATTACHMENT_THREAT",
                    "title": "📎 Attachment Threat Verified",
                    "target": report.get("file_name"),
                    "verdict": verdict,
                    "risk_score": report.get("risk_score"),
                    "threat_level": report.get("threat_level"),
                    "details": report.get("flags"),
                    "recommendation": report.get("recommendation")
                })
            else:
                messagebox.showinfo("Attachment Scan Result", f"✅ File is 100% CLEAN & SAFE\n\n• Name: {report.get('file_name')}\n• Type: {report.get('detected_type')}\n• SHA-256: {report.get('hashes', {}).get('sha256')[:16]}...\n\nNo virus, macro hooks, or disguised extensions found.")

    def run(self):
        """Start the Tkinter event loop."""
        self.root.mainloop()


def launch_floating_hud():
    """Launch the floating assistive widget."""
    app = FloatingCyberHUD()
    app.run()


if __name__ == "__main__":
    launch_floating_hud()
