"""Active Screen & In-Flight Mail Sentry Engine.

Autonomous background worker that:
1. Monitors active foreground window titles (Gmail, Outlook, Windows Mail, Thunderbird, Webmail tabs)
2. Monitors Windows clipboard for suspicious copied text/links/attachments
3. Inspects newly downloaded or opened files in Downloads/Temp folders
4. Feeds real-time alerts into the Floating Assistive HUD
"""

import ctypes
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from core.file_scanner import scan_attachment_file
from core.threat_scanner import scan_email_text, scan_suspicious_url
from core.deep_screen_inspector import inspect_deep_window_threats, get_active_window_hwnd


def get_foreground_window_title() -> str:
    """Retrieve title of currently focused / active foreground window on Windows."""
    if sys.platform != "win32":
        return ""
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd)
        buff = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buff, length + 1)
        return buff.value
    except Exception:
        return ""


def get_windows_clipboard_text() -> str:
    """Safely get plain text from Windows clipboard with 64-bit pointers."""
    if sys.platform != "win32":
        return ""
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_bool
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = ctypes.c_bool
        user32.GetClipboardData.argtypes = [ctypes.c_uint]
        user32.GetClipboardData.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = ctypes.c_bool

        if not user32.OpenClipboard(None):
            return ""
        
        CF_UNICODETEXT = 13
        h_clip = user32.GetClipboardData(CF_UNICODETEXT)
        text = ""
        if h_clip:
            ptr = kernel32.GlobalLock(h_clip)
            if ptr:
                text = ctypes.wstring_at(ptr)
                kernel32.GlobalUnlock(h_clip)
        user32.CloseClipboard()
        return text or ""
    except Exception:
        return ""


class ActiveThreatSentry:
    """Autonomous Background Sentry daemon monitoring mail windows, clipboard, and downloads."""

    def __init__(self, alert_callback: Optional[Callable[[Dict], None]] = None):
        self.alert_callback = alert_callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_clipboard = ""
        self._last_window_title = ""
        self.last_target_hwnd = 0
        self.last_target_title = ""
        self._scanned_hashes = set()
        self.recent_alerts: List[Dict] = []

    def start(self):
        """Start the autonomous sentry background polling loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the autonomous sentry daemon."""
        self._running = False

    def _monitor_loop(self):
        """Main polling cycle running every 0.8 seconds."""
        downloads_dir = Path.home() / "Downloads"

        while self._running:
            try:
                # 1. Zero-Copy Active Window & Opened Page Inspection
                hwnd = get_active_window_hwnd()
                current_title = get_foreground_window_title()
                
                # Exclude HUD windows from target tracking
                if current_title and "sentry" not in current_title.lower() and "radar" not in current_title.lower():
                    self.last_target_hwnd = hwnd
                    self.last_target_title = current_title

                if current_title and current_title != self._last_window_title:
                    self._last_window_title = current_title
                    self._inspect_active_window(current_title)

                # 2. Check Clipboard for Copied Links or Suspicious Emails
                clip_text = get_windows_clipboard_text().strip()
                if clip_text and clip_text != self._last_clipboard:
                    self._last_clipboard = clip_text
                    self._inspect_clipboard_content(clip_text)

                # 3. Check Recent Downloads for Weaponized Attachments
                if downloads_dir.exists():
                    self._inspect_recent_downloads(downloads_dir)

            except Exception:
                pass

            time.sleep(1.0)

    def _inspect_active_window(self, title: str):
        """Inspect background text, embedded links, and attached items in opened window automatically."""
        if not title:
            return

        # Deep analysis of active window UI controls, background text & embedded URLs
        report = inspect_deep_window_threats()
        
        if report.get("verdict") not in ["CLEAN / SAFE", "LOW"] or report.get("risk_score", 0) >= 30:
            alert = {
                "type": "DEEP_WINDOW_THREAT",
                "title": f"🚨 {report.get('verdict')} Detected in Active Window",
                "target": report.get("window_title", title),
                "verdict": report.get("verdict"),
                "risk_score": report.get("risk_score"),
                "threat_level": report.get("threat_level"),
                "details": report.get("flags", []),
                "recommendation": report.get("recommendation")
            }
            self._dispatch_alert(alert)

    def _inspect_clipboard_content(self, text: str):
        """Analyze newly copied text or URL."""
        # Is it a URL?
        if text.startswith(("http://", "https://", "www.")) or re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$", text):
            url_report = scan_suspicious_url(text)
            if url_report.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]:
                alert = {
                    "type": "LINK_THREAT",
                    "title": "🚨 Malicious Phishing Link Intercepted",
                    "target": text,
                    "verdict": url_report.get("verdict"),
                    "risk_score": url_report.get("risk_score"),
                    "threat_level": url_report.get("threat_level"),
                    "details": url_report.get("flags", []),
                    "recommendation": url_report.get("recommendation")
                }
                self._dispatch_alert(alert)

        # Is it an email body / text paragraph with urgency or credentials?
        elif len(text) > 30:
            email_report = scan_email_text(text)
            if "MALICIOUS" in email_report.get("verdict", "") or "SUSPICIOUS" in email_report.get("verdict", ""):
                alert = {
                    "type": "EMAIL_THREAT",
                    "title": "📧 Active Phishing / Social Engineering Detected",
                    "target": text[:80] + "...",
                    "verdict": email_report.get("verdict"),
                    "risk_score": email_report.get("risk_score"),
                    "threat_level": email_report.get("threat_level"),
                    "details": email_report.get("flags", []),
                    "recommendation": email_report.get("recommendation")
                }
                self._dispatch_alert(alert)

    def _inspect_recent_downloads(self, downloads_dir: Path):
        """Check the newest file in Downloads folder modified within the last 60 seconds."""
        try:
            files = list(downloads_dir.glob("*"))
            if not files:
                return
            newest_file = max(files, key=lambda f: f.stat().st_mtime if f.is_file() else 0)
            if not newest_file.is_file():
                return
            
            # If modified within last 45 seconds and not already scanned
            age = time.time() - newest_file.stat().st_mtime
            if age < 45 and str(newest_file) not in self._scanned_hashes:
                self._scanned_hashes.add(str(newest_file))
                file_report = scan_attachment_file(str(newest_file))
                if file_report.get("verdict") in ["MALICIOUS ATTACHMENT", "SUSPICIOUS ATTACHMENT"]:
                    alert = {
                        "type": "ATTACHMENT_THREAT",
                        "title": "📎 Dangerous Attachment / Payload Downloaded",
                        "target": newest_file.name,
                        "verdict": file_report.get("verdict"),
                        "risk_score": file_report.get("risk_score"),
                        "threat_level": file_report.get("threat_level"),
                        "details": file_report.get("flags", []),
                        "recommendation": file_report.get("recommendation")
                    }
                    self._dispatch_alert(alert)
        except Exception:
            pass

    def _dispatch_alert(self, alert: Dict):
        """Send threat alert to callback and store in history."""
        self.recent_alerts.insert(0, alert)
        if len(self.recent_alerts) > 20:
            self.recent_alerts.pop()
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception:
                pass
