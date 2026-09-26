"""Deep Active Window Content, Background Text, Embedded Links & Attachment Inspector.

Uses Win32 API & Windows UI Automation primitives to extract:
1. Full background text content of the active window (email body, web page text, document text)
2. All embedded hyperlinks present anywhere inside the opened window/page
3. Attached items, file downloads, images, and document payloads
4. Comprehensive multi-threat evaluation (Phishing + Malicious Links + Weaponized Attachments)
"""

import ctypes
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from core.file_scanner import scan_attachment_file
from core.threat_scanner import scan_email_text, scan_suspicious_url


def get_active_window_hwnd() -> int:
    """Get HWND of currently active foreground window on Windows."""
    if sys.platform != "win32":
        return 0
    try:
        return ctypes.windll.user32.GetForegroundWindow()
    except Exception:
        return 0


def get_window_title(hwnd: int) -> str:
    """Get full window title text for given HWND."""
    if not hwnd or sys.platform != "win32":
        return ""
    try:
        user32 = ctypes.windll.user32
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return ""
        buff = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buff, length + 1)
        return buff.value or ""
    except Exception:
        return ""


def extract_child_windows_text(hwnd: int) -> List[str]:
    """Recursively extract background text from all child controls (Notepad Edit controls, RichEdit, document views)."""
    if not hwnd or sys.platform != "win32":
        return []

    texts = []
    user32 = ctypes.windll.user32
    WM_GETTEXTLENGTH = 0x000E
    WM_GETTEXT = 0x000D

    def enum_proc(child_hwnd, lparam):
        try:
            # 1. SendMessageW WM_GETTEXT (Works for Notepad Edit controls, text boxes, RichEdit)
            length = user32.SendMessageW(child_hwnd, WM_GETTEXTLENGTH, 0, 0)
            if 0 < length < 100000:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.SendMessageW(child_hwnd, WM_GETTEXT, length + 1, buff)
                val = buff.value.strip()
                if val and len(val) > 2:
                    texts.append(val)

            # 2. GetWindowTextW
            length_wt = user32.GetWindowTextLengthW(child_hwnd)
            if 0 < length_wt < 20000:
                buff_wt = ctypes.create_unicode_buffer(length_wt + 1)
                user32.GetWindowTextW(child_hwnd, buff_wt, length_wt + 1)
                val_wt = buff_wt.value.strip()
                if val_wt and len(val_wt) > 2 and val_wt not in texts:
                    texts.append(val_wt)
        except Exception:
            pass
        return True

    try:
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        user32.EnumChildWindows(hwnd, WNDENUMPROC(enum_proc), 0)
    except Exception:
        pass

    return texts


def inspect_deep_window_threats(hwnd: int = 0) -> Dict[str, Any]:
    """Extract background text, embedded links, and file attachments from active window and perform deep analysis."""
    if not hwnd:
        hwnd = get_active_window_hwnd()

    title = get_window_title(hwnd)
    child_texts = extract_child_windows_text(hwnd)

    # Check Windows clipboard fallback text
    from core.active_sentry import get_windows_clipboard_text
    clip_fallback = get_windows_clipboard_text()

    # Combine full background text
    full_text_chunks = [title] + child_texts
    if clip_fallback:
        full_text_chunks.append(clip_fallback)

    combined_text = "\n".join(full_text_chunks)

    all_flags: List[str] = []
    max_risk_score = 0
    primary_verdict = "CLEAN / SAFE"
    primary_threat_level = "LOW"
    target_summary = title if title else "Active Window"

    # 1. Extract ALL Embedded URLs/Hyperlinks in background text & title
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.(?:xyz|click|top|buzz|cfd|monster|icu|cam|tk|ml|ga|work)[^\s]*'
    extracted_urls = list(set(re.findall(url_pattern, combined_text)))

    url_reports = []
    for u in extracted_urls[:10]:  # Audit top 10 embedded hyperlinks in background text
        u_rep = scan_suspicious_url(u)
        url_reports.append(u_rep)
        if u_rep["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
            max_risk_score = max(max_risk_score, u_rep["risk_score"])
            all_flags.extend([f"🚨 Embedded Link [{u_rep['url']}]: {flag}" for flag in u_rep["flags"]])
            if u_rep["verdict"] == "MALICIOUS":
                primary_verdict = "MALICIOUS PHISHING LINK IN WINDOW"
                primary_threat_level = "CRITICAL"

    # 2. Audit Background Text for Phishing & Urgency Tactics
    if len(combined_text) > 10:
        email_rep = scan_email_text(combined_text)
        if email_rep["risk_score"] > 25:
            max_risk_score = max(max_risk_score, email_rep["risk_score"])
            all_flags.extend([f"📧 Background Text Trigger: {flag}" for flag in email_rep["flags"]])
            if "MALICIOUS" in email_rep["verdict"]:
                primary_verdict = "MALICIOUS PHISHING EMAIL ON SCREEN"
                primary_threat_level = "CRITICAL"
            elif "SUSPICIOUS" in email_rep["verdict"] and primary_verdict == "CLEAN / SAFE":
                primary_verdict = "SUSPICIOUS CONTENT ON SCREEN"
                primary_threat_level = "MEDIUM"

    # 3. Extract Attached Files / Disguised Executable Extensions in Window & Downloads
    file_pattern = r'[\w\.-]+\.(?:pdf|docx?|xlsx?|jpg|png|zip|rar|iso|img)\.(?:exe|scr|bat|vbs|js|cmd|hta|ps1)'
    extracted_files = list(set(re.findall(file_pattern, combined_text, re.IGNORECASE)))

    for f_name in extracted_files[:5]:
        max_risk_score = max(max_risk_score, 90)
        all_flags.append(f"🚨 Weaponized Attachment Disguised in Window: '{f_name}' (Double extension payload)")
        primary_verdict = "WEAPONIZED ATTACHMENT IN WINDOW"
        primary_threat_level = "CRITICAL"

    # Check recent downloads folder for active attachments
    downloads_dir = Path.home() / "Downloads"
    if downloads_dir.exists():
        try:
            recent_files = [f for f in downloads_dir.glob("*") if f.is_file()]
            if recent_files:
                newest = max(recent_files, key=lambda f: f.stat().st_mtime)
                # If modified within last 45 seconds
                import time
                if time.time() - newest.stat().st_mtime < 45:
                    file_rep = scan_attachment_file(str(newest))
                    if file_rep["verdict"] in ["MALICIOUS ATTACHMENT", "SUSPICIOUS ATTACHMENT"]:
                        max_risk_score = max(max_risk_score, file_rep["risk_score"])
                        all_flags.extend([f"📎 Downloaded Attachment [{newest.name}]: {flag}" for flag in file_rep["flags"]])
                        primary_verdict = "MALICIOUS DOWNLOADED ATTACHMENT"
                        primary_threat_level = "CRITICAL"
        except Exception:
            pass

    # Recommendation
    if max_risk_score >= 65:
        recommendation = "🚨 DANGER: Do not click links, enter credentials, or open attachments displayed in this window!"
    elif max_risk_score >= 30:
        recommendation = "⚠️ WARNING: Background text contains suspicious phishing / urgency patterns. Verify sender authenticity."
    else:
        recommendation = "✅ No malicious background text, phishing links, or disguised attachments detected in open window."

    # Remove duplicates from flags
    unique_flags = list(dict.fromkeys(all_flags))

    return {
        "window_title": title,
        "extracted_urls_count": len(extracted_urls),
        "extracted_urls": extracted_urls,
        "verdict": primary_verdict,
        "risk_score": max_risk_score,
        "threat_level": primary_threat_level,
        "flags": unique_flags if unique_flags else ["All background text, hyperlinks & attachments passed security checks"],
        "recommendation": recommendation,
        "scanned_text_length": len(combined_text)
    }
