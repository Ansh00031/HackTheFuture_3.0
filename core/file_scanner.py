"""Autonomous Attachment, Document & Image Virus/Malware Scanner.

Audits:
1. Double extensions (e.g. invoice.pdf.exe, receipt.docx.vbs)
2. Magic byte mismatch (Disguised PE executables masquerading as images/PDFs)
3. Office macro exploits (.xlsm, .docm with suspicious VBA indicators)
4. Malicious script payloads (.js, .ps1, .bat, .hta, .iso, .vbs)
5. Image metadata / Steganography / Suspicious EXIF payloads
"""

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Magic byte signatures for true file type identification
MAGIC_SIGNATURES = {
    b"MZ": {"type": "PE Executable (.exe / .dll / .scr)", "risk": "CRITICAL"},
    b"%PDF-": {"type": "PDF Document", "risk": "LOW"},
    b"\xff\xd8\xff": {"type": "JPEG Image", "risk": "LOW"},
    b"\x89PNG\r\n\x1a\n": {"type": "PNG Image", "risk": "LOW"},
    b"GIF87a": {"type": "GIF Image", "risk": "LOW"},
    b"GIF89a": {"type": "GIF Image", "risk": "LOW"},
    b"PK\x03\x04": {"type": "ZIP / Office Archive (.docx / .xlsx / .zip / .apk)", "risk": "LOW"},
    b"Rar!\x1a\x07": {"type": "RAR Archive", "risk": "MEDIUM"},
    b"7z\xbc\xaf\x27\x1c": {"type": "7-Zip Archive", "risk": "MEDIUM"},
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1",
    ".iso", ".img", ".xlsm", ".docm", ".dll", ".hta", ".apk", ".jar", ".pif"
}

SUSPICIOUS_DOUBLE_EXTENSIONS = [
    r"\.pdf\.(exe|scr|bat|vbs|js|cmd|hta)$",
    r"\.docx?\.(exe|scr|bat|vbs|js|cmd|hta)$",
    r"\.xlsx?\.(exe|scr|bat|vbs|js|cmd|hta)$",
    r"\.jpg\.(exe|scr|bat|vbs|js|cmd|hta)$",
    r"\.png\.(exe|scr|bat|vbs|js|cmd|hta)$",
    r"\.zip\.(exe|scr|bat|vbs|js|cmd|hta)$",
]

VBA_MACRO_INDICATORS = [
    b"AutoOpen", b"AutoExec", b"Document_Open", b"Workbook_Open",
    b"Shell", b"WScript.Shell", b"powershell", b"cmd.exe", b"URLDownloadToFile"
]


def compute_file_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate MD5 and SHA-256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except Exception:
        return {"md5": "UNKNOWN", "sha256": "UNKNOWN"}


def scan_attachment_file(file_path_str: str) -> Dict[str, Any]:
    """Inspect a file or attachment for masquerading, macros, executable payloads and malware indicators."""
    path = Path(file_path_str)
    if not path.exists() or not path.is_file():
        return {
            "file_name": path.name,
            "exists": False,
            "verdict": "ERROR",
            "risk_score": 0,
            "flags": ["File not found or inaccessible"],
            "recommendation": "File path does not exist."
        }

    file_name = path.name
    file_name_lower = file_name.lower()
    file_size = path.stat().st_size
    flags: List[str] = []
    risk_score = 0

    # 1. Double Extension Inspection
    for pattern in SUSPICIOUS_DOUBLE_EXTENSIONS:
        if re.search(pattern, file_name_lower):
            risk_score += 65
            flags.append(f"🚨 Double Extension Spoofing: Disguised file extension ({file_name})")
            break

    # 2. High-Risk Executable / Script Extension
    ext = path.suffix.lower()
    if ext in HIGH_RISK_EXTENSIONS:
        risk_score += 45
        flags.append(f"Dangerous Executable / Script Payload extension ({ext})")

    # 3. Magic Bytes & Disguise Inspection (Content vs Extension Mismatch)
    try:
        with open(path, "rb") as f:
            header = f.read(512)
    except Exception as e:
        header = b""
        flags.append(f"Could not read file header: {e}")

    detected_real_type = "Unknown / Plain Text"
    for magic, info in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            detected_real_type = info["type"]
            if info["risk"] == "CRITICAL" and ext not in [".exe", ".dll"]:
                risk_score += 85
                flags.append(f"🚨 Severe Masquerading: File named '{file_name}' contains hidden Windows PE Executable binary!")
            break

    # 4. Office Macro Payload Inspection (.xlsm, .docm, or zipped VBA)
    if ext in [".xlsm", ".docm", ".dotm", ".xltm"] or (b"vbaProject.bin" in header):
        risk_score += 35
        flags.append(f"Enabled VBA Macros detected in Office Document ({ext})")
        
        # Scan for dangerous auto-execution commands
        try:
            with open(path, "rb") as f:
                content = f.read(1024 * 1024)  # read up to 1MB
                matched_indicators = [ind.decode("utf-8", errors="ignore") for ind in VBA_MACRO_INDICATORS if ind in content]
                if matched_indicators:
                    risk_score += 45
                    flags.append(f"🚨 Weaponized Macro Hooks: Auto-execution triggers ({', '.join(matched_indicators[:4])})")
        except Exception:
            pass

    # 5. Image EXIF & Script Injection Audit
    if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"]:
        # Check for embedded script tags or shell payloads hidden inside image binary
        try:
            with open(path, "rb") as f:
                img_data = f.read(512 * 1024)
                if b"<script" in img_data.lower() or b"powershell" in img_data.lower() or b"cmd.exe" in img_data.lower():
                    risk_score += 55
                    flags.append("🚨 Steganographic / Script Injection: Hidden executable code detected inside image payload")
        except Exception:
            pass

    # Risk Normalization
    risk_score = min(100, risk_score)
    hashes = compute_file_hashes(path)

    if risk_score >= 65:
        verdict = "MALICIOUS ATTACHMENT"
        threat_level = "CRITICAL"
        recommendation = "🚨 QUARANTINE & DO NOT OPEN: High probability of malware, ransomware, or trojan dropper."
    elif risk_score >= 30:
        verdict = "SUSPICIOUS ATTACHMENT"
        threat_level = "MEDIUM"
        recommendation = "⚠️ USE CAUTION: File exhibits unusual properties. Scan with dedicated sandbox before opening."
    else:
        verdict = "CLEAN / BENIGN FILE"
        threat_level = "LOW"
        recommendation = "✅ No malicious payloads, disguised headers, or weaponized macros detected."

    return {
        "file_name": file_name,
        "file_path": str(path.resolve()),
        "file_size_bytes": file_size,
        "detected_type": detected_real_type,
        "verdict": verdict,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "flags": flags if flags else ["Passed standard attachment safety verification"],
        "hashes": hashes,
        "recommendation": recommendation
    }
