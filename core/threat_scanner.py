"""Cyber Threat Scanner: Spam/Phishing Email & Malicious Link Detection Engine.

Uses a multi-layered hybrid approach:
1. Deterministic Heuristics (Regex patterns, suspicious TLDs, IP formats, Homoglyphs, Urgency triggers)
2. Structural URL Analysis (Entropy, Punycode/Homoglyphs, dangerous file extensions, credential spoofing)
3. AI Cognitive Threat Analyzer (LLM reasoning with deterministic fallback)
"""

import math
import re
import urllib.parse
from typing import Any, Dict, List, Optional

# Known high-risk and suspicious Top-Level Domains (TLDs) frequently abused in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "click", "rest", "surf", "cfd", "monster", "icu", "cam",
    "country", "stream", "gq", "cf", "tk", "ml", "ga", "work", "loan", "men",
    "fit", "date", "faith", "racing", "review", "download", "party", "accountant"
}

# High-profile brand keywords commonly targeted in typosquatting / credential harvesting
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank",
    "chase", "wellsfargo", "binance", "metamask", "coinbase", "steam",
    "facebook", "instagram", "whatsapp", "dropbox", "dhl", "fedex", "usps"
]

# High-urgency and panic-inducing keywords used in social engineering
URGENCY_KEYWORDS = [
    "urgent", "immediate action required", "account suspended", "unauthorized transaction",
    "security alert", "wire transfer", "verify your identity", "24 hours", "locked out",
    "billing problem", "refund waiting", "tax refund", "claim your prize", "winner",
    "reset your password now", "unusual sign-in activity", "compromised"
]

# Dangerous file extensions often delivered via malicious links or attachments
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1",
    ".iso", ".img", ".xlsm", ".docm", ".dll", ".hta", ".apk", ".jar"
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to detect high randomness (DGA / obfuscated domains)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def scan_suspicious_url(url: str) -> Dict[str, Any]:
    """Analyze URL structure, TLD reputation, homoglyphs, and dangerous patterns.
    
    Returns structured risk evaluation dictionary.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    flags: List[str] = []
    risk_score = 0  # 0 to 100

    try:
        parsed = urllib.parse.urlparse(url_to_parse)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        return {
            "url": url,
            "verdict": "MALICIOUS",
            "risk_score": 95,
            "threat_level": "CRITICAL",
            "flags": ["Malformed / Obfuscated URL structure"],
            "recommendation": "Do not open or click this link."
        }

    # 1. IP Address as Hostname
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    if re.match(ip_pattern, netloc):
        risk_score += 45
        flags.append("Raw IPv4 Hostname used instead of standard domain (Bypasses DNS reputation)")

    # 2. Embedded Credentials / Userinfo (@ trick)
    if "@" in netloc or "@" in url:
        risk_score += 40
        flags.append("Embedded credential / '@' redirect spoofing detected")

    # 3. Suspicious or High-Risk TLD
    domain_parts = netloc.split(":")[0].split(".")
    if len(domain_parts) > 1:
        tld = domain_parts[-1]
        if tld in SUSPICIOUS_TLDS:
            risk_score += 30
            flags.append(f"High-Risk / Shady TLD detected (.{tld}) commonly abused in phishing campaigns")

    # 4. Brand Typosquatting / Lookalike in Subdomain
    matched_brands = [b for b in TARGETED_BRANDS if b in netloc]
    if matched_brands:
        # Check if the primary registered domain is NOT the genuine brand
        # e.g., paypal.com.attacker.com or paypal-security-update.xyz
        genuine_domains = {f"{brand}.com" for brand in matched_brands} | {f"{brand}.org" for brand in matched_brands} | {f"{brand}.net" for brand in matched_brands}
        is_genuine = any(netloc == brand or netloc.endswith(f".{brand}.com") for brand in matched_brands)
        if not is_genuine:
            risk_score += 45
            flags.append(f"Suspected Brand Impersonation / Typosquatting targeting: {', '.join(matched_brands).upper()}")

    # 5. Excessive Subdomain Depth (Subdomain flooding)
    if len(domain_parts) >= 5:
        risk_score += 25
        flags.append("Excessive subdomain depth (Deep nesting to conceal origin)")

    # 6. Dangerous Executable / Payload Extension in Path
    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext) or ext in query:
            risk_score += 50
            flags.append(f"Direct download link to dangerous executable payload ({ext})")
            break

    # 7. Obfuscated / Non-ASCII Punycode (Homoglyph Attack)
    if "xn--" in netloc:
        risk_score += 35
        flags.append("Punycode (IDN) detected: Potential Internationalized Domain Homoglyph spoofing")

    # 8. High Entropy Subdomain / Path (Randomized token or DGA)
    entropy = calculate_entropy(netloc)
    if entropy > 4.2 and len(netloc) > 18:
        risk_score += 20
        flags.append(f"High domain character entropy ({entropy}): Suspicious randomized domain / DGA")

    # 9. Excessive URL length
    if len(url) > 250:
        risk_score += 15
        flags.append("Unusually long URL payload (>250 chars) typical of tracking/phishing tokens")

    # Final Risk Normalization
    risk_score = min(100, risk_score)

    if risk_score >= 65:
        verdict = "MALICIOUS"
        threat_level = "CRITICAL"
        recommendation = "🚨 BLOCK & QUARANTINE: Do not click or navigate to this URL. High probability of phishing or drive-by malware."
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
        threat_level = "MEDIUM"
        recommendation = "⚠️ PROCEED WITH CAUTION: Domain exhibits anomalous patterns. Verify sender authenticity before interacting."
    else:
        verdict = "CLEAN / SAFE"
        threat_level = "LOW"
        recommendation = "✅ No prominent structural threats or phishing indicators detected."

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "flags": flags if flags else ["Passed standard heuristic checks"],
        "recommendation": recommendation,
        "parsed_domain": netloc,
        "entropy": entropy
    }


def scan_email_text(raw_text: str) -> Dict[str, Any]:
    """Analyze email content for social engineering, urgency, credential harvesting, and suspicious links.
    
    Returns structured email threat assessment.
    """
    flags: List[str] = []
    risk_score = 0
    text_lower = raw_text.lower()

    # 1. Detect Extracted URLs and Scan them
    extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', raw_text)
    url_results = []
    for u in extracted_urls[:5]:  # scan up to top 5 links
        u_res = scan_suspicious_url(u)
        url_results.append(u_res)
        if u_res["verdict"] == "MALICIOUS":
            risk_score += 40
            flags.append(f"Contains Malicious Phishing Link: {u_res['url']} (Score: {u_res['risk_score']}%)")
        elif u_res["verdict"] == "SUSPICIOUS":
            risk_score += 20
            flags.append(f"Contains Suspicious Link: {u_res['url']}")

    # 2. Urgency and Panic Social Engineering Triggers
    matched_urgency = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    if matched_urgency:
        risk_score += min(35, len(matched_urgency) * 12)
        flags.append(f"Social Engineering Urgency Tactics Detected ({', '.join(matched_urgency[:3])})")

    # 3. Credential & Financial Harvesting Inquiries
    financial_keywords = ["password", "seed phrase", "credit card", "bank account", "social security", "ssn", "otp", "wire money", "crypto", "wallet private key"]
    matched_fin = [kw for kw in financial_keywords if kw in text_lower]
    if matched_fin:
        risk_score += 30
        flags.append(f"Sensitive Credential / Financial Asset Inquiries ({', '.join(matched_fin)})")

    # 4. Brand Impersonation inside text
    matched_brands = [b for b in TARGETED_BRANDS if b in text_lower]
    if matched_brands and matched_urgency:
        risk_score += 25
        flags.append(f"Targeted Brand Impersonation with High Pressure ({', '.join(matched_brands).upper()})")

    # 5. Generic / Impersonal Greeting
    generic_greetings = ["dear customer", "dear user", "valued customer", "dear member", "undisclosed-recipients"]
    if any(g in text_lower for g in generic_greetings):
        risk_score += 15
        flags.append("Generic / Impersonal Greeting (Common in bulk mass-phishing)")

    # Normalize Score
    risk_score = min(100, risk_score)

    if risk_score >= 60:
        verdict = "MALICIOUS PHISHING"
        threat_level = "CRITICAL"
        recommendation = "🚨 DO NOT RESPOND, CLICK LINKS, OR OPEN ATTACHMENTS. Mark as Phishing and permanently delete."
    elif risk_score >= 30:
        verdict = "SUSPICIOUS / SPAM"
        threat_level = "MEDIUM"
        recommendation = "⚠️ POTENTIAL SPAM: Exercise extreme vigilance. Verify sender identity via an independent official channel."
    else:
        verdict = "LEGITIMATE / SAFE"
        threat_level = "LOW"
        recommendation = "✅ No aggressive phishing patterns or social engineering indicators found."

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "flags": flags if flags else ["No suspicious phishing triggers detected"],
        "extracted_urls_count": len(extracted_urls),
        "url_analysis": url_results,
        "recommendation": recommendation,
    }
