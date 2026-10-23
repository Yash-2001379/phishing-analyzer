"""
Phase 3: Risk scoring + readable report.

Usage:
    python src/report.py samples/newsletter1.eml     (one email)
    python src/report.py samples                     (every .eml in the folder)

Each run prints the report and saves a copy in reports/.
"""
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

from parser import load_email, get_headers, get_body_and_urls, get_attachments, domain_of

# ---------- settings you can tweak ----------

# Domains that show up in almost every HTML email and mean nothing
JUNK_DOMAINS = {"www.w3.org", "w3.org", "schemas.microsoft.com"}

# Image files are just pictures in the email, not links people click
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp")

# Attachment types that can run code or hide malware
RISKY_EXTS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso",
              ".img", ".zip", ".rar", ".7z", ".html", ".htm", ".docm", ".xlsm")

# Words phishers love because they create panic
URGENT_WORDS = ("urgent", "verify", "suspended", "locked", "password", "immediately",
                "unusual activity", "confirm your", "account will be", "final notice")

# Brands that get impersonated a lot
BRANDS = ("paypal", "microsoft", "apple", "amazon", "netflix", "google", "outlook",
          "office365", "docusign", "dropbox", "fedex", "dhl", "canada post", "cra",
          "rbc", "td bank", "scotiabank", "cibc", "bmo", "interac")

# Country endings that use two parts, like bbc.co.uk
TWO_PART_TLDS = ("co.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "ac.uk", "gov.uk")


# ---------- helpers ----------

def root_domain(domain):
    """accounts.brain.fm -> brain.fm, so subdomains of one company count as the same."""
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def auth_status(auth_header):
    """Pull pass/fail/none for SPF, DKIM, DMARC out of the Authentication-Results header."""
    auth = auth_header.lower()
    result = {}
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{check}=(\w+)", auth)
        result[check] = m.group(1) if m else "missing"
    return result


def summarize_links(urls):
    """Collapse dozens of tracking URLs into a short list of real destinations."""
    domains = {}
    raw_ip_urls = []
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        path = urlparse(url).path.lower()
        if not host or host in JUNK_DOMAINS or path.endswith(IMAGE_EXTS):
            continue
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            raw_ip_urls.append(url)
        domains[host] = domains.get(host, 0) + 1
    return domains, raw_ip_urls


# ---------- scoring ----------

def score_email(path):
    msg = load_email(path)
    h = get_headers(msg)
    body, urls = get_body_and_urls(msg)
    attachments = get_attachments(msg)
    auth = auth_status(h["auth_results"])
    link_domains, raw_ips = summarize_links(urls)

    from_root = root_domain(domain_of(h["from_addr"]))
    findings = []   # (points, reason)

    # 1. Authentication. Real companies almost always pass these.
    if auth["spf"] in ("fail", "softfail"):
        findings.append((2, f"SPF {auth['spf']}, the sending server isn't allowed to send for this domain"))
    if auth["dkim"] == "fail":
        findings.append((2, "DKIM failed, the email may have been altered or forged"))
    if auth["dmarc"] == "fail":
        findings.append((3, "DMARC failed, the domain owner says this email isn't theirs"))
    dmarc_ok = auth["dmarc"] == "pass"

    # 2. Reply-To going somewhere else is a classic trick
    if h["reply_to"]:
        reply_root = root_domain(domain_of(h["reply_to"]))
        if reply_root != from_root:
            findings.append((3, f"Replies go to {reply_root}, not {from_root}"))

    # 3. Return-Path mismatch. Only counts if DMARC didn't pass,
    #    because newsletters use services like SendGrid all the time.
    if h["return_path"] and not dmarc_ok:
        rp_root = root_domain(domain_of(h["return_path"]))
        if rp_root != from_root:
            findings.append((1, f"Bounce address is {rp_root}, not {from_root}"))

    # 4. Display name pretends to be a brand the domain isn't
    name = h["from_name"].lower()
    for brand in BRANDS:
        if brand in name and brand.replace(" ", "") not in from_root:
            findings.append((3, f"Name says '{h['from_name']}' but it's sent from {from_root}"))
            break

    # 5. Links pointing at raw IP addresses
    for url in raw_ips:
        findings.append((3, f"Link goes to a raw IP address ({urlparse(url).hostname})"))

    # 6. Pressure language
    text = (h["subject"] + " " + body).lower()
    hits = [w for w in URGENT_WORDS if w in text]
    if hits:
        findings.append((1, f"Pressure words used: {', '.join(hits[:4])}"))

    # 7. Dangerous attachments
    for att in attachments:
        fname = (att["filename"] or "").lower()
        if fname.endswith(RISKY_EXTS):
            findings.append((3, f"Risky attachment: {att['filename']}"))

    total = sum(p for p, _ in findings)
    if total >= 6:
        verdict = "HIGH"
    elif total >= 3:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "file": os.path.basename(path),
        "headers": h,
        "auth": auth,
        "from_root": from_root,
        "link_domains": link_domains,
        "total_urls": len(urls),
        "attachments": attachments,
        "findings": findings,
        "score": total,
        "verdict": verdict,
    }


# ---------- report text ----------

def build_report(r):
    h = r["headers"]
    icon = {"pass": "PASS", "fail": "FAIL", "softfail": "SOFTFAIL", "none": "NONE", "missing": "MISSING"}
    lines = []
    lines.append("=" * 60)
    lines.append(f"  PHISHING REPORT  |  {r['file']}")
    lines.append("=" * 60)
    lines.append(f"  VERDICT: {r['verdict']} RISK   (score {r['score']})")
    lines.append("")
    lines.append(f"  Subject : {h['subject']}")
    lines.append(f"  From    : {h['from_name']} <{h['from_addr']}>")
    if h["reply_to"]:
        lines.append(f"  Reply-To: {h['reply_to']}")
    lines.append("")
    lines.append("  Authentication")
    for check in ("spf", "dkim", "dmarc"):
        status = r["auth"][check]
        lines.append(f"    {check.upper():<6} {icon.get(status, status.upper())}")
    lines.append("")
    lines.append("  Why")
    if r["findings"]:
        for points, reason in sorted(r["findings"], reverse=True):
            lines.append(f"    +{points}  {reason}")
    else:
        lines.append("    Nothing suspicious found")
    lines.append("")
    lines.append(f"  Links ({r['total_urls']} found, {len(r['link_domains'])} real destinations)")
    for dom, count in sorted(r["link_domains"].items(), key=lambda x: -x[1]):
        lines.append(f"    {dom}  x{count}")
    if r["attachments"]:
        lines.append("")
        lines.append("  Attachments")
        for att in r["attachments"]:
            lines.append(f"    {att['filename']}  ({att['size_bytes']} bytes)")
            lines.append(f"      sha256 {att['sha256']}")
    lines.append("=" * 60)
    return "\n".join(lines)


def save_report(text, eml_name):
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.join("reports", f"{os.path.splitext(eml_name)[0]}_{stamp}.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    return out


# ---------- main ----------

def main():
    if len(sys.argv) != 2:
        print("Usage: python src/report.py <email.eml or folder>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isdir(target):
        files = sorted(os.path.join(target, f) for f in os.listdir(target) if f.lower().endswith(".eml"))
    else:
        files = [target]

    if not files:
        print("No .eml files found")
        sys.exit(1)

    results = []
    for path in files:
        r = score_email(path)
        text = build_report(r)
        print(text)
        print(f"  saved to {save_report(text, r['file'])}\n")
        results.append(r)

    # Summary table when you scan a whole folder
    if len(results) > 1:
        print("SUMMARY")
        print(f"  {'FILE':<30} {'VERDICT':<8} SCORE")
        for r in sorted(results, key=lambda x: -x["score"]):
            print(f"  {r['file'][:30]:<30} {r['verdict']:<8} {r['score']}")


if __name__ == "__main__":
    main()
