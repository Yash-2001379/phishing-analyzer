"""
Phase 3: Risk scoring + readable report.

Usage:
    python src/report.py samples/newsletter1.eml     (one email)
    python src/report.py samples                     (every .eml in the folder)
    python src/report.py samples --vt                (also check VirusTotal)

Prints a colored report in the terminal and saves a Markdown copy in reports/.
Uses only Python's standard library, nothing to install.
"""
import os
import re
import sys
import html
from datetime import datetime
from urllib.parse import urlparse

from parser import load_email, get_headers, get_body_and_urls, get_attachments, domain_of
import vt_client

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
                "unusual activity", "unusual sign", "confirm your", "account will be",
                "final notice")

# Words scammers use to bait you with a reward
LURE_WORDS = ("free gift", "free spin", "no deposit", "you have won", "winner", "prize",
              "claim your", "expiring", "expires today", "bonus", "reward")

# Brands that get impersonated a lot, and the real domains they send from
BRANDS = {
    "paypal": ["paypal.com", "paypal.ca"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "outlook": ["microsoft.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.ca"],
    "netflix": ["netflix.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.ca"],
    "canada post": ["canadapost.ca", "canadapost-postescanada.ca"],
    "rbc": ["rbc.com", "rbcroyalbank.com"],
    "td bank": ["td.com", "tdbank.com"],
    "scotiabank": ["scotiabank.com"],
    "cibc": ["cibc.com"],
    "bmo": ["bmo.com"],
    "interac": ["interac.ca"],
}

# Free domains anyone can sign up for. Real companies don't send from these.
FREE_TENANT_DOMAINS = ("onmicrosoft.com",)
FREE_WEBMAIL = ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
                "proton.me", "protonmail.com", "icloud.com", "gmx.com", "mail.ru")

# Tricks scammers use to make a fake domain look like a real brand (paypa1, micr0soft, rnicrosoft)
LOOKALIKE_SWAPS = {"0": "o", "3": "e", "4": "a", "5": "s", "rn": "m", "vv": "w"}
# Short brand names like "bmo" or "cra" hide inside normal words, so only check longer ones
LOOKALIKE_MIN_LEN = 5

# VirusTotal (only used with --vt).
# One vendor flagging something is often a false alarm, so we need at least this many.
VT_MIN_VENDORS = 2
# Only check the busiest few link domains per email, to save the 500/day quota
VT_MAX_LINK_DOMAINS = 3
# Common helper sites in HTML emails, not worth a lookup
VT_SKIP_DOMAINS = {"fonts.googleapis.com", "fonts.gstatic.com"}

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


def lookalike_brand(root):
    """Return the brand a domain is pretending to be (paypa1.com -> paypal), or None."""
    if not root or root in FREE_TENANT_DOMAINS or root in FREE_WEBMAIL:
        return None
    name = root.split(".")[0].replace("-", "")
    # "1" can stand in for "l" (paypa1) or "i" (m1crosoft), so try both
    versions = []
    for one_as in ("l", "i"):
        fixed = name.replace("1", one_as)
        for fake, real in LOOKALIKE_SWAPS.items():
            fixed = fixed.replace(fake, real)
        versions.append(fixed)
    for brand, real_domains in BRANDS.items():
        brand_word = brand.replace(" ", "")
        if len(brand_word) < LOOKALIKE_MIN_LEN or root in real_domains:
            continue
        for v in versions:
            if brand_word in v:
                return brand
    return None


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

def verdict_for(total):
    """Turn a point total into HIGH, MEDIUM, or LOW."""
    if total >= 6:
        return "HIGH"
    if total >= 3:
        return "MEDIUM"
    return "LOW"


def score_email(path):
    msg = load_email(path)
    h = get_headers(msg)
    body, urls = get_body_and_urls(msg)
    attachments = get_attachments(msg)
    auth = auth_status(h["auth_results"])
    link_domains, raw_ips = summarize_links(urls)

    from_domain = domain_of(h["from_addr"])
    from_root = root_domain(from_domain) if from_domain else ""
    sender_label = from_root or "an empty sender"
    findings = []   # (points, reason)

    # 1. Sender address itself. Missing or fake-looking = big red flag.
    if not h["from_addr"]:
        findings.append((3, "No sender address at all"))
    elif not from_domain:
        findings.append((2, "Sender address has no domain (no @ part)"))
    elif "." not in from_domain:
        findings.append((2, f"Sender domain '{from_domain}' isn't a real domain"))
    if from_root in FREE_TENANT_DOMAINS:
        findings.append((2, f"Sent from a free {from_root} trial domain, often abused by scammers"))

    # 2. Authentication. Real companies almost always pass these.
    if auth["spf"] in ("fail", "softfail"):
        findings.append((2, f"SPF {auth['spf']}, the sending server isn't allowed to send for this domain"))
    if auth["dkim"] == "fail":
        findings.append((2, "DKIM failed, the email may have been altered or forged"))
    if auth["dmarc"] == "fail":
        findings.append((3, "DMARC failed, the domain owner says this email isn't theirs"))
    dmarc_ok = auth["dmarc"] == "pass"
    # Passed checks prove the sending server and signature are real for this email
    authenticated = dmarc_ok or (auth["spf"] == "pass" and auth["dkim"] == "pass")
    if auth["dkim"] in ("none", "missing") and not dmarc_ok:
        findings.append((2, "No DKIM signature and no DMARC pass, nothing proves who sent this"))

    # 3. Reply-To going somewhere else is a classic trick.
    #    Free inboxes always count fully. A different company domain counts less
    #    when the email is authenticated, because big companies use sister
    #    domains (playstation.com replies go to sony.com).
    if h["reply_to"]:
        reply_root = root_domain(domain_of(h["reply_to"]))
        if reply_root != from_root:
            if reply_root in FREE_WEBMAIL:
                findings.append((3, f"Replies go to a free {reply_root} inbox, not {sender_label}"))
            elif authenticated:
                findings.append((1, f"Replies go to {reply_root}, not {sender_label} (email is authenticated)"))
            else:
                findings.append((3, f"Replies go to {reply_root}, not {sender_label}"))

    # 4. Return-Path mismatch. Only counts if DMARC didn't pass,
    #    because newsletters use services like SendGrid all the time.
    if h["return_path"] and not dmarc_ok:
        rp_root = root_domain(domain_of(h["return_path"]))
        if rp_root != from_root:
            findings.append((1, f"Bounce address is {rp_root}, not {sender_label}"))

    # 5. Pretending to be a brand it isn't.
    #    Sender name: always counts. Subject: only counts if the email isn't authenticated,
    #    because real newsletters mention other brands all the time.
    name = h["from_name"].lower()
    subject = h["subject"].lower()
    for brand, real_domains in BRANDS.items():
        if from_root in real_domains:
            continue
        if brand in name:
            findings.append((3, f"Name says '{h['from_name']}' but it's sent from {sender_label}"))
            break
        if brand in subject and not dmarc_ok:
            findings.append((2, f"Subject mentions {brand.title()} but it's sent from {sender_label}"))
            break

    # 5b. Domain built to look like a brand (paypa1.com, paypal-help.com)
    fake_of = lookalike_brand(from_root)
    if fake_of:
        findings.append((3, f"Domain {from_root} is a lookalike of {fake_of.title()}, not their real site"))

    # 6. Links pointing at raw IP addresses. Count each IP once, even if many links use it.
    seen_ips = []
    for url in raw_ips:
        ip = urlparse(url).hostname
        if ip not in seen_ips:
            seen_ips.append(ip)
            findings.append((3, f"Link goes to a raw IP address ({ip})"))

    # 7. Pressure and bait language
    text = (h["subject"] + " " + body).lower()
    urgent = [w for w in URGENT_WORDS if w in text]
    if urgent:
        findings.append((1, f"Pressure words used: {', '.join(urgent[:4])}"))
    lure = [w for w in LURE_WORDS if w in text]
    if lure:
        findings.append((1, f"Bait words used: {', '.join(lure[:4])}"))

    # 8. Dangerous attachments
    for att in attachments:
        fname = (att["filename"] or "").lower()
        if fname.endswith(RISKY_EXTS):
            findings.append((3, f"Risky attachment: {att['filename']}"))

    total = sum(p for p, _ in findings)
    verdict = verdict_for(total)

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


# ---------- VirusTotal (optional, --vt) ----------

def vt_targets(r):
    """Pick the few things worth spending VirusTotal quota on for one email."""
    targets = []   # (label, value, endpoint)
    seen = set()

    def add(label, value, endpoint):
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            targets.append((label, value, endpoint))

    sender = domain_of(r["headers"]["from_addr"])
    add("sender domain", sender, vt_client.domain_endpoint(sender))
    reply = domain_of(r["headers"]["reply_to"])
    add("reply-to domain", reply, vt_client.domain_endpoint(reply))

    busiest = sorted(r["link_domains"].items(), key=lambda x: -x[1])
    links_added = 0
    for d, _ in busiest:
        if links_added >= VT_MAX_LINK_DOMAINS:
            break
        if d in VT_SKIP_DOMAINS:
            continue
        before = len(targets)
        add("link domain", d, vt_client.domain_endpoint(d))
        if len(targets) > before:
            links_added += 1

    for a in r["attachments"]:
        add("attachment", a["filename"] or "(no name)", vt_client.file_endpoint(a["sha256"]))
    return targets


def add_vt_findings(r, cache, api_key):
    """Look up an email's domains and attachments on VirusTotal and add points for bad ones."""
    targets = vt_targets(r)
    new = sum(1 for _, _, ep in targets if not vt_client.is_cached(cache, ep))
    if new:
        print(c(f"  VirusTotal: checking {new} new item(s) for {clean(r['file'], 40)}"
                f" (about {new * vt_client.RATE_DELAY}s)", GREY), flush=True)

    r["vt"] = {"checked": 0, "unknown": 0, "flagged": 0, "errors": 0}
    for label, value, endpoint in targets:
        try:
            res = vt_client.vt_get(endpoint, cache, api_key)
        except vt_client.VTError as e:
            if e.fatal:
                raise
            r["vt"]["errors"] += 1
            continue
        if res["status"] == "not_found":
            r["vt"]["unknown"] += 1
            continue
        r["vt"]["checked"] += 1
        if res["malicious"] >= VT_MIN_VENDORS:
            r["vt"]["flagged"] += 1
            r["findings"].append((3, f"VirusTotal: {res['malicious']} vendors flag {label} {value} as malicious"))

    r["score"] = sum(p for p, _ in r["findings"])
    r["verdict"] = verdict_for(r["score"])


def vt_summary(vt):
    """One short line like '4 checked, 1 flagged, 1 unknown to VirusTotal'."""
    parts = [f"{vt['checked']} checked", f"{vt['flagged']} flagged"]
    if vt["unknown"]:
        parts.append(f"{vt['unknown']} unknown to VirusTotal")
    if vt["errors"]:
        parts.append(f"{vt['errors']} failed")
    return ", ".join(parts)


# ---------- terminal colors ----------
# Plain ANSI escape codes, built into every modern terminal. No packages needed.

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if os.name == "nt":
    os.system("")  # turns on color support in older Windows terminals

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)

RED, AMBER, GREEN, GREY, BOLD = "31", "33", "32", "90", "1"
VERDICT_COLOR = {"HIGH": RED, "MEDIUM": AMBER, "LOW": GREEN}
VERDICT_LABEL = {"HIGH": "HIGH RISK", "MEDIUM": "MEDIUM RISK", "LOW": "LOW RISK"}


def clean(text, limit=None):
    """Strip control characters from email text so an attacker can't mess with your terminal."""
    text = "".join(ch for ch in str(text or "") if ch.isprintable())
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def label(name):
    """Grey field label padded to a fixed width. Pad first, then color, or the color codes break the spacing."""
    return c(f"{name:<12}", GREY)


def auth_badge(name, status):
    if status == "pass":
        return c(f"✓ {name}", GREEN)
    if status in ("fail", "softfail"):
        return c(f"✗ {name} {status}", RED)
    return c(f"? {name} {status}", AMBER)


# ---------- terminal report ----------

def print_card(r):
    h = r["headers"]
    color = VERDICT_COLOR[r["verdict"]]
    width = 64
    top = f" {VERDICT_LABEL[r['verdict']]}  ·  score {r['score']} "
    name = f" {clean(r['file'], 28)} "
    gap = width - len(top) - len(name)

    print(c("╭" + "─" * width + "╮", color))
    print(c("│", color) + c(top, color + ";" + BOLD) + " " * max(gap, 1) + c(name, GREY) + c("│", color))
    print(c("╰" + "─" * width + "╯", color))

    print("  " + c(clean(h["subject"], 70) or "(no subject)", BOLD))
    sender = clean(h["from_addr"]) or c("(no address)", RED)
    print(f"  {label('From')}{clean(h['from_name'], 30)} <{sender}>")
    if h["reply_to"]:
        print(f"  {label('Reply-To')}{clean(h['reply_to'])}")
    badges = "   ".join(auth_badge(k.upper(), r["auth"][k]) for k in ("spf", "dkim", "dmarc"))
    print(f"  {label('Auth')}{badges}")
    if "vt" in r:
        vt_color = RED if r["vt"]["flagged"] else GREY
        print(f"  {label('VirusTotal')}{c(vt_summary(r['vt']), vt_color)}")

    print()
    if r["findings"]:
        for points, reason in sorted(r["findings"], reverse=True):
            print(f"   {c('+' + str(points), RED + ';' + BOLD)}  {clean(reason)}")
    else:
        print("   " + c("✓ Nothing suspicious found", GREEN))

    if r["link_domains"]:
        top_links = sorted(r["link_domains"].items(), key=lambda x: -x[1])[:5]
        links = ", ".join(clean(d) for d, _ in top_links)
        more = len(r["link_domains"]) - len(top_links)
        extra = f" +{more} more" if more > 0 else ""
        print(f"\n  {label('Links')}{links}{extra}")
    for a in r["attachments"]:
        print(f"  {label('Attachment')}{clean(a['filename'])}  {c(a['sha256'][:16] + '…', GREY)}")
    print()


def print_summary(results, skipped, md_path):
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in ("HIGH", "MEDIUM", "LOW")}
    print(c("SUMMARY", BOLD) + c(f"   {len(results)} emails scanned", GREY))
    print("  " + "   ".join(c(f"{counts[v]} {v.lower()}", VERDICT_COLOR[v] + ";" + BOLD) for v in counts))
    print()
    for r in sorted(results, key=lambda x: -x["score"]):
        tag = c(f"{r['verdict']:<6}", VERDICT_COLOR[r["verdict"]] + ";" + BOLD)
        print(f"  {tag}  {r['score']:>3}   {clean(r['headers']['subject'], 50) or '(no subject)'}")
    if skipped:
        print("\n" + c("SKIPPED", GREY))
        for n, why in skipped:
            print(f"  {clean(n, 30):<30} {c(why, GREY)}")
    print("\n" + c(f"Saved report: {md_path}", GREY))
    print(c("Open it in VS Code and press Ctrl+Shift+V for the formatted view", GREY))


# ---------- markdown report ----------
# Email text gets escaped so nothing in a phishing email can turn into
# a live link, image, or HTML when you preview the report.

def md(text, limit=None):
    text = html.escape(clean(text, limit), quote=False)
    for ch in "|`*_[]":
        text = text.replace(ch, "\\" + ch)
    # "Defang" links the way analysts do, so nothing in the report is clickable
    text = re.sub(r"(?i)http(s?)://", r"hxxp\1://", text)
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return text


def build_markdown(results, skipped):
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in ("HIGH", "MEDIUM", "LOW")}
    icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}
    auth_icon = lambda s: "✅" if s == "pass" else ("❌" if s in ("fail", "softfail") else "⚠️")
    ordered = sorted(results, key=lambda x: -x["score"])

    out = ["# Phishing Report", "",
           f"Scanned **{len(results)}** emails on {datetime.now().strftime('%b %d, %Y at %I:%M %p')}", "",
           f"🔴 **{counts['HIGH']}** high  ·  🟠 **{counts['MEDIUM']}** medium  ·  🟢 **{counts['LOW']}** low", "",
           "| Verdict | Score | Subject |", "|---|---:|---|"]
    for r in ordered:
        out.append(f"| {icon[r['verdict']]} {r['verdict']} | {r['score']} | {md(r['headers']['subject'], 60) or '(no subject)'} |")

    for r in ordered:
        h = r["headers"]
        out += ["", "---", "",
                f"## {icon[r['verdict']]} {md(h['subject'], 90) or '(no subject)'}", "",
                f"**{VERDICT_LABEL[r['verdict']]}**, score {r['score']}  ·  `{clean(r['file'])}`", "",
                "| | |", "|---|---|",
                f"| From | {md(h['from_name'], 40)} &lt;{md(h['from_addr']) or '**no address**'}&gt; |"]
        if h["reply_to"]:
            out.append(f"| Reply-To | {md(h['reply_to'])} |")
        out.append("| Auth | " + "  ".join(f"{auth_icon(r['auth'][k])} {k.upper()} {r['auth'][k]}"
                                           for k in ("spf", "dkim", "dmarc")) + " |")
        if "vt" in r:
            out.append(f"| VirusTotal | {vt_summary(r['vt'])} |")
        out += ["", "**Why**", ""]
        if r["findings"]:
            out += [f"- **+{p}** {md(reason)}" for p, reason in sorted(r["findings"], reverse=True)]
        else:
            out.append("- ✅ Nothing suspicious found")
        if r["link_domains"]:
            doms = sorted(r["link_domains"].items(), key=lambda x: -x[1])
            out += ["", f"**Link destinations** ({r['total_urls']} links total)", ""]
            out += [f"- {md(d)} (x{n})" for d, n in doms]
        if r["attachments"]:
            out += ["", "**Attachments**", ""]
            out += [f"- {md(a['filename'])}, {a['size_bytes']:,} bytes, SHA256 {a['sha256']}" for a in r["attachments"]]

    if skipped:
        out += ["", "---", "", "## Skipped files", ""]
        out += [f"- {md(n)}, {md(w)}" for n, w in skipped]
    return "\n".join(out) + "\n"


def save_markdown(text):
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.join("reports", f"report_{stamp}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    return out


# ---------- main ----------

def looks_like_email(path):
    """Check the first few lines for normal email headers, whatever the file is called."""
    try:
        with open(path, "rb") as f:
            start = f.read(4096).decode("utf-8", errors="ignore").lower()
    except OSError:
        return False
    return any(h in start for h in ("from:", "received:", "subject:", "return-path:"))


def find_emails(folder):
    """Every file in the folder that is actually an email, any name, any extension."""
    found, skipped = [], []
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path) or name.startswith("."):
            continue
        if name.lower().endswith(".msg"):
            skipped.append((name, "Outlook .msg format, save it as .eml instead"))
        elif looks_like_email(path):
            found.append(path)
        else:
            skipped.append((name, "doesn't look like an email"))
    return found, skipped


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = sys.argv[1:]
    use_vt = "--vt" in args
    args = [a for a in args if a != "--vt"]
    if len(args) != 1:
        print("Usage: python src/report.py <email file or folder> [--vt]")
        sys.exit(1)

    api_key = None
    if use_vt:
        api_key = vt_client.load_api_key()
        if not api_key:
            print("--vt needs VT_API_KEY=... in a .env file in the project folder.")
            sys.exit(1)

    target = args[0]
    if not os.path.exists(target):
        print(f"Can't find '{target}'. Check the name, or just point it at the whole folder.")
        sys.exit(1)

    if os.path.isdir(target):
        files, skipped = find_emails(target)
    else:
        files, skipped = [target], []

    results = []
    for path in files:
        try:
            results.append(score_email(path))
        except Exception as e:
            # One broken email shouldn't kill the whole scan
            skipped.append((os.path.basename(path), f"couldn't read it ({str(e)[:60]})"))

    if not results:
        print("No emails were analyzed.")
        sys.exit(1)

    if use_vt:
        cache = vt_client.load_cache()
        for r in results:
            try:
                add_vt_findings(r, cache, api_key)
            except vt_client.VTError as e:
                # Bad key or no quota left, so the rest would fail too. Finish without VT.
                print(c(f"  VirusTotal stopped: {e}", AMBER))
                break

    print()
    for r in sorted(results, key=lambda x: -x["score"]):
        print_card(r)
    md_path = save_markdown(build_markdown(results, skipped))
    print_summary(results, skipped, md_path)


if __name__ == "__main__":
    main()
