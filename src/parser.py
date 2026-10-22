"""
Phase 1: Email parser for the Phishing Email Analyzer.
Usage: python parser.py samples/suspicious.eml
"""
import sys
import re
import hashlib
import json
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

URL_REGEX = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)


def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_headers(msg):
    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))
    return {
        "subject": msg.get("Subject", ""),
        "from_name": from_name,
        "from_addr": from_addr.lower(),
        "reply_to": reply_to.lower(),
        "return_path": return_path.lower(),
        "auth_results": msg.get("Authentication-Results", ""),
        "received_hops": len(msg.get_all("Received", []) or []),
    }


def get_body_and_urls(msg):
    text = ""
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                text += part.get_content() + "\n"
            except Exception:
                pass
    urls = sorted(set(URL_REGEX.findall(text)))
    return text, urls


def get_attachments(msg):
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return attachments


def domain_of(addr):
    return addr.split("@")[-1] if "@" in addr else ""


def red_flags(headers, urls):
    flags = []
    from_dom = domain_of(headers["from_addr"])
    if headers["reply_to"] and domain_of(headers["reply_to"]) != from_dom:
        flags.append("Reply-To domain differs from From domain")
    if headers["return_path"] and domain_of(headers["return_path"]) != from_dom:
        flags.append("Return-Path domain differs from From domain")
    auth = headers["auth_results"].lower()
    for check in ("spf", "dkim", "dmarc"):
        if f"{check}=fail" in auth or f"{check}=softfail" in auth:
            flags.append(f"{check.upper()} failed")
    for url in urls:
        if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
            flags.append(f"URL uses raw IP address: {url}")
    return flags


def analyze(path):
    msg = load_email(path)
    headers = get_headers(msg)
    _, urls = get_body_and_urls(msg)
    return {
        "file": path,
        "headers": headers,
        "urls": urls,
        "attachments": get_attachments(msg),
        "red_flags": red_flags(headers, urls),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parser.py <email.eml>")
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), indent=2))
