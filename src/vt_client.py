"""
Phase 2: VirusTotal lookups for URLs, domains and attachment hashes.
Usage: python vt_client.py samples/suspicious.eml
Needs VT_API_KEY in a .env file. Free tier = 4 requests/min, 500/day.
"""
import os
import sys
import json
import time
import base64
import requests
from dotenv import load_dotenv
from parser import analyze, domain_of

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
BASE = "https://www.virustotal.com/api/v3"
CACHE_FILE = "vt_cache.json"
RATE_DELAY = 15  # seconds between live calls (4/min on free tier)

_last_call = 0.0


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def vt_get(endpoint, cache):
    """GET from VT with caching + rate limiting. Returns stats dict or None."""
    global _last_call
    if endpoint in cache:
        return cache[endpoint]

    wait = RATE_DELAY - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)

    resp = requests.get(f"{BASE}/{endpoint}", headers={"x-apikey": API_KEY}, timeout=30)
    _last_call = time.time()

    if resp.status_code == 404:
        result = {"status": "not_found"}
    elif resp.status_code == 200:
        stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
        result = {"status": "found", **stats}
    else:
        print(f"[!] VT error {resp.status_code} on {endpoint}")
        return None

    cache[endpoint] = result
    save_cache(cache)
    return result


def url_id(url):
    # VT identifies URLs by unpadded base64url of the URL
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_email(path):
    if not API_KEY:
        sys.exit("Missing VT_API_KEY in .env")

    report = analyze(path)
    cache = load_cache()
    vt = {"urls": {}, "domains": {}, "attachments": {}}

    for url in report["urls"]:
        vt["urls"][url] = vt_get(f"urls/{url_id(url)}", cache)

    domains = {domain_of(report["headers"]["from_addr"]),
               domain_of(report["headers"]["reply_to"])} - {""}
    for d in domains:
        vt["domains"][d] = vt_get(f"domains/{d}", cache)

    for att in report["attachments"]:
        vt["attachments"][att["filename"]] = vt_get(f"files/{att['sha256']}", cache)

    # Add VT hits to red flags
    for kind, results in vt.items():
        for item, r in results.items():
            if r and r.get("malicious", 0) > 0:
                report["red_flags"].append(
                    f"VT: {kind[:-1]} {item} flagged malicious by {r['malicious']} vendors")

    report["virustotal"] = vt
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_client.py <email.eml>")
        sys.exit(1)
    print(json.dumps(check_email(sys.argv[1]), indent=2))
