"""
VirusTotal lookups for domains and attachment hashes.

Uses only Python's standard library. Reads VT_API_KEY from the .env file in the
project folder. Free tier = 4 requests/min and 500/day, so every result is cached
in vt_cache.json and live calls are spaced 15 seconds apart.

We only ask VirusTotal what it already knows. Nothing is uploaded or visited.

Debug usage:
    python src/vt_client.py example.com
    python src/vt_client.py <sha256 hash>
"""
import os
import re
import sys
import json
import time
import urllib.request
import urllib.error

# ---------- settings you can tweak ----------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT, ".env")
CACHE_FILE = os.path.join(ROOT, "vt_cache.json")
BASE = "https://www.virustotal.com/api/v3"
RATE_DELAY = 15   # seconds between live calls (4/min on free tier)
TIMEOUT = 30      # seconds to wait for VirusTotal to answer

# Email content is attacker-controlled, so only clean-looking values go into the URL
DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

_last_call = 0.0


class VTError(Exception):
    """A lookup failed. fatal=True means stop trying (bad key or quota used up)."""

    def __init__(self, message, fatal=False):
        super().__init__(message)
        self.fatal = fatal


def load_api_key():
    """Read VT_API_KEY from .env by hand, so we don't need the python-dotenv package."""
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"].strip()
    if not os.path.exists(ENV_FILE):
        return None
    # utf-8-sig skips the hidden marker some Windows editors put at the start of a file
    with open(ENV_FILE, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() == "VT_API_KEY":
                return value.strip().strip('"').strip("'") or None
    return None


def load_cache():
    """Load saved lookups so the same thing is never looked up twice."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        # A broken cache just means we look things up again
        return {}


def save_cache(cache):
    """Write the cache back to disk."""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def is_cached(cache, endpoint):
    """True if this lookup is already saved and won't use any quota."""
    return endpoint in cache


def vt_get(endpoint, cache, api_key):
    """Ask VirusTotal about one thing, using the cache and the rate limit."""
    global _last_call
    if endpoint in cache:
        return cache[endpoint]

    wait = RATE_DELAY - (time.time() - _last_call)
    if _last_call and wait > 0:
        time.sleep(wait)

    req = urllib.request.Request(f"{BASE}/{endpoint}",
                                 headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.load(resp)
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        result = {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {"status": "not_found"}
        elif e.code in (401, 403):
            raise VTError("VirusTotal rejected the API key, check VT_API_KEY in .env", fatal=True)
        elif e.code == 429:
            raise VTError("VirusTotal quota used up (4 per minute, 500 per day), try again later", fatal=True)
        else:
            raise VTError(f"VirusTotal error {e.code}")
    except (urllib.error.URLError, TimeoutError) as e:
        raise VTError(f"couldn't reach VirusTotal ({e})")
    except (ValueError, KeyError):
        raise VTError("VirusTotal sent back something unexpected")
    finally:
        _last_call = time.time()

    cache[endpoint] = result
    save_cache(cache)
    return result


def domain_endpoint(domain):
    """Build the lookup path for a domain, or None if it doesn't look like a real domain."""
    domain = domain.lower().strip().strip(".")
    return f"domains/{domain}" if DOMAIN_RE.match(domain) else None


def file_endpoint(sha256):
    """Build the lookup path for an attachment hash, or None if it isn't a SHA256."""
    sha256 = sha256.lower().strip()
    return f"files/{sha256}" if SHA256_RE.match(sha256) else None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python src/vt_client.py <domain or sha256>")
        sys.exit(1)
    key = load_api_key()
    if not key:
        sys.exit("Missing VT_API_KEY in .env")
    value = sys.argv[1]
    endpoint = file_endpoint(value) or domain_endpoint(value)
    if not endpoint:
        sys.exit("That doesn't look like a domain or a SHA256 hash.")
    try:
        print(json.dumps(vt_get(endpoint, load_cache(), key), indent=2))
    except VTError as e:
        sys.exit(str(e))
