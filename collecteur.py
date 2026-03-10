# collector.py
import os
import time
import json
import re
import sqlite3
from datetime import datetime
import requests
from dotenv import load_dotenv
import tldextract

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

DB_PATH = "data/iocs.db"

# -------------------------
# Regex validators (simple)
# -------------------------
RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RE_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
RE_MD5 = re.compile(r"^[A-Fa-f0-9]{32}$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")

def is_valid_ioc(ioc, ioc_type):
    if ioc_type == "ip":
        return bool(RE_IPV4.match(ioc))
    if ioc_type == "hash":
        return bool(RE_SHA256.match(ioc)) or bool(RE_MD5.match(ioc))
    if ioc_type == "domain":
        return bool(RE_DOMAIN.match(ioc)) or bool(tldextract.extract(ioc).domain)
    return False

# -------------------------
# DB helpers
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc TEXT,
        type TEXT,
        source TEXT,
        first_seen TEXT,
        raw JSON,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_ioc(ioc, ioc_type, source, raw):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO iocs (ioc, type, source, first_seen, raw, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ioc, ioc_type, source, datetime.utcnow().isoformat()+"Z", json.dumps(raw), datetime.utcnow().isoformat()+"Z"))
    conn.commit()
    conn.close()

# -------------------------
# VirusTotal (example: domain report)
# -------------------------
def vt_lookup_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 429:
        print("VT rate limited. sleeping 30s")
        time.sleep(30)
        return vt_lookup_domain(domain)
    else:
        print("VT error", r.status_code, r.text[:200])
        return None

# -------------------------
# AlienVault OTX (example: domain pulses / indicators)
# -------------------------
def otx_domain(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 429:
        print("OTX rate limited. sleeping 60s")
        time.sleep(60)
        return otx_domain(domain)
    else:
        print("OTX error", r.status_code)
        return None

# -------------------------
# AbuseIPDB (example: ip check)
# -------------------------
def abuseipdb_check(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 429:
        print("AbuseIPDB rate limited. sleeping 60s")
        time.sleep(60)
        return abuseipdb_check(ip)
    else:
        print("AbuseIPDB error", r.status_code)
        return None

# -------------------------
# GitHub code search (example: search for "api_key" in public code)
# -------------------------
def github_search_code(query, per_page=10):
    url = "https://api.github.com/search/code"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    params = {"q": query, "per_page": per_page}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 403:
        print("GitHub rate limit or permissions issue.", r.status_code, r.text[:200])
        return None
    else:
        print("GitHub error", r.status_code)
        return None

# -------------------------
# Small extractor examples
# -------------------------
def extract_domains_from_github_result(item):
    # item has repository info and path; we'll return repo html_url or file url
    return item.get("repository", {}).get("html_url")

# -------------------------
# Main demo flow
# -------------------------
def main():
    init_db()
    sample_domain = "example.com"
    print("VT lookup:", sample_domain)
    vt = vt_lookup_domain(sample_domain)
    if vt:
        save_ioc(sample_domain, "domain", "VirusTotal", vt)
        print("Saved VT domain report (truncated):", json.dumps(vt)[:400])

    print("OTX lookup:", sample_domain)
    o = otx_domain(sample_domain)
    if o:
        save_ioc(sample_domain, "domain", "OTX", o)
        print("Saved OTX report (truncated):", json.dumps(o)[:400])

    sample_ip = "8.8.8.8"
    print("AbuseIPDB check:", sample_ip)
    aip = abuseipdb_check(sample_ip)
    if aip:
        save_ioc(sample_ip, "ip", "AbuseIPDB", aip)
        print("Saved AbuseIPDB (truncated):", json.dumps(aip)[:400])

    print("GitHub search for 'api_key' in public code (demo)")
    gh = github_search_code("api_key in:file language:python")
    if gh and gh.get("items"):
        for item in gh["items"][:3]:
            repo = extract_domains_from_github_result(item)
            save_ioc(repo or item.get("html_url"), "url", "GitHub", item)
            print("Saved GitHub result:", repo or item.get("html_url"))

if __name__ == "__main__":
    main()
