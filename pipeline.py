import requests
import json
import os
import csv
import io
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# ─────────────────────────────────────────
# 1. COLLECTOR
# ─────────────────────────────────────────

def collect_malwarebazaar():
    print("📡 Collecting from MalwareBazaar...")
    try:
        r = requests.get("https://bazaar.abuse.ch/export/csv/recent/", timeout=15)
        iocs = []
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        for line in lines:
            reader = csv.reader(io.StringIO(line))
            for parts in reader:
                if len(parts) < 9:
                    continue
                parts = [p.strip().strip('"').strip() for p in parts]
                sha256 = parts[1]
                if len(sha256) != 64:
                    continue
                family = parts[8]
                if family in ["n/a", "", "None"]:
                    family = "Unknown"
                iocs.append({
                    "value":         sha256,
                    "type":          "hash",
                    "source":        "MalwareBazaar",
                    "source_url":    "https://bazaar.abuse.ch",
                    "family":        family,
                    "first_seen":    parts[0],
                    "last_seen":     parts[0],
                    "geo":           None,
                    "file_type":     parts[6],
                    "tags":          [],
                    "vt_detections": 0,
                    "vt_total":      0,
                })
            if len(iocs) >= 100:
                break
        print(f"   ✓ {len(iocs)} hashes collected")
        return iocs
    except Exception as e:
        print(f"   ✗ MalwareBazaar error: {e}")
        return []


def collect_urlhaus():
    print("📡 Collecting from URLhaus...")
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15)
        iocs = []
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        for line in lines:
            reader = csv.reader(io.StringIO(line))
            for parts in reader:
                if len(parts) < 6:
                    continue
                parts = [p.strip().strip('"').strip() for p in parts]
                url = parts[2]
                if not url.startswith("http"):
                    continue
                threat = parts[5] if len(parts) > 5 else ""
                tags   = parts[6] if len(parts) > 6 else ""
                family = "Unknown"
                if tags:
                    tag_list = [t.strip() for t in tags.split(",")]
                    known = [t for t in tag_list if t not in
                             ["32-bit", "64-bit", "elf", "exe", "mips",
                              "arm", "mozi", "n/a", ""] and len(t) > 2]
                    if known:
                        family = known[0].capitalize()
                    elif threat and threat != "malware_download":
                        family = threat.capitalize()
                iocs.append({
                    "value":         url,
                    "type":          "url",
                    "source":        "URLhaus",
                    "source_url":    "https://urlhaus.abuse.ch",
                    "family":        family,
                    "first_seen":    parts[1],
                    "last_seen":     parts[1],
                    "geo":           None,
                    "file_type":     None,
                    "tags":          tags.split(",") if tags else [],
                    "vt_detections": 0,
                    "vt_total":      0,
                })
            if len(iocs) >= 100:
                break
        print(f"   ✓ {len(iocs)} URLs collected")
        return iocs
    except Exception as e:
        print(f"   ✗ URLhaus error: {e}")
        return []


def collect_feodo():
    print("📡 Collecting from Feodo Tracker...")
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=15)
        data = r.json()
        iocs = []
        for item in data[:80]:
            iocs.append({
                "value":         item.get("ip_address", ""),
                "type":          "ip",
                "source":        "Feodo Tracker",
                "source_url":    "https://feodotracker.abuse.ch",
                "family":        item.get("malware") or "Unknown",
                "first_seen":    item.get("first_seen"),
                "last_seen":     item.get("last_seen"),
                "geo":           item.get("country"),
                "file_type":     None,
                "tags":          [],
                "vt_detections": 0,
                "vt_total":      0,
            })
        print(f"   ✓ {len(iocs)} IPs collected")
        return iocs
    except Exception as e:
        print(f"   ✗ Feodo error: {e}")
        return []


# ─────────────────────────────────────────
# 2. ENRICHER — VirusTotal
# ─────────────────────────────────────────

def enrich_with_virustotal(iocs, limit=10):
    if not VT_API_KEY:
        print("⚠  No VT API key — skipping VT enrichment")
        return iocs

    print(f"🔍 Enriching top {limit} IOCs with VirusTotal...")
    endpoints = {
        "hash":   "files",
        "ip":     "ip_addresses",
        "url":    "urls",
        "domain": "domains"
    }
    for i, ioc in enumerate(iocs[:limit]):
        try:
            ep = endpoints.get(ioc["type"])
            if not ep:
                continue
            r = requests.get(
                f"https://www.virustotal.com/api/v3/{ep}/{ioc['value']}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10)
            data = r.json()
            stats = (data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {}))
            if stats:
                ioc["vt_detections"] = stats.get("malicious", 0)
                ioc["vt_total"]      = sum(stats.values())
            print(f"   ✓ [{i+1}/{limit}] {str(ioc['value'])[:40]}...")
        except Exception as e:
            print(f"   ✗ VT error: {e}")
    return iocs


# ─────────────────────────────────────────
# 3. SCORER
# ─────────────────────────────────────────

def score_ioc(ioc):
    score = 0
    reasons = []
    family = ioc["family"]

    # Source fiable
    source_scores = {
        "MalwareBazaar": 35,
        "Feodo Tracker": 40,
        "URLhaus":        30,
    }
    pts = source_scores.get(ioc["source"], 10)
    score += pts
    reasons.append(f"Trusted source ({ioc['source']}): +{pts}")

    # Famille connue
    if family and family not in ["Unknown", "malware_download", "n/a", ""]:
        score += 25
        reasons.append(f"Known malware family ({family}): +25")

    # Sample confirmé dans MalwareBazaar avec famille
    if ioc["source"] == "MalwareBazaar" and family not in ["Unknown", "n/a", ""]:
        score += 10
        reasons.append("Confirmed malware sample in database: +10")

    # IP botnet C2 confirmée
    if ioc["source"] == "Feodo Tracker":
        score += 10
        reasons.append("Active botnet C2 IP: +10")

    # Détections VirusTotal
    vt = ioc.get("vt_detections", 0)
    if vt > 30:
        score += 30
        reasons.append(f"VT very high detections ({vt}): +30")
    elif vt > 10:
        score += 20
        reasons.append(f"VT high detections ({vt}): +20")
    elif vt > 3:
        score += 10
        reasons.append(f"VT medium detections ({vt}): +10")

    # Géo à risque
    high_risk = ["RU", "CN", "KP", "IR", "NG", "UA", "BR"]
    if ioc.get("geo") in high_risk:
        score += 15
        reasons.append(f"High-risk country ({ioc['geo']}): +15")

    ioc["score"]    = min(score, 100)
    ioc["severity"] = get_severity(ioc["score"])
    ioc["reasons"]  = reasons
    return ioc


def get_severity(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────
# 4. NOISE FILTER
# ─────────────────────────────────────────

def filter_noise(iocs):
    clean = []
    noise = []

    for ioc in iocs:
        flags = []
        val = str(ioc.get("value") or "")

        # Hash invalide
        if ioc["type"] == "hash" and len(val) != 64:
            flags.append("Invalid SHA256 hash")

        # Valeur vide
        if not val or val == "None":
            flags.append("Empty IOC value")

        # IP privée
        if ioc["type"] == "ip":
            if (val.startswith("192.168.") or val.startswith("10.") or
                    val.startswith("127.") or val.startswith("172.16.")):
                flags.append("Private/local IP address")

        # Score trop bas
        if ioc["score"] < 25:
            flags.append("Score too low — likely benign")

        if flags:
            ioc["noise_flags"] = flags
            noise.append(ioc)
        else:
            ioc["noise_flags"] = []
            clean.append(ioc)

    return clean, noise


# ─────────────────────────────────────────
# 5. POISON DETECTOR
# ─────────────────────────────────────────

def detect_poisoning(iocs):
    poisoned = []

    for ioc in iocs:
        flags = []

        # Score élevé mais famille inconnue
        if ioc["score"] >= 70 and ioc["family"] in ["Unknown", "n/a", ""]:
            flags.append("High score but unknown family — needs verification")

        # Score max sans confirmation VT
        if (ioc["score"] >= 80 and
                ioc.get("vt_detections", 0) == 0 and
                ioc.get("vt_total", 0) == 0):
            flags.append("High score with zero VT confirmation — possible poisoning")

        if flags:
            ioc["poison_flags"] = flags
            poisoned.append(ioc)
        else:
            ioc["poison_flags"] = []

    return iocs, poisoned


# ─────────────────────────────────────────
# 6. REPORTER
# ─────────────────────────────────────────

def generate_report(all_iocs, clean_iocs, noise_iocs, poisoned_iocs):
    now = datetime.utcnow()

    severity_counts = Counter(ioc["severity"] for ioc in clean_iocs)
    family_counts   = Counter(
        ioc["family"] for ioc in clean_iocs
        if ioc["family"] not in ["Unknown", "n/a", ""]
    )
    geo_counts    = Counter(
        ioc["geo"] for ioc in clean_iocs
        if ioc.get("geo") and len(str(ioc["geo"])) == 2
    )
    source_counts = Counter(ioc["source"] for ioc in all_iocs)

    report = {
        "report_id":    f"TI-{now.strftime('%Y%m%d%H%M%S')}",
        "generated_at": now.isoformat() + "Z",
        "pipeline":     "CyberHorizon TI Pipeline v2.0",

        "summary": {
            "total_collected":         len(all_iocs),
            "total_clean":             len(clean_iocs),
            "total_noise_filtered":    len(noise_iocs),
            "noise_ratio_pct":         round(len(noise_iocs) / max(len(all_iocs), 1) * 100, 1),
            "total_poisoning_flagged": len(poisoned_iocs),
            "sources_used":            list(source_counts.keys()),
            "severity_breakdown":      dict(severity_counts),
        },

        "top_malware_families": [
            {"family": f, "count": c}
            for f, c in family_counts.most_common(10)
        ],

        "top_countries": [
            {"country": g, "count": c}
            for g, c in geo_counts.most_common(10)
        ],

        "sources_breakdown": dict(source_counts),

        "critical_iocs": [
            _format_ioc(ioc) for ioc in clean_iocs
            if ioc["severity"] in ["CRITICAL", "HIGH"]
        ][:50],

        "noise_filtered": [
            {"value": ioc["value"], "type": ioc["type"],
             "reason": ioc["noise_flags"]}
            for ioc in noise_iocs
        ][:30],

        "poisoning_flagged": [
            {"value": ioc["value"], "type": ioc["type"],
             "flags": ioc["poison_flags"], "score": ioc["score"]}
            for ioc in poisoned_iocs
        ],

        "soc_recommendations": _get_soc_recommendations(
            severity_counts, len(poisoned_iocs)),
    }

    return report


def _format_ioc(ioc):
    return {
        "value":         ioc["value"],
        "type":          ioc["type"],
        "source":        ioc["source"],
        "source_url":    ioc["source_url"],
        "family":        ioc["family"],
        "geo":           ioc.get("geo"),
        "first_seen":    ioc.get("first_seen"),
        "last_seen":     ioc.get("last_seen"),
        "score":         ioc["score"],
        "severity":      ioc["severity"],
        "reasons":       ioc["reasons"],
        "vt_detections": ioc.get("vt_detections", 0),
        "poison_flags":  ioc.get("poison_flags", []),
    }


def _get_soc_recommendations(severity_counts, nb_poisoned):
    actions = []
    if severity_counts.get("CRITICAL", 0) > 0:
        actions.append(
            f"URGENT: Block {severity_counts['CRITICAL']} CRITICAL IOCs on firewall/EDR immediately")
    if severity_counts.get("HIGH", 0) > 0:
        actions.append(
            f"ALERT: {severity_counts['HIGH']} HIGH IOCs — assign to Tier 2 analyst")
    if severity_counts.get("MEDIUM", 0) > 0:
        actions.append(
            f"MONITOR: {severity_counts['MEDIUM']} MEDIUM IOCs — add to watchlist")
    if nb_poisoned > 0:
        actions.append(
            f"WARNING: {nb_poisoned} IOCs flagged for poisoning — manual verification required")
    actions.append("Update SIEM rules with new CRITICAL/HIGH IOCs")
    actions.append("Cross-reference families with MITRE ATT&CK framework")
    actions.append("Share confirmed IOCs via STIX/TAXII feed")
    return actions


def print_summary(report):
    s = report["summary"]
    print(f"\n{'='*55}")
    print(f"  CYBERHORIZON TI PIPELINE — REPORT SUMMARY")
    print(f"  {report['generated_at']}")
    print(f"{'='*55}")
    print(f"  IOCs Collected      : {s['total_collected']}")
    print(f"  IOCs Clean          : {s['total_clean']}")
    print(f"  Noise Filtered      : {s['total_noise_filtered']} ({s['noise_ratio_pct']}%)")
    print(f"  Poisoning Flagged   : {s['total_poisoning_flagged']}")
    print(f"  Sources Used        : {', '.join(s['sources_used'])}")
    print(f"\n  SEVERITY BREAKDOWN:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = s["severity_breakdown"].get(sev, 0)
        bar = "█" * (count // 5)
        print(f"    {sev:<10} : {count:>4}  {bar}")
    print(f"\n  TOP MALWARE FAMILIES:")
    for item in report["top_malware_families"][:5]:
        print(f"    {item['family']:<22} : {item['count']}")
    print(f"\n  TOP COUNTRIES:")
    for item in report["top_countries"][:5]:
        print(f"    {item['country']:<10} : {item['count']}")
    print(f"\n  SOC RECOMMENDATIONS:")
    for action in report["soc_recommendations"]:
        print(f"    → {action}")
    print(f"{'='*55}\n")


# ─────────────────────────────────────────
# 7. MAIN
# ─────────────────────────────────────────

def run_pipeline():
    print("\n" + "="*55)
    print("  CYBERHORIZON TI PIPELINE v2.0")
    print("  Starting full OSINT collection...")
    print("="*55 + "\n")

    # 1. Collecte
    all_iocs = []
    all_iocs += collect_malwarebazaar()
    all_iocs += collect_urlhaus()
    all_iocs += collect_feodo()
    print(f"\n✓ Total collected: {len(all_iocs)} IOCs\n")

    # 2. Enrichissement VT
    all_iocs = enrich_with_virustotal(all_iocs, limit=10)

    # 3. Scoring
    print("📊 Scoring all IOCs...")
    all_iocs = [score_ioc(ioc) for ioc in all_iocs]

    # 4. Filtrage bruit
    print("🧹 Filtering noise...")
    clean_iocs, noise_iocs = filter_noise(all_iocs)
    print(f"   ✓ Clean: {len(clean_iocs)} | Noise: {len(noise_iocs)}")

    # 5. Poison detection
    print("🛡️  Detecting poisoning...")
    clean_iocs, poisoned_iocs = detect_poisoning(clean_iocs)
    print(f"   ✓ Poisoning flagged: {len(poisoned_iocs)}")

    # 6. Rapport
    print("📋 Generating report...")
    report = generate_report(all_iocs, clean_iocs, noise_iocs, poisoned_iocs)

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/TI_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print_summary(report)
    print(f"✅ Full report saved: {filename}\n")


if __name__ == "__main__":
    run_pipeline()