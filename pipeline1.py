import requests
import json
import os
import csv
import io
import time
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY      = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_KEY")

# ─────────────────────────────────────────
# MITRE ATT&CK MAPPING (amélioration #5)
# ─────────────────────────────────────────

MITRE_MAP = {
    "Emotet":          ["T1566.001 - Spearphishing Attachment", "T1071.001 - Web Protocols"],
    "Qakbot":          ["T1055 - Process Injection",            "T1547 - Boot Autostart"],
    "QakBot":          ["T1055 - Process Injection",            "T1547 - Boot Autostart"],
    "Redline":         ["T1056 - Input Capture",                "T1041 - Exfiltration Over C2"],
    "AgentTesla":      ["T1056 - Input Capture",                "T1041 - Exfiltration Over C2"],
    "Cobalt Strike":   ["T1059 - Command Scripting",            "T1105 - Ingress Tool Transfer"],
    "Icedid":          ["T1566.001 - Spearphishing Attachment", "T1027 - Obfuscated Files"],
    "IcedID":          ["T1566.001 - Spearphishing Attachment", "T1027 - Obfuscated Files"],
    "Lokibot":         ["T1056 - Input Capture",                "T1041 - Exfiltration Over C2"],
    "Formbook":        ["T1056 - Input Capture",                "T1113 - Screen Capture"],
    "Njrat":           ["T1021 - Remote Services",              "T1059 - Command Scripting"],
    "Asyncrat":        ["T1021 - Remote Services",              "T1140 - Deobfuscate Files"],
    "Nanocore":        ["T1021 - Remote Services",              "T1113 - Screen Capture"],
    "Mirai":           ["T1498 - Network DoS",                  "T1078 - Valid Accounts"],
    "Trickbot":        ["T1566.001 - Spearphishing Attachment", "T1055 - Process Injection"],
    "Dridex":          ["T1566.001 - Spearphishing Attachment", "T1071.001 - Web Protocols"],
    "Ursnif":          ["T1566.001 - Spearphishing Attachment", "T1056 - Input Capture"],
}


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
                    "value":              sha256,
                    "type":               "hash",
                    "source":             "MalwareBazaar",
                    "source_url":         "https://bazaar.abuse.ch",
                    "family":             family,
                    "first_seen":         parts[0],
                    "last_seen":          parts[0],
                    "geo":                None,
                    "file_type":          parts[6],
                    "tags":               [],
                    "vt_detections":      0,
                    "vt_total":           0,
                    "abuse_confidence":   0,
                    "mitre":              [],
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
                    "value":              url,
                    "type":               "url",
                    "source":             "URLhaus",
                    "source_url":         "https://urlhaus.abuse.ch",
                    "family":             family,
                    "first_seen":         parts[1],
                    "last_seen":          parts[1],
                    "geo":                None,
                    "file_type":          None,
                    "tags":               tags.split(",") if tags else [],
                    "vt_detections":      0,
                    "vt_total":           0,
                    "abuse_confidence":   0,
                    "mitre":              [],
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
                "value":              item.get("ip_address", ""),
                "type":               "ip",
                "source":             "Feodo Tracker",
                "source_url":         "https://feodotracker.abuse.ch",
                "family":             item.get("malware") or "Unknown",
                "first_seen":         item.get("first_seen"),
                "last_seen":          item.get("last_seen"),
                "geo":                item.get("country"),
                "file_type":          None,
                "tags":               [],
                "vt_detections":      0,
                "vt_total":           0,
                "abuse_confidence":   0,
                "mitre":              [],
            })
        print(f"   ✓ {len(iocs)} IPs collected")
        return iocs
    except Exception as e:
        print(f"   ✗ Feodo error: {e}")
        return []


# ─────────────────────────────────────────
# AMÉLIORATION #6 — Déduplication
# ─────────────────────────────────────────

def deduplicate(iocs):
    seen = set()
    unique = []
    for ioc in iocs:
        val = str(ioc.get("value", "")).strip()
        if val and val not in seen:
            seen.add(val)
            unique.append(ioc)
    removed = len(iocs) - len(unique)
    if removed:
        print(f"   ✓ Déduplication : {removed} doublons supprimés → {len(unique)} IOCs uniques")
    return unique


# ─────────────────────────────────────────
# 2. ENRICHER — VirusTotal (amélioration #4 : rate-limiter)
# ─────────────────────────────────────────

def enrich_with_virustotal(iocs, limit=20):
    """
    Enrichit les IOCs via VirusTotal.
    Amélioration #4 : rate-limiter intégré (15s entre requêtes = 4 req/min)
    pour respecter la limite de l'API gratuite et enrichir plus d'IOCs.
    """
    if not VT_API_KEY:
        print("⚠  No VT API key — skipping VT enrichment")
        return iocs

    print(f"🔍 Enriching top {limit} IOCs with VirusTotal (rate-limited)...")
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
            print(f"   ✓ [{i+1}/{limit}] {str(ioc['value'])[:45]}...")
            # Rate-limiter : 15s entre chaque requête (4 req/min sur VT gratuit)
            if i < limit - 1:
                time.sleep(15)
        except Exception as e:
            print(f"   ✗ VT error: {e}")
    return iocs


# ─────────────────────────────────────────
# AMÉLIORATION #1 — AbuseIPDB enrichment
# ─────────────────────────────────────────

def enrich_with_abuseipdb(iocs):
    """
    Enrichit les IOCs de type IP avec AbuseIPDB.
    Ajoute le champ abuse_confidence (0-100) à chaque IP.
    """
    if not ABUSEIPDB_KEY:
        print("⚠  No AbuseIPDB key — skipping AbuseIPDB enrichment")
        return iocs

    ip_iocs = [ioc for ioc in iocs if ioc["type"] == "ip"]
    print(f"🔍 Enriching {len(ip_iocs)} IPs with AbuseIPDB...")
    for i, ioc in enumerate(ip_iocs):
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ioc["value"], "maxAgeInDays": 90},
                timeout=10
            )
            data = r.json().get("data", {})
            ioc["abuse_confidence"] = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode")
            if country and not ioc.get("geo"):
                ioc["geo"] = country
            print(f"   ✓ [{i+1}/{len(ip_iocs)}] {ioc['value']} → confidence: {ioc['abuse_confidence']}%")
            time.sleep(1)  # AbuseIPDB : 1000 req/jour sur plan gratuit
        except Exception as e:
            print(f"   ✗ AbuseIPDB error for {ioc['value']}: {e}")
    return iocs


# ─────────────────────────────────────────
# 3. SCORER (amélioration #1 : score AbuseIPDB intégré)
# ─────────────────────────────────────────

def score_ioc(ioc):
    score = 0
    reasons = []
    family = ioc.get("family", "Unknown")

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

    # Amélioration #1 — Score AbuseIPDB
    abuse = ioc.get("abuse_confidence", 0)
    if abuse >= 80:
        score += 20
        reasons.append(f"AbuseIPDB very high confidence ({abuse}%): +20")
    elif abuse >= 50:
        score += 12
        reasons.append(f"AbuseIPDB high confidence ({abuse}%): +12")
    elif abuse >= 20:
        score += 5
        reasons.append(f"AbuseIPDB medium confidence ({abuse}%): +5")

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
# AMÉLIORATION #5 — Mapping MITRE ATT&CK
# ─────────────────────────────────────────

def map_mitre(iocs):
    """Enrichit chaque IOC avec les techniques MITRE ATT&CK correspondant à sa famille."""
    mapped = 0
    for ioc in iocs:
        family = ioc.get("family", "")
        techniques = MITRE_MAP.get(family, [])
        ioc["mitre"] = techniques
        if techniques:
            mapped += 1
    print(f"   ✓ MITRE ATT&CK : {mapped} IOCs mappés sur {len(iocs)}")
    return iocs


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
# 5. POISON DETECTOR (amélioration #4 : exclure Feodo Tracker)
# ─────────────────────────────────────────

def detect_poisoning(iocs):
    """
    Amélioration #4 : les IPs Feodo Tracker sont exclues du check de poisoning
    car elles sont des C2 confirmés et ont légitimement vt_total=0.
    """
    poisoned = []

    for ioc in iocs:
        flags = []

        # Score élevé mais famille inconnue
        if ioc["score"] >= 70 and ioc["family"] in ["Unknown", "n/a", ""]:
            flags.append("High score but unknown family — needs verification")

        # Score max sans confirmation VT — sauf si source Feodo (C2 confirmé)
        if (ioc["score"] >= 80 and
                ioc.get("vt_detections", 0) == 0 and
                ioc.get("vt_total", 0) == 0 and
                ioc["source"] != "Feodo Tracker"):  # ← fix
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

    # Collecte toutes les techniques MITRE détectées
    all_mitre = []
    for ioc in clean_iocs:
        all_mitre.extend(ioc.get("mitre", []))
    mitre_counts = Counter(all_mitre)

    report = {
        "report_id":    f"TI-{now.strftime('%Y%m%d%H%M%S')}",
        "generated_at": now.isoformat() + "Z",
        "pipeline":     "CyberHorizon TI Pipeline v3.0",

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

        # Amélioration #5 — MITRE dans le rapport
        "mitre_techniques_observed": [
            {"technique": t, "count": c}
            for t, c in mitre_counts.most_common(15)
        ],

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
        "value":            ioc["value"],
        "type":             ioc["type"],
        "source":           ioc["source"],
        "source_url":       ioc["source_url"],
        "family":           ioc["family"],
        "geo":              ioc.get("geo"),
        "first_seen":       ioc.get("first_seen"),
        "last_seen":        ioc.get("last_seen"),
        "score":            ioc["score"],
        "severity":         ioc["severity"],
        "reasons":          ioc["reasons"],
        "vt_detections":    ioc.get("vt_detections", 0),
        "abuse_confidence": ioc.get("abuse_confidence", 0),
        "mitre":            ioc.get("mitre", []),
        "poison_flags":     ioc.get("poison_flags", []),
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
    actions.append("Cross-reference families with MITRE ATT&CK framework (see mitre_techniques_observed)")
    actions.append("Share confirmed IOCs via STIX/TAXII feed (see STIX export)")
    return actions


def print_summary(report):
    s = report["summary"]
    print(f"\n{'='*60}")
    print(f"  CYBERHORIZON TI PIPELINE v3.0 — REPORT SUMMARY")
    print(f"  {report['generated_at']}")
    print(f"{'='*60}")
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
    print(f"\n  TOP MITRE ATT&CK TECHNIQUES:")
    for item in report["mitre_techniques_observed"][:5]:
        print(f"    {item['technique']:<45} : {item['count']}")
    print(f"\n  TOP COUNTRIES:")
    for item in report["top_countries"][:5]:
        print(f"    {item['country']:<10} : {item['count']}")
    print(f"\n  SOC RECOMMENDATIONS:")
    for action in report["soc_recommendations"]:
        print(f"    → {action}")
    print(f"{'='*60}\n")


# ─────────────────────────────────────────
# AMÉLIORATION #3 — Export STIX 2.1
# ─────────────────────────────────────────

def export_stix(clean_iocs, output_dir="reports"):
    """
    Génère un bundle STIX 2.1 avec les IOCs CRITICAL et HIGH.
    Format consommable par les SIEMs (Splunk, QRadar) et plateformes TAXII.
    Nécessite : pip install stix2
    """
    try:
        from stix2 import Indicator, Bundle, Malware, Relationship
    except ImportError:
        print("⚠  stix2 non installé — pip install stix2")
        return None

    indicators = []
    malwares   = {}

    for ioc in clean_iocs:
        if ioc["severity"] not in ["CRITICAL", "HIGH"]:
            continue

        # Créer l'objet Malware si la famille est connue
        family = ioc.get("family", "Unknown")
        if family not in ["Unknown", "n/a", ""] and family not in malwares:
            malwares[family] = Malware(
                name=family,
                is_family=True,
                description=f"Malware family detected by CyberHorizon TI Pipeline"
            )

        # Créer le pattern STIX selon le type d'IOC
        try:
            if ioc["type"] == "hash":
                pattern = f"[file:hashes.'SHA-256' = '{ioc['value']}']"
            elif ioc["type"] == "ip":
                pattern = f"[ipv4-addr:value = '{ioc['value']}']"
            elif ioc["type"] == "url":
                url_escaped = ioc['value'].replace("'", "\\'")
                pattern = f"[url:value = '{url_escaped}']"
            elif ioc["type"] == "domain":
                pattern = f"[domain-name:value = '{ioc['value']}']"
            else:
                continue

            indicator = Indicator(
                name=f"{family} - {ioc['type'].upper()}",
                description=(
                    f"Source: {ioc['source']} | Score: {ioc['score']} | "
                    f"Severity: {ioc['severity']} | "
                    f"MITRE: {', '.join(ioc.get('mitre', ['N/A']))}"
                ),
                pattern=pattern,
                pattern_type="stix",
                labels=["malicious-activity"],
                confidence=ioc["score"],
            )
            indicators.append(indicator)
        except Exception as e:
            print(f"   ✗ STIX indicator error: {e}")
            continue

    # Construire les relations Indicator → Malware
    relationships = []
    for ind in indicators:
        family_name = ind.name.split(" - ")[0]
        if family_name in malwares:
            rel = Relationship(
                relationship_type="indicates",
                source_ref=ind.id,
                target_ref=malwares[family_name].id
            )
            relationships.append(rel)

    all_objects = indicators + list(malwares.values()) + relationships
    if not all_objects:
        print("⚠  Aucun IOC éligible pour l'export STIX")
        return None

    bundle = Bundle(objects=all_objects)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/TI_stix_{ts}.json"
    os.makedirs(output_dir, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))

    print(f"   ✓ STIX bundle : {len(indicators)} indicators, {len(malwares)} malware objects → {filename}")
    return filename


# ─────────────────────────────────────────
# AMÉLIORATION #2 — Rapport HTML
# ─────────────────────────────────────────

def generate_html_report(report, output_dir="reports"):
    """
    Génère un rapport HTML interactif avec tableau des IOCs critiques,
    graphiques de sévérité, familles, pays et recommandations SOC colorées.
    """
    s   = report["summary"]
    now = report["generated_at"]

    def sev_badge(sev):
        colors = {
            "CRITICAL": ("FCEBEB", "A32D2D"),
            "HIGH":     ("FAEEDA", "633806"),
            "MEDIUM":   ("E6F1FB", "0C447C"),
            "LOW":      ("EAF3DE", "27500A"),
        }
        bg, fg = colors.get(sev, ("F1EFE8", "2C2C2A"))
        return f'<span style="background:#{bg};color:#{fg};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{sev}</span>'

    # Lignes du tableau IOCs critiques
    ioc_rows = ""
    for ioc in report["critical_iocs"][:30]:
        val = str(ioc["value"])
        val_display = val[:52] + "…" if len(val) > 52 else val
        mitre_str = ", ".join(ioc.get("mitre", [])) or "—"
        ioc_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{val_display}</td>
          <td><span style="background:#E6F1FB;color:#0C447C;padding:1px 6px;border-radius:3px;font-size:11px">{ioc['type']}</span></td>
          <td style="font-size:12px">{ioc['source']}</td>
          <td style="font-size:12px">{ioc['family']}</td>
          <td style="font-size:12px">{ioc.get('geo') or '—'}</td>
          <td style="font-weight:600;font-size:12px">{ioc['score']}</td>
          <td>{sev_badge(ioc['severity'])}</td>
          <td style="font-size:10px;color:#5F5E5A;max-width:180px">{mitre_str[:60]}</td>
          <td style="font-size:11px">{ioc.get('vt_detections', 0)}/{ioc.get('vt_total', 0) or '—'}</td>
          <td style="font-size:11px">{ioc.get('abuse_confidence', 0)}%</td>
        </tr>"""

    # Lignes recommandations SOC
    rec_colors = {
        "URGENT":   ("#FCEBEB", "#A32D2D"),
        "ALERT":    ("#FAEEDA", "#633806"),
        "MONITOR":  ("#E6F1FB", "#0C447C"),
        "WARNING":  ("#FAECE7", "#712B13"),
        "Update":   ("#E1F5EE", "#085041"),
        "Cross-ref":("#E1F5EE", "#085041"),
        "Share":    ("#E1F5EE", "#085041"),
    }
    rec_rows = ""
    for action in report["soc_recommendations"]:
        key  = action.split(":")[0].strip()
        bg, fg = rec_colors.get(key, ("#F1EFE8", "#2C2C2A"))
        rec_rows += f'<div style="background:{bg};color:{fg};padding:8px 14px;border-radius:6px;font-size:13px;margin-bottom:6px">{action}</div>'

    # Top familles
    family_rows = "".join(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
        f'<span style="font-size:13px;width:120px">{item["family"]}</span>'
        f'<div style="flex:1;height:8px;background:#F1EFE8;border-radius:4px;overflow:hidden">'
        f'<div style="width:{min(item["count"]*3,100)}%;height:100%;background:#534AB7;border-radius:4px"></div></div>'
        f'<span style="font-size:12px;color:#5F5E5A;min-width:20px">{item["count"]}</span></div>'
        for item in report["top_malware_families"][:8]
    )

    # Top MITRE
    mitre_rows = "".join(
        f'<div style="font-size:12px;padding:4px 0;border-bottom:1px solid #F1EFE8;display:flex;justify-content:space-between">'
        f'<span style="color:#3d3d3a">{item["technique"]}</span>'
        f'<span style="font-weight:600;color:#534AB7">{item["count"]}</span></div>'
        for item in report["mitre_techniques_observed"][:10]
    )

    # Compteurs sévérité pour JS chart
    sev_data = {k: s["severity_breakdown"].get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberHorizon TI Report — {report['report_id']}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #f5f4f0; color: #2c2c2a; padding: 32px 24px; }}
  h1   {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; }}
  h2   {{ font-size: 15px; font-weight: 600; margin-bottom: 14px; color: #3d3d3a; }}
  .meta {{ font-size: 12px; color: #888780; margin-bottom: 28px; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }}
  .card {{ background: #fff; border: 1px solid #e8e7e0; border-radius: 10px; padding: 18px 20px; }}
  .kpi  {{ background: #f5f4f0; border-radius: 8px; padding: 14px 16px; text-align: center; }}
  .kpi-label {{ font-size: 11px; color: #888780; margin-bottom: 4px; }}
  .kpi-val   {{ font-size: 24px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th  {{ background: #f5f4f0; padding: 8px 10px; text-align: left; font-size: 11px; color: #888780; font-weight: 600; border-bottom: 1px solid #e8e7e0; }}
  td  {{ padding: 7px 10px; border-bottom: 1px solid #f5f4f0; vertical-align: middle; }}
  tr:hover td {{ background: #fafaf8; }}
  footer {{ font-size: 11px; color: #888780; text-align: center; margin-top: 32px; }}
</style>
</head>
<body>

<h1>CyberHorizon TI Pipeline v3.0</h1>
<div class="meta">Rapport {report['report_id']} · Généré le {now} · Sources : {', '.join(s['sources_used'])}</div>

<div class="grid-4">
  <div class="kpi"><div class="kpi-label">IOCs collectés</div><div class="kpi-val">{s['total_collected']}</div></div>
  <div class="kpi"><div class="kpi-label">IOCs propres</div><div class="kpi-val" style="color:#3B6D11">{s['total_clean']}</div></div>
  <div class="kpi"><div class="kpi-label">Bruit filtré</div><div class="kpi-val" style="color:#854F0B">{s['total_noise_filtered']} <span style="font-size:14px">({s['noise_ratio_pct']}%)</span></div></div>
  <div class="kpi"><div class="kpi-label">Poisoning flagged</div><div class="kpi-val" style="color:#A32D2D">{s['total_poisoning_flagged']}</div></div>
</div>

<div class="grid-2">
  <div class="card">
    <h2>Répartition par sévérité</h2>
    <div style="position:relative;height:200px"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="card">
    <h2>Top familles de malware</h2>
    {family_rows}
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <h2>Techniques MITRE ATT&CK observées</h2>
    {mitre_rows if mitre_rows else '<p style="font-size:13px;color:#888">Aucune technique mappée</p>'}
  </div>
  <div class="card">
    <h2>Recommandations SOC</h2>
    {rec_rows}
  </div>
</div>

<div class="card" style="margin-bottom:20px">
  <h2>IOCs CRITICAL &amp; HIGH ({len(report['critical_iocs'])} au total — top 30 affichés)</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>Valeur</th><th>Type</th><th>Source</th><th>Famille</th>
      <th>Pays</th><th>Score</th><th>Sévérité</th>
      <th>MITRE ATT&CK</th><th>VT det/total</th><th>AbuseIPDB</th>
    </tr></thead>
    <tbody>{ioc_rows}</tbody>
  </table>
  </div>
</div>

<footer>CyberHorizon TI Pipeline v3.0 — OSINT public uniquement · MalwareBazaar · URLhaus · Feodo Tracker · VirusTotal · AbuseIPDB</footer>

<script>
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    datasets: [{{ data: [{sev_data['CRITICAL']}, {sev_data['HIGH']}, {sev_data['MEDIUM']}, {sev_data['LOW']}],
      backgroundColor: ['#E24B4A', '#BA7517', '#185FA5', '#3B6D11'],
      borderWidth: 0, hoverOffset: 4 }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'right', labels: {{ font: {{ size: 12 }}, padding: 12 }} }} }} }}
}});
</script>
</body>
</html>"""

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/TI_report_{ts}.html"
    os.makedirs(output_dir, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"   ✓ Rapport HTML généré → {filename}")
    return filename


# ─────────────────────────────────────────
# 7. MAIN
# ─────────────────────────────────────────

def run_pipeline():
    print("\n" + "="*60)
    print("  CYBERHORIZON TI PIPELINE v3.0")
    print("  Starting full OSINT collection...")
    print("="*60 + "\n")

    # 1. Collecte
    all_iocs = []
    all_iocs += collect_malwarebazaar()
    all_iocs += collect_urlhaus()
    all_iocs += collect_feodo()
    print(f"\n✓ Total collected: {len(all_iocs)} IOCs\n")

    # AMÉLIORATION #6 — Déduplication
    print("🧹 Deduplicating IOCs...")
    all_iocs = deduplicate(all_iocs)

    # 2. Enrichissement VT (rate-limité)
    all_iocs = enrich_with_virustotal(all_iocs, limit=20)

    # AMÉLIORATION #1 — AbuseIPDB
    all_iocs = enrich_with_abuseipdb(all_iocs)

    # 3. Scoring
    print("\n📊 Scoring all IOCs...")
    all_iocs = [score_ioc(ioc) for ioc in all_iocs]

    # AMÉLIORATION #5 — MITRE ATT&CK mapping
    print("🗺️  Mapping MITRE ATT&CK techniques...")
    all_iocs = map_mitre(all_iocs)

    # 4. Filtrage bruit
    print("🧹 Filtering noise...")
    clean_iocs, noise_iocs = filter_noise(all_iocs)
    print(f"   ✓ Clean: {len(clean_iocs)} | Noise: {len(noise_iocs)}")

    # 5. Poison detection (Feodo exclu)
    print("🛡️  Detecting poisoning...")
    clean_iocs, poisoned_iocs = detect_poisoning(clean_iocs)
    print(f"   ✓ Poisoning flagged: {len(poisoned_iocs)}")

    # 6. Rapport JSON
    print("📋 Generating reports...")
    report = generate_report(all_iocs, clean_iocs, noise_iocs, poisoned_iocs)

    os.makedirs("reports", exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_file = f"reports/TI_report_{ts}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"   ✓ JSON → {json_file}")

    # AMÉLIORATION #2 — Rapport HTML
    generate_html_report(report)

    # AMÉLIORATION #3 — Export STIX 2.1
    print("📦 Exporting STIX 2.1 bundle...")
    export_stix(clean_iocs)

    print_summary(report)
    print(f"✅ Pipeline v3.0 terminé.\n")


if __name__ == "__main__":
    run_pipeline()