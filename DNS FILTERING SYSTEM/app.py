# app.py
import os
import re
import socket
import time
import math
import json
import requests
import csv
import smtplib
from io import StringIO
from email.message import EmailMessage
from collections import defaultdict
from difflib import SequenceMatcher
from datetime import datetime
from flask import Flask, render_template, request, jsonify, abort, Response

# optional imports
try:
    import whois as whois_mod
except Exception:
    whois_mod = None

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    geoip2 = None
    GEOIP_AVAILABLE = False

app = Flask(__name__)

# ---------- Config & state ----------------------------------------------
BLACKLIST = {"malicious.com", "bad-domain.org"}
ALLOWLIST = {"example.com"}

STATS_FILE = "dns_stats.json"
HISTORY_FILE = "history.json"
PASSIVE_DNS_FILE = "passive_dns.json"

stats = {"total": 0, "safe": 0, "malicious": 0}
history = []
ip_domain_map = defaultdict(set)
HISTORY_MAX = 1000

# small IP blocklist (can be extended via feeds)
BAD_IPS = {"45.83.43.21", "185.234.219.50"}

POPULAR_DOMAINS = ["google.com", "amazon.com", "paypal.com", "microsoft.com"]
RISKY_TLDS = {"xyz", "top", "tk", "gq", "ml"}

# API token for sensitive routes - set via env
API_TOKEN = os.environ.get("TI_API_TOKEN", "changeme")

# Email alert config (optional, set via env)
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_FROM = os.environ.get("SMTP_FROM", "threat-intel@example.com")

# ipinfo token for ASN lookups (optional)
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

# path to GeoLite2 DB if using geoip2 (optional)
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "GeoLite2-Country.mmdb")


# ---------- Persistence helpers -----------------------------------------
def load_state():
    global stats, history, ip_domain_map
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                stats = json.load(f)
        except Exception:
            pass
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass
    if os.path.exists(PASSIVE_DNS_FILE):
        try:
            with open(PASSIVE_DNS_FILE, "r") as f:
                raw = json.load(f)
                ip_domain_map = defaultdict(set, {k: set(v) for k, v in raw.items()})
        except Exception:
            pass


def save_state():
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(stats, f)
        with open(HISTORY_FILE, "w") as f:
            json.dump(history[-HISTORY_MAX:], f)
        simple = {k: list(v) for k, v in ip_domain_map.items()}
        with open(PASSIVE_DNS_FILE, "w") as f:
            json.dump(simple, f)
    except Exception as e:
        app.logger.warning("Could not persist state: %s", e)


# ---------- Utilities ---------------------------------------------------
def require_token():
    token = request.headers.get("X-API-Token") or request.args.get("api_token")
    if token != API_TOKEN:
        abort(401)


def sanitize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = - sum([p * math.log2(p) for p in prob])
    return entropy


def is_suspicious_heuristic(domain: str) -> bool:
    if len(domain) > 30:
        return True
    if re.search(r"[bcdfghjklmnpqrstvwxyz0-9]{6,}", domain, re.IGNORECASE):
        return True
    if domain.count('-') >= 3:
        return True
    return False


def resolves(domain: str) -> (bool, list):
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = []
        for entry in infos:
            sockaddr = entry[4]
            if sockaddr and len(sockaddr) > 0:
                ips.append(sockaddr[0])
        return True, sorted(set(ips))
    except Exception:
        return False, []


def domain_age_days(domain: str):
    if not whois_mod:
        return None
    try:
        info = whois_mod.whois(domain)
        created = info.creation_date
        if not created:
            return None
        if isinstance(created, list):
            created = created[0]
        if not isinstance(created, datetime):
            return None
        return (datetime.utcnow() - created).days
    except Exception:
        return None


def ip_reputation_check(ips):
    for ip in ips:
        if ip in BAD_IPS:
            return True
    return False


def update_passive_dns(domain, ips):
    for ip in ips:
        ip_domain_map[ip].add(domain)


def suspicious_shared_ips(domain):
    for ip, domains in ip_domain_map.items():
        if domain in domains and len(domains) > 5:
            return True
    return False


def tld_of(domain: str):
    parts = domain.split('.')
    return parts[-1] if len(parts) > 1 else ''


def brand_similarity(domain):
    max_sim = 0
    for brand in POPULAR_DOMAINS:
        sim = SequenceMatcher(None, domain, brand).ratio()
        max_sim = max(max_sim, sim)
    return max_sim


def geoip_check(ips):
    countries = []
    if not GEOIP_AVAILABLE:
        return countries
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        return countries
    for ip in ips:
        try:
            res = reader.country(ip)
            countries.append(res.country.iso_code)
        except Exception:
            pass
    try:
        reader.close()
    except Exception:
        pass
    return countries


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def lookup_asn(ip):
    # Use ipinfo.io simple endpoint (may be rate-limited). Optional token.
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if IPINFO_TOKEN:
            headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"
        r = requests.get(url, headers=headers, timeout=6)
        if r.ok:
            return r.json().get("org")
    except Exception:
        pass
    return None


def send_alert(subject, body):
    if not ALERT_EMAIL_TO:
        app.logger.info("Alert not sent - ALERT_EMAIL_TO not configured")
        return
    try:
        msg = EmailMessage()
        msg['From'] = SMTP_FROM
        msg['To'] = ALERT_EMAIL_TO
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.send_message(msg)
    except Exception as e:
        app.logger.warning("Alert send failed: %s", e)


def compute_reputation(domain: str, evidence: dict) -> float:
    score = 0.5
    if evidence.get("blacklist_hit"):
        return 0.0
    if evidence.get("allowlist_hit"):
        return 1.0

    resolved = evidence.get("resolves", False)
    if resolved:
        score += 0.12
    else:
        score -= 0.12

    ent = evidence.get("entropy", 0.0)
    if ent > 4.0:
        score -= 0.30
    elif ent > 3.5:
        score -= 0.18
    elif ent > 3.0:
        score -= 0.08

    length = evidence.get("length", 0)
    if length > 40:
        score -= 0.25
    elif length > 30:
        score -= 0.12

    if evidence.get("heuristic_suspicious"):
        score -= 0.14

    age = evidence.get("domain_age_days")
    if age is not None:
        if age < 30:
            score -= 0.30
        elif age < 180:
            score -= 0.08
        else:
            score += 0.06

    if evidence.get("bad_ip_hit"):
        score -= 0.40

    if evidence.get("shared_ip_suspicious"):
        score -= 0.22

    tld = evidence.get("tld")
    if tld in RISKY_TLDS:
        score -= 0.18

    sim = evidence.get("brand_similarity", 0.0)
    if sim > 0.85 and domain not in POPULAR_DOMAINS:
        score -= 0.35
    elif sim > 0.7:
        score -= 0.12

    score = max(0.0, min(1.0, score))
    return round(score, 3)


# ---------- Routes ------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", stats=stats)


@app.route("/check", methods=["POST"])
def check_domain():
    data = request.get_json() or {}
    raw = data.get("domain", "")
    domain = sanitize_domain(raw)
    if not domain:
        return jsonify({"error": "Empty domain"}), 400

    evidence = {}
    evidence["timestamp"] = int(time.time())
    evidence["length"] = len(domain)
    evidence["entropy"] = round(shannon_entropy(domain), 3)
    evidence["heuristic_suspicious"] = is_suspicious_heuristic(domain)
    evidence["blacklist_hit"] = domain in BLACKLIST
    evidence["allowlist_hit"] = domain in ALLOWLIST

    resolved_flag, ips = resolves(domain)
    evidence["resolves"] = resolved_flag
    evidence["resolved_ips"] = ips
    evidence["bad_ip_hit"] = ip_reputation_check(ips)

    if resolved_flag and ips:
        update_passive_dns(domain, ips)
    evidence["shared_ip_suspicious"] = suspicious_shared_ips(domain)

    evidence["domain_age_days"] = domain_age_days(domain)
    evidence["tld"] = tld_of(domain)
    evidence["brand_similarity"] = round(brand_similarity(domain), 3)
    evidence["resolved_countries"] = geoip_check(ips) if ips else []
    # enrichment
    evidence["reverse_dns"] = {ip: reverse_dns(ip) for ip in ips} if ips else {}
    evidence["asn_info"] = {ip: lookup_asn(ip) for ip in ips} if ips else {}

    reputation = compute_reputation(domain, evidence)
    status = "Safe" if reputation >= 0.5 else "Malicious"

    stats["total"] += 1
    if status == "Safe":
        stats["safe"] += 1
    else:
        stats["malicious"] += 1

    feature_vector = {
        "entropy": evidence["entropy"],
        "length": evidence["length"],
        "resolves": int(evidence["resolves"]),
        "bad_ip_hit": int(evidence["bad_ip_hit"]),
        "shared_ip_suspicious": int(evidence["shared_ip_suspicious"]),
        "domain_age_days": evidence["domain_age_days"],
        "tld": evidence["tld"],
        "brand_similarity": evidence["brand_similarity"]
    }

    record = {"domain": domain, "status": status, "reputation": reputation,
              "evidence": evidence, "feature_vector": feature_vector}
    history.append(record)
    if len(history) > HISTORY_MAX:
        del history[0: len(history) - HISTORY_MAX]
    save_state()

    # Alert if malicious (simple)
    if status == "Malicious":
        try:
            send_alert(f"[ThreatIntel] Malicious domain detected: {domain}",
                       f"Domain: {domain}\nReputation: {reputation}\nEvidence: {json.dumps(evidence, indent=2)}")
        except Exception:
            pass

    return jsonify({
        "domain": domain,
        "status": status,
        "reputation": reputation,
        "evidence": evidence,
        "feature_vector": feature_vector,
        "stats": stats
    })


@app.route("/check_bulk", methods=["POST"])
def check_bulk():
    """
    Accepts JSON {"domains": [...]} OR form file upload with key 'file' (csv or newline list).
    Protected route - require token.
    """
    require_token()
    items = []
    if request.content_type and "application/json" in request.content_type:
        data = request.get_json() or {}
        items = data.get("domains", [])
    else:
        f = request.files.get("file")
        if f:
            text = f.read().decode('utf-8', errors='ignore')
            for line in text.splitlines():
                for part in line.replace(',', '\n').splitlines():
                    part = part.strip()
                    if part:
                        items.append(part)
    if not items:
        return jsonify({"error": "No domains provided"}), 400

    results = []
    for d in items:
        domain = sanitize_domain(d)
        evidence = {
            "timestamp": int(time.time()),
            "length": len(domain),
            "entropy": round(shannon_entropy(domain), 3),
            "heuristic_suspicious": is_suspicious_heuristic(domain),
            "blacklist_hit": domain in BLACKLIST,
            "allowlist_hit": domain in ALLOWLIST
        }
        resolved_flag, ips = resolves(domain)
        evidence["resolves"] = resolved_flag
        evidence["resolved_ips"] = ips
        evidence["bad_ip_hit"] = ip_reputation_check(ips)
        if resolved_flag and ips:
            update_passive_dns(domain, ips)
        evidence["shared_ip_suspicious"] = suspicious_shared_ips(domain)
        evidence["domain_age_days"] = domain_age_days(domain)
        evidence["tld"] = tld_of(domain)
        evidence["brand_similarity"] = round(brand_similarity(domain), 3)
        reputation = compute_reputation(domain, evidence)
        status = "Safe" if reputation >= 0.5 else "Malicious"
        results.append({"domain": domain, "status": status, "reputation": reputation, "evidence": evidence})

    save_state()
    return jsonify({"count": len(results), "results": results})


@app.route("/fetch_feed", methods=["POST"])
def fetch_feed():
    """
    Manual feed fetch. JSON: { "url": "...", "type": "domains"|"ips" }.
    Adds to BLACKLIST or BAD_IPS. Protected route.
    """
    require_token()
    data = request.get_json() or {}
    url = data.get("url")
    feed_type = data.get("type", "domains")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        headers = {}
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
    except Exception as e:
        return jsonify({"error": f"Could not fetch feed: {e}"}), 400

    added = 0
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if feed_type == "ips":
            ip = line.split()[0]
            if ip not in BAD_IPS:
                BAD_IPS.add(ip)
                added += 1
        else:
            d = sanitize_domain(line.split()[0])
            if d and d not in BLACKLIST:
                BLACKLIST.add(d)
                added += 1
    save_state()
    return jsonify({"added": added, "blacklist_size": len(BLACKLIST), "bad_ips_size": len(BAD_IPS)})


@app.route("/permutations", methods=["GET"])
def perms():
    domain = sanitize_domain(request.args.get('domain', ''))
    if not domain:
        return jsonify({"error": "domain required"}), 400

    def generate_permutations(domain):
        out = set()
        name_parts = domain.split('.')
        name = name_parts[0]
        suffix = ".".join(name_parts[1:]) if len(name_parts) > 1 else ""
        for i in range(len(name)-1):
            s = list(name)
            s[i], s[i+1] = s[i+1], s[i]
            candidate = ''.join(s)
            out.add(candidate + ('.' + suffix if suffix else ''))
        for i in range(len(name)):
            out.add(name[:i] + name[i+1:] + ('.' + suffix if suffix else ''))
        return sorted(out)

    return jsonify({"permutations": generate_permutations(domain)})


@app.route("/export_training", methods=["GET"])
def export_training():
    require_token()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["domain","status","reputation","entropy","length","resolves","bad_ip_hit","shared_ip","domain_age_days","tld","brand_similarity","timestamp"])
    for rec in history:
        e = rec.get("evidence", {})
        writer.writerow([
            rec.get("domain"),
            rec.get("status"),
            rec.get("reputation"),
            e.get("entropy"),
            e.get("length"),
            int(bool(e.get("resolves"))),
            int(bool(e.get("bad_ip_hit"))),
            int(bool(e.get("shared_ip_suspicious"))),
            e.get("domain_age_days"),
            e.get("tld"),
            e.get("brand_similarity"),
            e.get("timestamp")
        ])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=training_data.csv"})


@app.route("/history", methods=["GET"])
def get_history():
    return jsonify({"history": history[-100:]})


@app.route("/allowlist", methods=["GET", "POST", "DELETE"])
def allowlist_ops():
    if request.method == "GET":
        return jsonify({"allowlist": sorted(list(ALLOWLIST))})
    data = request.get_json() or {}
    domain = sanitize_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if request.method == "POST":
        ALLOWLIST.add(domain)
        save_state()
        return jsonify({"result": "added", "allowlist": sorted(list(ALLOWLIST))})
    if request.method == "DELETE":
        ALLOWLIST.discard(domain)
        save_state()
        return jsonify({"result": "removed", "allowlist": sorted(list(ALLOWLIST))})


@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json() or {}
    domain = sanitize_domain(data.get("domain", ""))
    label = (data.get("label") or "").strip().lower()
    if not domain or label not in ("malicious", "safe"):
        return jsonify({"error": "domain and label (malicious|safe) required"}), 400

    resolved_flag, ips = resolves(domain)
    evidence = {
        "timestamp": int(time.time()),
        "length": len(domain),
        "entropy": round(shannon_entropy(domain), 3),
        "heuristic_suspicious": is_suspicious_heuristic(domain),
        "resolves": resolved_flag,
        "resolved_ips": ips,
        "blacklist_hit": domain in BLACKLIST,
        "allowlist_hit": domain in ALLOWLIST,
    }
    evidence["bad_ip_hit"] = ip_reputation_check(ips)
    evidence["domain_age_days"] = domain_age_days(domain)
    evidence["tld"] = tld_of(domain)
    evidence["brand_similarity"] = round(brand_similarity(domain), 3)
    evidence["shared_ip_suspicious"] = suspicious_shared_ips(domain)

    reputation = compute_reputation(domain, evidence)
    status = "Malicious" if label == "malicious" else "Safe"

    stats["total"] += 1
    if status == "Safe":
        stats["safe"] += 1
    else:
        stats["malicious"] += 1

    record = {"domain": domain, "status": status, "reputation": reputation, "evidence": evidence, "feedback": True}
    history.append(record)
    if len(history) > HISTORY_MAX:
        del history[0: len(history) - HISTORY_MAX]
    save_state()

    return jsonify({"result": "stored", "record": record, "stats": stats})


# Load state on startup
load_state()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=bool(os.environ.get("DEBUG", False)))
