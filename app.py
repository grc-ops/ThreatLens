#!/usr/bin/env python3
"""
ThreatLens - multi-source IOC lookup and bulk triage.

Queries many threat-intel sources in parallel, normalises each verdict to a
0-100 score, and consolidates them into one score per IOC. API keys live in
.env on the server; the browser never sees them.
"""
import base64
import hashlib
import ipaddress
import os
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from urllib.parse import quote

import requests
from flask import Flask, jsonify, request, send_from_directory

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
MAX_BULK = int(os.getenv("MAX_BULK", "500"))
UA = "ThreatLens/1.0 (+SOC IOC triage)"

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

import store  # noqa: E402  (history, sightings, saved searches)

from intel import bp as intel_bp  # noqa: E402  (news search, IOC extraction, ATT&CK mapping)

app.register_blueprint(intel_bp)


def key(name):
    return os.getenv(name, "").strip()


# --------------------------------------------------------------------------
# Parsing / classification
# --------------------------------------------------------------------------
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$",
    re.I,
)
INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".intranet", ".localdomain")


def refang(s):
    s = s.strip().strip("\"'")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"^fxp", "ftp", s, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
                 ("[:]", ":"), ("[://]", "://"), ("[@]", "@"), ("[at]", "@")):
        s = s.replace(a, b)
    return s


def classify(v):
    """Return (type, normalised_value). Types: ip, domain, url, hash, cve, unknown."""
    v = v.strip()
    if CVE_RE.match(v):
        return "cve", v.upper()
    if re.fullmatch(r"[a-fA-F0-9]+", v) and len(v) in HASH_LEN:
        return "hash", v.lower()
    try:
        return "ip", str(ipaddress.ip_address(v.strip("[]")))
    except ValueError:
        pass
    if re.match(r"^[a-z][a-z0-9+.-]*://\S+", v, re.I):
        return "url", v
    host = v.split("/")[0].split(":")[0]
    if "/" in v and DOMAIN_RE.match(host):
        return "url", "http://" + v
    if DOMAIN_RE.match(v):
        return "domain", v.lower().rstrip(".")
    return "unknown", v


def is_internal(ioc, t):
    if t == "ip":
        ip = ipaddress.ip_address(ioc)
        return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)
    if t == "domain":
        return ioc.endswith(INTERNAL_SUFFIXES)
    return False


# --------------------------------------------------------------------------
# Plumbing: rate limiting, caching, provider registry
# --------------------------------------------------------------------------
class Limiter:
    """Spaces calls so a provider never exceeds its requests-per-minute quota."""

    def __init__(self, rpm):
        self.interval = 60.0 / rpm if rpm and rpm > 0 else 0.0
        self.lock = threading.Lock()
        self.next = 0.0

    def wait(self, max_wait=120):
        if not self.interval:
            return True
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next)
            if slot - now > max_wait:
                return False
            self.next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        return True


CACHE = {}
CACHE_LOCK = threading.Lock()


def cache_get(k):
    with CACHE_LOCK:
        hit = CACHE.get(k)
        if hit and time.time() - hit[0] < CACHE_TTL:
            return hit[1]
    return None


def cache_put(k, v):
    with CACHE_LOCK:
        CACHE[k] = (time.time(), v)


PROVIDERS = {}


def provider(pid, name, short, types, link, env=None, weight=1.0, rpm=0, desc="", daily=None):
    def deco(fn):
        PROVIDERS[pid] = dict(id=pid, name=name, short=short, types=set(types), env=env,
                              weight=weight, limiter=Limiter(rpm), fn=fn, link=link, desc=desc, daily=daily, rpm=rpm)
        return fn
    return deco


def norm_date(x):
    """Epoch seconds or any ISO-ish string -> 'YYYY-MM-DD' (or None)."""
    if x in (None, "", 0):
        return None
    if isinstance(x, (int, float)):
        try:
            return datetime.fromtimestamp(int(x), timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return None
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(x))
    return m.group(0) if m else None


def res(score=None, badge="", summary="", details=None, link=None, status="ok",
        first=None, last=None, registered=None, meta=None):
    details = {k: v for k, v in (details or {}).items() if v not in (None, "", [], {})}
    return dict(status=status, score=score, badge=badge, summary=summary, details=details, link=link,
                first_seen=norm_date(first), last_seen=norm_date(last), registered=norm_date(registered), meta=meta)


TL = threading.local()
HEALTH = {}
HLOCK = threading.Lock()


def health_entry(pid):
    return HEALTH.setdefault(pid, {"recent": deque(maxlen=10), "ok": 0, "err": 0, "last_error": None,
                                   "last_error_at": None, "last_ok_at": None, "remaining": None,
                                   "day": date.today().isoformat(), "today": 0})


def http(method, url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    headers = kw.pop("headers", None) or {}
    headers.setdefault("User-Agent", UA)
    r = requests.request(method, url, headers=headers, **kw)
    pid = getattr(TL, "pid", None)
    if pid:
        for k, v in r.headers.items():
            if re.search(r"ratelimit.*remaining", k, re.I) and str(v).strip().isdigit():
                with HLOCK:
                    health_entry(pid)["remaining"] = int(v)
    return r


def note_call(pid, ok, err=None):
    with HLOCK:
        h = health_entry(pid)
        today = date.today().isoformat()
        if h["day"] != today:
            h["day"], h["today"] = today, 0
        h["today"] += 1
        h["recent"].append(ok)
        if ok:
            h["ok"] += 1
            h["last_ok_at"] = store.now()
        else:
            h["err"] += 1
            h["last_error"], h["last_error_at"] = (err or "")[:140], store.now()


def htype(h):
    return HASH_LEN[len(h)]


def band(score):
    if score is None:
        return "unknown"
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 10:
        return "low"
    return "clean"


def ts(epoch):
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------
def vt_link(ioc, t):
    base = "https://www.virustotal.com/gui/"
    if t == "ip":
        return f"{base}ip-address/{ioc}"
    if t == "domain":
        return f"{base}domain/{ioc}"
    if t == "hash":
        return f"{base}file/{ioc}"
    return f"{base}url/{hashlib.sha256(ioc.encode()).hexdigest()}"


@provider("virustotal", "VirusTotal", "VT", {"ip", "domain", "url", "hash"}, vt_link,
          env="VT_API_KEY", weight=3, rpm=int(os.getenv("VT_RPM", "4")), daily=int(os.getenv("VT_DAILY", "500")),
          desc="Engine detections across 70+ AV/URL scanners. Free tier: 4 req/min.")
def p_virustotal(ioc, t):
    if t == "ip":
        path = f"ip_addresses/{ioc}"
    elif t == "domain":
        path = f"domains/{ioc}"
    elif t == "hash":
        path = f"files/{ioc}"
    else:
        path = "urls/" + base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    r = http("GET", f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key("VT_API_KEY")})
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="Not seen by VirusTotal")
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited (free tier allows 4 requests/min)")
    if r.status_code in (401, 403):
        return res(status="error", badge="auth", summary="API key rejected")
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    s = a.get("last_analysis_stats", {})
    mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
    total = sum(s.get(x, 0) for x in ("malicious", "suspicious", "harmless", "undetected"))
    score = min(100, mal * 8 + sus * 3)
    ptc = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return res(
        score=score,
        badge=f"{mal}/{total}",
        summary=f"{mal} malicious, {sus} suspicious of {total} engines",
        details={
            "Threat label": ptc, "Reputation": a.get("reputation"),
            "File name": a.get("meaningful_name"), "File type": a.get("type_description"),
            "Owner": a.get("as_owner"), "Country": a.get("country"), "Registrar": a.get("registrar"),
            "Tags": ", ".join(a.get("tags", [])[:8]),
            "Last analysed": ts(a.get("last_analysis_date")),
        },
        first=a.get("first_submission_date"), last=a.get("last_analysis_date"),
        registered=a.get("creation_date") if t == "domain" else None,
    )


@provider("abuseipdb", "AbuseIPDB", "AIPDB", {"ip"}, lambda i, t: f"https://www.abuseipdb.com/check/{i}",
          env="ABUSEIPDB_API_KEY", weight=2, desc="Crowd-sourced abuse confidence score for IPs (90 days).",
          daily=int(os.getenv("ABUSEIPDB_DAILY", "1000")))
def p_abuseipdb(ioc, t):
    r = http("GET", "https://api.abuseipdb.com/api/v2/check",
             params={"ipAddress": ioc, "maxAgeInDays": 90},
             headers={"Key": key("ABUSEIPDB_API_KEY"), "Accept": "application/json"})
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited (daily quota reached)")
    if r.status_code in (401, 403):
        return res(status="error", badge="auth", summary="API key rejected")
    r.raise_for_status()
    d = r.json()["data"]
    score = d.get("abuseConfidenceScore", 0)
    return res(score=score, badge=f"{score}%",
               summary=f"{d.get('totalReports', 0)} reports from {d.get('numDistinctUsers', 0)} users (90d)",
               details={"ISP": d.get("isp"), "Usage": d.get("usageType"), "Country": d.get("countryCode"),
                        "Domain": d.get("domain"), "Tor": d.get("isTor") or None,
                        "Last reported": (d.get("lastReportedAt") or "")[:10]}, last=d.get("lastReportedAt"))


def otx_link(ioc, t):
    seg = {"ip": "ip", "domain": "domain", "url": "url", "hash": "file"}[t]
    return f"https://otx.alienvault.com/indicator/{seg}/{quote(ioc, safe=':/')}"


@provider("otx", "AlienVault OTX", "OTX", {"ip", "domain", "url", "hash"}, otx_link,
          env="OTX_API_KEY", weight=1, desc="Community threat pulses referencing the indicator.")
def p_otx(ioc, t):
    if t == "ip":
        seg = "IPv6" if ":" in ioc else "IPv4"
    else:
        seg = {"domain": "domain", "url": "url", "hash": "file"}[t]
    r = http("GET", f"https://otx.alienvault.com/api/v1/indicators/{seg}/{quote(ioc, safe='')}/general",
             headers={"X-OTX-API-KEY": key("OTX_API_KEY")})
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="No OTX record")
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited")
    r.raise_for_status()
    d = r.json()
    pi = d.get("pulse_info", {})
    n = pi.get("count", 0)
    names = [p.get("name") for p in pi.get("pulses", [])[:3]]
    score = min(80, n * 10)
    return res(score=score, badge=f"{n} pulses", summary=f"Referenced in {n} community pulse(s)",
               details={"Top pulses": "; ".join(x for x in names if x), "Country": d.get("country_name"),
                        "ASN": d.get("asn"), "Reputation": d.get("reputation") or None})


@provider("greynoise", "GreyNoise", "GN", {"ip"}, lambda i, t: f"https://viz.greynoise.io/ip/{i}",
          env="GREYNOISE_API_KEY", weight=1.5, desc="Separates internet background noise from targeted activity.")
def p_greynoise(ioc, t):
    r = http("GET", f"https://api.greynoise.io/v3/community/{ioc}", headers={"key": key("GREYNOISE_API_KEY")})
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="Not observed scanning the internet")
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited")
    r.raise_for_status()
    d = r.json()
    cls = d.get("classification", "unknown")
    if d.get("riot") or cls == "benign":
        score = 0
    elif cls == "malicious":
        score = 85
    else:
        score = 30 if d.get("noise") else 10
    return res(score=score, badge=cls, summary=f"Classified {cls}" + (" (common business service)" if d.get("riot") else ""),
               details={"Name": d.get("name"), "Noise": d.get("noise"), "RIOT": d.get("riot"),
                        "Last seen": d.get("last_seen")}, last=d.get("last_seen"))


def abusech_headers():
    return {"Auth-Key": key("ABUSECH_API_KEY")}


def urlhaus_link(ioc, t):
    if t in ("domain", "ip"):
        return f"https://urlhaus.abuse.ch/host/{ioc}/"
    return f"https://urlhaus.abuse.ch/browse.php?search={quote(ioc, safe='')}"


@provider("urlhaus", "URLhaus", "URLhaus", {"ip", "domain", "url", "hash"}, urlhaus_link,
          env="ABUSECH_API_KEY", weight=2, desc="abuse.ch malware-distribution URLs and hosts.")
def p_urlhaus(ioc, t):
    if t == "url":
        ep, data = "url/", {"url": ioc}
    elif t in ("domain", "ip"):
        ep, data = "host/", {"host": ioc}
    else:
        if len(ioc) == 40:
            return res(status="skipped", summary="URLhaus supports MD5 and SHA256 only")
        ep, data = "payload/", {"md5_hash" if len(ioc) == 32 else "sha256_hash": ioc}
    r = http("POST", "https://urlhaus-api.abuse.ch/v1/" + ep, data=data, headers=abusech_headers())
    if r.status_code in (401, 403):
        return res(status="error", badge="auth", summary="abuse.ch Auth-Key rejected")
    r.raise_for_status()
    d = r.json()
    qs = d.get("query_status")
    if qs != "ok":
        return res(status="not_found", badge="-", summary="Not listed in URLhaus")
    link = d.get("urlhaus_reference")
    if t == "url":
        online = d.get("url_status") == "online"
        return res(score=95 if online else 75, badge=d.get("url_status", "listed"),
                   summary=f"Listed as {d.get('threat', 'malicious')} ({d.get('url_status')})", link=link,
                   details={"Threat": d.get("threat"), "Tags": ", ".join(d.get("tags") or []),
                            "Date added": (d.get("date_added") or "")[:10]}, first=d.get("date_added"))
    if t == "hash":
        return res(score=90, badge=d.get("signature") or "listed",
                   summary=f"Payload seen on {d.get('url_count', '?')} URL(s)", link=link,
                   details={"Signature": d.get("signature"), "File type": d.get("file_type")},
                   first=d.get("firstseen"), last=d.get("lastseen"))
    online = int(d.get("urls_online") or 0)
    count = d.get("url_count")
    return res(score=90 if online else 60, badge=f"{online} online",
               summary=f"{count} malware URL(s) hosted, {online} online", link=link,
               details={"Blacklists": ", ".join(f"{k}:{v}" for k, v in (d.get("blacklists") or {}).items() if v not in ("not listed", None))},
               first=d.get("firstseen"))


@provider("threatfox", "ThreatFox", "TFox", {"ip", "domain", "url", "hash"},
          lambda i, t: f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(i, safe='')}",
          env="ABUSECH_API_KEY", weight=2, desc="abuse.ch IOC database with malware family and confidence.")
def p_threatfox(ioc, t):
    r = http("POST", "https://threatfox-api.abuse.ch/api/v1/",
             json={"query": "search_ioc", "search_term": ioc, "exact_match": t in ("url", "hash")},
             headers=abusech_headers())
    if r.status_code in (401, 403):
        return res(status="error", badge="auth", summary="abuse.ch Auth-Key rejected")
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok" or not isinstance(d.get("data"), list) or not d["data"]:
        return res(status="not_found", badge="-", summary="Not listed in ThreatFox")
    rows = d["data"]
    best = max(rows, key=lambda x: x.get("confidence_level") or 0)
    conf = int(best.get("confidence_level") or 50)
    return res(score=conf, badge=f"{conf}%", link=f"https://threatfox.abuse.ch/ioc/{best.get('id')}/",
               summary=f"{len(rows)} match(es): {best.get('malware_printable')} ({best.get('threat_type')})",
               details={"Malware": best.get("malware_printable"), "Threat type": best.get("threat_type"),
                        "First seen": (best.get("first_seen") or "")[:10],
                        "Tags": ", ".join(best.get("tags") or [])},
               first=best.get("first_seen"), last=best.get("last_seen"))


@provider("malwarebazaar", "MalwareBazaar", "MB", {"hash"},
          lambda i, t: f"https://bazaar.abuse.ch/browse.php?search={i}",
          env="ABUSECH_API_KEY", weight=2, desc="abuse.ch repository of known malware samples.")
def p_malwarebazaar(ioc, t):
    r = http("POST", "https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": ioc},
             headers=abusech_headers())
    if r.status_code in (401, 403):
        return res(status="error", badge="auth", summary="abuse.ch Auth-Key rejected")
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok" or not d.get("data"):
        return res(status="not_found", badge="-", summary="Sample not in MalwareBazaar")
    s = d["data"][0]
    return res(score=95, badge=s.get("signature") or "known",
               summary=f"Known malware sample: {s.get('signature') or 'unclassified'}",
               link=f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/",
               details={"Signature": s.get("signature"), "File type": s.get("file_type"),
                        "File name": s.get("file_name"), "Tags": ", ".join(s.get("tags") or []),
                        "First seen": (s.get("first_seen") or "")[:10], "SHA256": s.get("sha256_hash")},
               first=s.get("first_seen"), last=s.get("last_seen"))


@provider("shodan", "Shodan InternetDB", "Shodan", {"ip"}, lambda i, t: f"https://www.shodan.io/host/{i}",
          weight=0.5, desc="No-key exposure context: open ports, CVEs, tags.")
def p_shodan(ioc, t):
    r = http("GET", f"https://internetdb.shodan.io/{ioc}")
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="No exposure data")
    r.raise_for_status()
    d = r.json()
    vulns, tags, ports = d.get("vulns") or [], d.get("tags") or [], d.get("ports") or []
    score = min(50, 10 + 5 * len(vulns)) if vulns else 0
    if {"malware", "compromised", "c2"} & set(tags):
        score = max(score, 80)
    return res(score=score, badge=f"{len(ports)} ports" + (f", {len(vulns)} CVE" if vulns else ""),
               summary=f"{len(ports)} open port(s), {len(vulns)} known CVE(s)",
               details={"Ports": ", ".join(map(str, ports[:15])), "CVEs": ", ".join(vulns[:8]),
                        "Tags": ", ".join(tags), "Hostnames": ", ".join((d.get("hostnames") or [])[:5])},
               meta={"cves": vulns[:30]})


def pulsedive_link(ioc, t):
    return "https://pulsedive.com/indicator/?ioc=" + base64.b64encode(ioc.encode()).decode()


@provider("pulsedive", "Pulsedive", "PD", {"ip", "domain", "url"}, pulsedive_link,
          env="PULSEDIVE_API_KEY", weight=1.5, desc="Aggregated risk rating with threat and feed context.")
def p_pulsedive(ioc, t):
    r = http("GET", "https://pulsedive.com/api/info.php", params={"indicator": ioc, "key": key("PULSEDIVE_API_KEY")})
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="Not in Pulsedive")
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited")
    r.raise_for_status()
    d = r.json()
    if d.get("error"):
        return res(status="not_found", badge="-", summary=str(d["error"])[:80])
    risk = d.get("risk", "unknown")
    m = {"none": 0, "low": 25, "medium": 50, "high": 75, "critical": 95, "retired": 0}
    threats = [x.get("name") for x in d.get("threats", [])[:4]]
    return res(score=m.get(risk), badge=risk, summary=f"Risk: {risk}",
               link=f"https://pulsedive.com/indicator/?iid={d['iid']}" if d.get("iid") else None,
               details={"Threats": ", ".join(x for x in threats if x),
                        "Risk factors": ", ".join(x.get("description", "") for x in d.get("riskfactors", [])[:3])},
               first=d.get("stamp_added"), last=d.get("stamp_seen"))


def urlscan_query(ioc, t):
    return {"ip": f'ip:"{ioc}"', "domain": f"page.domain:{ioc}", "url": f'page.url:"{ioc}"'}[t]


@provider("urlscan", "urlscan.io", "urlscan", {"ip", "domain", "url"},
          lambda i, t: "https://urlscan.io/search/#" + quote(urlscan_query(i, t)),
          weight=1.5, desc="Latest public scan verdict. API key optional (higher limits).")
def p_urlscan(ioc, t):
    h = {"API-Key": key("URLSCAN_API_KEY")} if key("URLSCAN_API_KEY") else {}
    r = http("GET", "https://urlscan.io/api/v1/search/", params={"q": urlscan_query(ioc, t), "size": 1}, headers=h)
    if r.status_code == 429:
        return res(status="error", badge="429", summary="Rate limited")
    r.raise_for_status()
    d = r.json()
    rows = d.get("results") or []
    if not rows:
        return res(status="not_found", badge="-", summary="No public scans")
    sid = rows[0]["_id"]
    link = f"https://urlscan.io/result/{sid}/"
    rr = http("GET", f"https://urlscan.io/api/v1/result/{sid}/", headers=h)
    mal, cats = False, []
    if rr.ok:
        v = rr.json().get("verdicts", {}).get("overall", {})
        mal, cats = bool(v.get("malicious")), v.get("categories", [])
    return res(score=90 if mal else 0, badge="malicious" if mal else "clean", link=link,
               summary=f"Latest of {d.get('total', '?')} scan(s): {'flagged malicious' if mal else 'no malicious verdict'}",
               details={"Categories": ", ".join(cats), "Scans": d.get("total")},
               last=(rows[0].get("task") or {}).get("time"))


@provider("circl", "CIRCL hashlookup", "CIRCL", {"hash"},
          lambda i, t: f"https://hashlookup.circl.lu/lookup/{htype(i)}/{i}",
          weight=0.5, desc="Known-file (NSRL etc.) lookup, a benign-software signal.")
def p_circl(ioc, t):
    r = http("GET", f"https://hashlookup.circl.lu/lookup/{htype(ioc)}/{ioc}")
    if r.status_code == 404:
        return res(status="not_found", badge="-", summary="Not a known-software hash")
    r.raise_for_status()
    d = r.json()
    return res(score=0, badge="known file", summary="Known software hash (likely benign)",
               details={"File name": d.get("FileName"), "Source": d.get("source"),
                        "Product": d.get("ProductName") or d.get("ProductCode")})


@provider("epss", "FIRST EPSS", "EPSS", {"cve"}, lambda i, t: f"https://api.first.org/data/v1/epss?cve={i}",
          weight=1, desc="Probability a CVE is exploited in the next 30 days.")
def p_epss(ioc, t):
    r = http("GET", "https://api.first.org/data/v1/epss", params={"cve": ioc})
    r.raise_for_status()
    rows = r.json().get("data") or []
    if not rows:
        return res(status="not_found", badge="-", summary="No EPSS score")
    p, pct = float(rows[0]["epss"]), float(rows[0]["percentile"])
    return res(score=round(p * 100), badge=f"{p * 100:.1f}%",
               summary=f"{p * 100:.2f}% exploitation probability (top {100 - pct * 100:.0f}% of CVEs)",
               details={"Percentile": f"{pct * 100:.1f}", "Score date": rows[0].get("date")})


KEV = {"ts": 0, "data": {}}
KEV_LOCK = threading.Lock()


def load_kev():
    with KEV_LOCK:
        if time.time() - KEV["ts"] > 6 * 3600:
            r = http("GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            r.raise_for_status()
            KEV["data"] = {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}
            KEV["ts"] = time.time()
        return KEV["data"]


@provider("cisa_kev", "CISA KEV", "KEV", {"cve"},
          lambda i, t: f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={i}",
          weight=3, desc="CISA catalogue of vulnerabilities exploited in the wild.")
def p_kev(ioc, t):
    v = load_kev().get(ioc)
    if not v:
        return res(score=None, badge="not listed", summary="Not in CISA KEV catalogue")
    return res(score=100, badge="KEV", summary=f"Actively exploited: {v.get('vulnerabilityName')}",
               details={"Vendor": v.get("vendorProject"), "Product": v.get("product"),
                        "Added": v.get("dateAdded"), "Remediation due": v.get("dueDate"),
                        "Ransomware use": v.get("knownRansomwareCampaignUse"),
                        "Required action": v.get("requiredAction")})


@provider("nvd", "NVD (CVSS)", "NVD", {"cve"}, lambda i, t: f"https://nvd.nist.gov/vuln/detail/{i}",
          weight=1, rpm=int(os.getenv("NVD_RPM", "10")), desc="Official CVSS base score and description.")
def p_nvd(ioc, t):
    h = {"apiKey": key("NVD_API_KEY")} if key("NVD_API_KEY") else {}
    r = http("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": ioc}, headers=h)
    if r.status_code in (403, 429):
        return res(status="error", badge="429", summary="NVD rate limited (get a free NVD_API_KEY)")
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities") or []
    if not vulns:
        return res(status="not_found", badge="-", summary="CVE not in NVD")
    c = vulns[0]["cve"]
    m = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if c.get("metrics", {}).get(k):
            m = c["metrics"][k][0]["cvssData"]
            break
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if not m:
        return res(status="ok", score=None, badge="no CVSS", summary=desc[:200])
    b = float(m["baseScore"])
    sev = "CRITICAL" if b >= 9 else "HIGH" if b >= 7 else "MEDIUM" if b >= 4 else "LOW"
    return res(score=round(b * 10), badge=f"{b} {sev.title()}", summary=desc[:240],
               details={"Vector": m.get("vectorString"), "Published": (c.get("published") or "")[:10]},
               first=c.get("published"))



@provider("rdap", "RDAP whois", "Whois", {"domain"}, lambda i, t: f"https://lookup.icann.org/en/lookup?name={i}",
          weight=0.7, desc="Domain registration date and registrar (no key). New domains score slightly higher.")
def p_rdap(ioc, t):
    labels = ioc.split(".")
    cands = [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))][:4]
    d = None
    for c in cands:
        r = http("GET", f"https://rdap.org/domain/{c}", headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            d = r.json()
            break
        if r.status_code not in (400, 404):
            r.raise_for_status()
    if not d:
        return res(status="not_found", badge="-", summary="No RDAP record for this domain")
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    reg, exp = norm_date(ev.get("registration")), norm_date(ev.get("expiration"))
    registrar = None
    for e in d.get("entities", []):
        if "registrar" in (e.get("roles") or []):
            vc = (e.get("vcardArray") or [None, []])[1]
            registrar = next((x[3] for x in vc if x and x[0] == "fn"), None)
    age = (date.today() - date.fromisoformat(reg)).days if reg else None
    score = None if age is None else 40 if age < 14 else 25 if age < 30 else 10 if age < 90 else None
    badge = "-" if age is None else f"{age}d old" if age < 365 else f"{age // 365}y old"
    return res(score=score, badge=badge, registered=reg,
               summary=(f"Registered {reg} ({age} days ago)" if reg else "Registration date not published")
               + (f" via {registrar}" if registrar else ""),
               details={"Registered": reg, "Expires": exp, "Registrar": registrar,
                        "Nameservers": ", ".join((n.get("ldhName") or "") for n in d.get("nameservers", [])[:4]),
                        "Status": ", ".join((d.get("status") or [])[:3])})


@provider("ripestat", "RIPEstat network", "ASN", {"ip"}, lambda i, t: f"https://stat.ripe.net/{i}",
          weight=0, desc="ASN, holder and announced prefix (no key). Context only, not scored.")
def p_ripestat(ioc, t):
    r = http("GET", "https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ioc})
    r.raise_for_status()
    d = r.json().get("data", {})
    asns = d.get("asns") or []
    if not asns:
        return res(status="not_found", badge="-", summary="Not announced in BGP")
    a = asns[0]
    return res(score=None, badge=f"AS{a.get('asn')}", summary=f"AS{a.get('asn')} {a.get('holder', '')} ({d.get('resource', '')})",
               details={"ASN": a.get("asn"), "Holder": a.get("holder"), "Prefix": d.get("resource")},
               meta={"asn": a.get("asn"), "holder": a.get("holder"), "prefix": d.get("resource")})


# --------------------------------------------------------------------------
# Pivot links (no API needed, always shown)
# --------------------------------------------------------------------------
def pivots(ioc, t):
    q = quote(ioc, safe="")
    P = []
    if t == "ip":
        P = [("Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={q}"),
             ("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/ip/{q}"),
             ("Censys", f"https://search.censys.io/hosts/{q}"),
             ("Criminal IP", f"https://www.criminalip.io/asset/report/{q}"),
             ("Spamhaus", f"https://check.spamhaus.org/results/?query={q}"),
             ("BGP.he.net", f"https://bgp.he.net/ip/{q}"),
             ("ThreatMiner", f"https://www.threatminer.org/host.php?q={q}"),
             ("ipinfo", f"https://ipinfo.io/{q}"),
             ("Shodan search", f"https://www.shodan.io/host/{q}")]
    elif t == "domain":
        P = [("Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={q}"),
             ("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/url/{q}"),
             ("crt.sh", f"https://crt.sh/?q={q}"),
             ("SecurityTrails", f"https://securitytrails.com/domain/{q}/dns"),
             ("DomainTools Whois", f"https://whois.domaintools.com/{q}"),
             ("Netcraft", f"https://sitereport.netcraft.com/?url={q}"),
             ("ThreatMiner", f"https://www.threatminer.org/domain.php?q={q}"),
             ("Google Safe Browsing", f"https://transparencyreport.google.com/safe-browsing/search?url={q}"),
             ("Shodan search", f"https://www.shodan.io/search?query=hostname%3A{q}"),
             ("Censys", f"https://search.censys.io/search?resource=hosts&q={q}")]
    elif t == "url":
        P = [("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/url/{q}"),
             ("Google Safe Browsing", f"https://transparencyreport.google.com/safe-browsing/search?url={q}"),
             ("Netcraft", f"https://sitereport.netcraft.com/?url={q}"),
             ("PhishTank", "https://phishtank.org/"),
             ("urlscan search", "https://urlscan.io/search/#" + quote(f'page.url:"{ioc}"'))]
    elif t == "hash":
        P = [("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={q}"),
             ("ANY.RUN", f"https://app.any.run/submissions/#filehash:{q}"),
             ("Triage", f"https://tria.ge/s?q={q}"),
             ("Joe Sandbox", f"https://www.joesandbox.com/search?q={q}"),
             ("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/malware/{q}"),
             ("Intezer", f"https://analyze.intezer.com/files/{q}"),
             ("YARAify", f"https://yaraify.abuse.ch/yara/?query={q}")]
    elif t == "cve":
        P = [("NVD", f"https://nvd.nist.gov/vuln/detail/{q}"),
             ("CVE.org", f"https://www.cve.org/CVERecord?id={q}"),
             ("Exploit-DB", f"https://www.exploit-db.com/search?cve={q}"),
             ("GitHub advisories", f"https://github.com/advisories?query={q}"),
             ("Vulners", f"https://vulners.com/cve/{q}"),
             ("CVEDetails", f"https://www.cvedetails.com/cve/{q}/"),
             ("OSV", f"https://osv.dev/vulnerability/{q}"),
             ("MITRE ATT&CK search", f"https://attack.mitre.org/search/?q={q}")]
    return [{"name": n, "url": u} for n, u in P]


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def configured(p):
    return p["env"] is None or bool(key(p["env"]))


def run_provider(p, ioc, t, refresh):
    meta = {"name": p["name"], "short": p["short"]}
    link = p["link"](ioc, t)
    if not configured(p):
        return {**meta, **res(status="skipped", summary=f"Not configured (set {p['env']} in .env)", link=link)}
    ck = (p["id"], t, ioc)
    if not refresh:
        hit = cache_get(ck)
        if hit:
            return {**meta, **hit}
    if not p["limiter"].wait():
        return {**meta, **res(status="error", badge="queue", summary="Skipped: provider rate-limit queue is full", link=link)}
    TL.pid = p["id"]
    try:
        out = p["fn"](ioc, t)
    except requests.Timeout:
        out = res(status="error", badge="timeout", summary="Provider timed out")
    except requests.RequestException as e:
        out = res(status="error", badge="err", summary=f"Request failed: {str(e)[:100]}")
    except Exception as e:  # noqa: BLE001 - never let one provider break a lookup
        out = res(status="error", badge="err", summary=f"Unexpected response: {str(e)[:100]}")
    finally_pid, TL.pid = TL.pid, None
    out["link"] = out.get("link") or link
    note_call(finally_pid, out["status"] != "error", out.get("summary"))
    if out["status"] in ("ok", "not_found"):
        cache_put(ck, out)
    return {**meta, **out}


def consolidate(provs):
    scored = [(PROVIDERS[k]["weight"], v["score"]) for k, v in provs.items()
              if v["status"] == "ok" and v["score"] is not None]
    if not scored:
        return None, 0
    wsum = sum(w for w, _ in scored)
    avg = sum(w * s for w, s in scored) / wsum
    top = max(s for _, s in scored)
    # One strong, high-fidelity hit should not be diluted away by silent sources.
    return int(round(max(avg, top * 0.8))), len(scored)


def aggregate_context(out):
    """Age, activity, network and related-CVE context gathered from whichever sources answered."""
    ok = [v for v in out.values() if v["status"] in ("ok", "not_found")]
    firsts = [v["first_seen"] for v in ok if v.get("first_seen")]
    lasts = [v["last_seen"] for v in ok if v.get("last_seen")]
    regs = [v["registered"] for v in ok if v.get("registered")]
    ctx = {"first_seen": min(firsts) if firsts else None, "last_seen": max(lasts) if lasts else None,
           "registered": min(regs) if regs else None, "registrar": None, "network": None, "cves": []}
    rd = out.get("rdap")
    if rd and rd["status"] == "ok":
        ctx["registrar"] = rd["details"].get("Registrar")
    rs = out.get("ripestat")
    if rs and rs["status"] == "ok":
        ctx["network"] = rs.get("meta")
    sh = out.get("shodan")
    if sh and sh["status"] == "ok":
        ctx["cves"] = (sh.get("meta") or {}).get("cves", [])
    return ctx


def lookup(raw, selected=None, refresh=False):
    t, ioc = classify(refang(raw))
    base = {"input": raw, "ioc": ioc, "type": t, "providers": {}, "flagged": 0, "sources": 0,
            "pivots": pivots(ioc, t) if t != "unknown" else [],
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if t == "unknown":
        return {**base, "score": None, "verdict": "unknown", "note": "Unrecognised indicator format"}
    if is_internal(ioc, t):
        return {**base, "score": None, "verdict": "internal", "pivots": [],
                "note": "Private or reserved address: not sent to external services"}
    elig = [p for p in PROVIDERS.values() if t in p["types"] and (not selected or p["id"] in selected)]
    out = {}
    if elig:
        with ThreadPoolExecutor(max_workers=len(elig)) as ex:
            futs = {p["id"]: ex.submit(run_provider, p, ioc, t, refresh) for p in elig}
            for p in elig:
                out[p["id"]] = futs[p["id"]].result()
    score, n = consolidate(out)
    flagged = sum(1 for v in out.values() if v["status"] == "ok" and (v["score"] or 0) >= 40)
    return {**base, "providers": out, "score": score, "verdict": band(score), "flagged": flagged, "sources": n,
            "ctx": aggregate_context(out)}


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/providers")
def api_providers():
    return jsonify([{"id": p["id"], "name": p["name"], "short": p["short"], "types": sorted(p["types"]),
                     "configured": configured(p), "env": p["env"], "desc": p["desc"], "daily": p["daily"]}
                    for p in PROVIDERS.values()])


@app.get("/api/health")
def api_health():
    out, today = [], date.today().isoformat()
    with HLOCK:
        for p in PROVIDERS.values():
            h = HEALTH.get(p["id"])
            conf = configured(p)
            recent = list(h["recent"]) if h else []
            state = ("off" if not conf else "idle" if not recent else "bad" if not recent[-1]
                     else "warn" if not all(recent) else "ok")
            out.append({"id": p["id"], "name": p["name"], "configured": conf, "state": state,
                        "calls_today": h["today"] if h and h["day"] == today else 0, "daily_limit": p["daily"],
                        "remaining": h["remaining"] if h else None, "rpm": p["rpm"] or None,
                        "last_error": h["last_error"] if h else None, "last_error_at": h["last_error_at"] if h else None,
                        "last_ok_at": h["last_ok_at"] if h else None})
    return jsonify(out)


@app.post("/api/history")
def api_history_add():
    b = request.get_json(force=True, silent=True) or {}
    results = b.get("results")
    if not isinstance(results, list) or not results:
        return jsonify({"error": "results are required"}), 400
    results = [r for r in results if isinstance(r, dict) and r.get("ioc")][: MAX_BULK * 2]
    mal = sum(1 for r in results if r.get("verdict") == "malicious")
    sus = sum(1 for r in results if r.get("verdict") == "suspicious")
    return jsonify({"id": store.add_batch(str(b.get("label") or "")[:120], len(results), mal, sus, results)})


@app.get("/api/history")
def api_history_list():
    return jsonify(store.list_batches())


@app.get("/api/history/<int:bid>")
def api_history_get(bid):
    r = store.get_batch(bid)
    return (jsonify({"results": r}) if r is not None else (jsonify({"error": "Not found"}), 404))


@app.delete("/api/history/<int:bid>")
def api_history_delete(bid):
    store.delete_batch(bid)
    return jsonify({"ok": True})


@app.post("/api/parse")
def api_parse():
    text = (request.get_json(force=True, silent=True) or {}).get("text", "")
    seen, items, skipped = set(), [], []
    for tok in re.split(r"[\s,;|]+", text):
        tok = refang(tok).strip("<>(){}\"'")
        if not tok:
            continue
        t, v = classify(tok)
        if t == "unknown":
            if len(skipped) < 50:
                skipped.append(tok[:80])
            continue
        if v in seen:
            continue
        seen.add(v)
        items.append({"input": tok, "ioc": v, "type": t})
    truncated = len(items) > MAX_BULK
    return jsonify({"items": items[:MAX_BULK], "skipped": skipped, "truncated": truncated, "total": len(items)})


@app.post("/api/lookup")
def api_lookup():
    body = request.get_json(force=True, silent=True) or {}
    raw = str(body.get("ioc", ""))[:2048]
    if not raw.strip():
        return jsonify({"error": "ioc is required"}), 400
    return jsonify(lookup(raw, set(body.get("providers") or []), bool(body.get("refresh"))))


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    live = [p["name"] for p in PROVIDERS.values() if configured(p)]
    print(f"ThreatLens on http://{host}:{port}  |  active providers: {', '.join(live) or 'none'}")
    app.run(host=host, port=port, threaded=True)
