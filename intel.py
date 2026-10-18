"""
ThreatLens intel module.

  1. News search across security RSS/Atom feeds (plus optional Bing News RSS).
  2. Safe article fetching and text extraction.
  3. IOC extraction (IP, domain, URL, hash, CVE) with confidence and noise filtering.
  4. MITRE ATT&CK mapping driven by the real ATT&CK dataset: explicit IDs,
     technique names, curated behaviour rules, and actor / malware profiles.
  5. ATT&CK Navigator layer export.
"""
import hashlib
import html as htmllib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from flask import Blueprint, jsonify, request

import store

try:
    import defusedxml.ElementTree as ET  # protects against entity-expansion attacks
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET
    print("warning: defusedxml not installed; run pip install defusedxml", file=sys.stderr)

bp = Blueprint("intel", __name__)
BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
ATTACK_PATH = os.path.join(DATA_DIR, "attack_index.json")
FEEDS_PATH = os.path.join(DATA_DIR, "feeds.json")
STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack.json")
UA = "ThreatLens/1.1 (+SOC news intel)"
FEED_TTL = int(os.getenv("FEED_TTL", "900"))
MAX_BYTES = 3_000_000
MAX_TEXT = 400_000

# --------------------------------------------------------------------------
# Feeds
# --------------------------------------------------------------------------
FEEDS_DEFAULT = [
    {"id": "bleeping", "name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"id": "thn", "name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"id": "krebs", "name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"id": "cisa", "name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"id": "unit42", "name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"id": "talos", "name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/"},
    {"id": "msft", "name": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"id": "gti", "name": "Google Threat Intel", "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"},
    {"id": "dfir", "name": "The DFIR Report", "url": "https://thedfirreport.com/feed/"},
    {"id": "sans", "name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},
    {"id": "securelist", "name": "Securelist", "url": "https://securelist.com/feed/"},
    {"id": "eset", "name": "WeLiveSecurity", "url": "https://www.welivesecurity.com/en/rss/feed/"},
    {"id": "elastic", "name": "Elastic Security Labs", "url": "https://www.elastic.co/security-labs/rss/feed.xml"},
    {"id": "sophos", "name": "Sophos X-Ops", "url": "https://news.sophos.com/en-us/category/threat-research/feed/"},
    {"id": "securityweek", "name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek"},
    {"id": "record", "name": "The Record", "url": "https://therecord.media/feed"},
    {"id": "darkreading", "name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
]


def load_feeds():
    if os.path.exists(FEEDS_PATH):
        try:
            with open(FEEDS_PATH, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                return data
        except Exception as e:  # noqa: BLE001
            print("feeds.json unreadable, using defaults:", e, file=sys.stderr)
    return FEEDS_DEFAULT


FEED_CACHE = {}
FEED_LOCK = threading.Lock()
ARTICLES = OrderedDict()  # id -> item (kept server-side so the browser only sends an id)


def local(tag):
    return tag.split("}")[-1] if isinstance(tag, str) else ""


def strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s or "")
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", htmllib.unescape(s)).strip()


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except Exception:  # noqa: BLE001
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def parse_feed(content, source):
    root = ET.fromstring(content)
    items = []
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"):
            continue
        d = {"title": "", "link": "", "date": None, "summary": "", "body": ""}
        for ch in el:
            n = local(ch.tag)
            if n == "title":
                d["title"] = strip_html(ch.text or "")
            elif n == "link":
                href = ch.get("href")
                if href:
                    if ch.get("rel") in (None, "alternate") and not d["link"]:
                        d["link"] = href.strip()
                elif (ch.text or "").strip() and not d["link"]:
                    d["link"] = ch.text.strip()
            elif n in ("pubDate", "published", "updated", "date") and not d["date"]:
                d["date"] = parse_date(ch.text)
            elif n in ("description", "summary"):
                d["summary"] = strip_html(ch.text or "")[:500]
                d["body"] = d["body"] or (ch.text or "")
            elif n in ("encoded", "content"):
                d["body"] = ch.text or d["body"]
        if not d["link"] or not d["title"]:
            continue
        d["source"] = source
        d["id"] = hashlib.sha1(d["link"].encode()).hexdigest()[:14]
        items.append(d)
    return items


def remember(items):
    for it in items:
        ARTICLES[it["id"]] = it
        ARTICLES.move_to_end(it["id"])
    while len(ARTICLES) > 3000:
        ARTICLES.popitem(last=False)


def fetch_feed(feed, refresh=False):
    with FEED_LOCK:
        hit = FEED_CACHE.get(feed["id"])
        if hit and not refresh and time.time() - hit[0] < FEED_TTL:
            return hit[1]
    r = requests.get(feed["url"], timeout=12, headers={
        "User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
    r.raise_for_status()
    items = parse_feed(r.content, feed["name"])
    with FEED_LOCK:
        FEED_CACHE[feed["id"]] = (time.time(), items)
    return items


def bing_news(q):
    r = requests.get("https://www.bing.com/news/search", params={"q": q, "format": "rss", "count": 30},
                     timeout=12, headers={"User-Agent": UA})
    r.raise_for_status()
    items = parse_feed(r.content, "Web news")
    for it in items:
        real = parse_qs(urlparse(it["link"]).query).get("url")
        if real:
            it["link"] = unquote(real[0])
            it["id"] = hashlib.sha1(it["link"].encode()).hexdigest()[:14]
    return items


def search_terms(q):
    return [(a or b).lower() for a, b in re.findall(r'"([^"]+)"|(\S+)', q)]



# --------------------------------------------------------------------------
# AlienVault OTX pulses (needs OTX_API_KEY)
# --------------------------------------------------------------------------
OTX_BASE = "https://otx.alienvault.com"
OTX_TYPES = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash", "CVE": "cve"}
OTX_MAX_IOCS = 2000


def otx_key():
    return os.getenv("OTX_API_KEY", "").strip()


def otx_get(path, **params):
    r = requests.get(OTX_BASE + path, params=params, timeout=25,
                     headers={"X-OTX-API-KEY": otx_key(), "User-Agent": UA})
    if r.status_code in (401, 403):
        raise RuntimeError("OTX rejected the API key")
    if r.status_code == 429:
        raise RuntimeError("OTX rate limit reached, try again in a minute")
    r.raise_for_status()
    return r.json()


def pulse_item(p):
    pid = str(p.get("id"))
    desc = strip_html(p.get("description") or "")
    tags = ", ".join((p.get("tags") or [])[:6])
    n = p.get("indicator_count") or len(p.get("indicators") or [])
    summary = (desc[:260] + (" " if desc else "") + (f"Tags: {tags}. " if tags else "") + f"{n} indicators.").strip()
    return {"id": "otx-" + pid, "otx_id": pid, "title": strip_html(p.get("name") or "Untitled pulse"),
            "link": f"{OTX_BASE}/pulse/{pid}", "source": "OTX · " + (p.get("author_name") or "community"),
            "date": parse_date(p.get("modified") or p.get("created")), "summary": summary, "body": "",
            "prefiltered": True}


def otx_items(q, days, refresh=False):
    ck = f"otx:{q}:{days}"
    with FEED_LOCK:
        hit = FEED_CACHE.get(ck)
        if hit and not refresh and time.time() - hit[0] < FEED_TTL:
            return hit[1]
    if q:
        data = otx_get("/api/v1/search/pulses", q=q, limit=30, sort="-modified")
    else:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        data = otx_get("/api/v1/pulses/subscribed", limit=30, modified_since=since)
        if not data.get("results"):
            data = otx_get("/api/v1/pulses/activity", limit=30)
    items = [pulse_item(p) for p in data.get("results", []) if p.get("id")]
    with FEED_LOCK:
        FEED_CACHE[ck] = (time.time(), items)
    return items


def tech_entry(tid, score, evidence):
    t = ATTACK["techniques"][tid]
    return {"id": tid, "name": t["full"], "tactics": t["tactics"], "score": score,
            "band": "high" if score >= 75 else "medium" if score >= 55 else "low", "desc": t["desc"],
            "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/", "evidence": evidence}


def analyze_pulse(item):
    p = otx_get(f"/api/v1/pulses/{item['otx_id']}")
    iocs, seen, other = [], set(), {}
    inds = p.get("indicators") or []
    for ind in inds[:OTX_MAX_IOCS]:
        typ = OTX_TYPES.get(ind.get("type"))
        val = str(ind.get("indicator") or "").strip()
        if not typ:
            other[ind.get("type", "other")] = other.get(ind.get("type", "other"), 0) + 1
            continue
        if typ == "hash":
            val = val.lower()
            if len(val) not in (32, 40, 64) or not re.fullmatch(r"[a-f0-9]+", val):
                continue
        elif typ == "ip":
            try:
                ip = ipaddress.ip_address(val)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                continue
            val = str(ip)
        elif typ == "domain":
            val = val.lower().rstrip(".")
            if "." not in val or " " in val or len(val) > 253:
                continue
        elif typ == "cve":
            val = val.upper()
        if (typ, val) in seen or not val:
            continue
        seen.add((typ, val))
        active = ind.get("is_active", 1) not in (0, False)
        ctx = re.sub(r"\s+", " ", " ".join(x for x in (ind.get("title"), ind.get("description"), ind.get("role")) if x)).strip()
        iocs.append({"value": val, "type": typ, "count": 1, "confidence": "high" if active else "low",
                     "defanged": False, "context": ctx[:200] or "Listed in this OTX pulse" + ("" if active else " (marked inactive)")})
    order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "cve": 4}
    iocs.sort(key=lambda x: (x["confidence"] != "high", order[x["type"]], x["value"]))

    fams = [m.get("display_name") or m.get("id") for m in (p.get("malware_families") or []) if isinstance(m, dict)]
    text = "\n".join(x for x in [p.get("name"), strip_html(p.get("description") or ""),
                                 "Adversary: " + p["adversary"] if p.get("adversary") else "",
                                 "Malware: " + ", ".join(f for f in fams if f) if fams else "",
                                 ", ".join(p.get("tags") or [])] if x)
    attack = map_attack(text)
    unmapped = []
    tags = [t for t in (p.get("attack_ids") or []) if isinstance(t, dict)]
    if attack is not None:
        by = {t["id"]: t for t in attack["techniques"]}
        for tag in tags:
            tid = str(tag.get("id") or "").strip().upper()
            ev = {"kind": "OTX tag", "match": tid, "snippet": "Tagged with this technique by the pulse author."}
            if tid in ATTACK["techniques"]:
                if tid in by:
                    by[tid]["evidence"].insert(0, ev)
                    by[tid]["score"], by[tid]["band"] = max(by[tid]["score"], 90), "high"
                else:
                    by[tid] = tech_entry(tid, 90, [ev])
                    attack["techniques"].append(by[tid])
            elif tid:
                unmapped.append({"id": tid, "name": tag.get("name") or tag.get("display_name") or ""})
        attack["techniques"].sort(key=lambda x: -x["score"])
    else:
        unmapped = [{"id": str(t.get("id")), "name": t.get("name") or ""} for t in tags]

    total = p.get("indicator_count") or len(inds)
    notes = []
    if total > OTX_MAX_IOCS:
        notes.append(f"Showing the first {OTX_MAX_IOCS} of {total} indicators.")
    if other:
        notes.append("Not shown (not checkable here): " + ", ".join(f"{k} x{v}" for k, v in sorted(other.items())) + ".")
    refs = [r for r in (p.get("references") or []) if isinstance(r, str) and r.startswith(("http://", "https://"))][:8]
    return {"title": strip_html(p.get("name") or "OTX pulse"), "link": item["link"], "source": item["source"],
            "date": item["date"].isoformat() if item["date"] else None, "chars": len(text), "note": " ".join(notes),
            "iocs": iocs, "attack": attack, "attack_loaded": attack is not None,
            "counts": {t: sum(1 for i in iocs if i["type"] == t) for t in ("ip", "domain", "url", "hash", "cve")},
            "otx": {"author": p.get("author_name"), "tlp": (p.get("TLP") or p.get("tlp") or "").lower(),
                    "adversary": p.get("adversary"), "malware": [f for f in fams if f][:8],
                    "tags": (p.get("tags") or [])[:12], "industries": (p.get("industries") or [])[:6],
                    "countries": (p.get("targeted_countries") or [])[:8], "references": refs, "unmapped_attack": unmapped}}


@bp.get("/api/feeds")
def api_feeds():
    out = [{"id": f["id"], "name": f["name"], "configured": True} for f in load_feeds()]
    out.append({"id": "otx", "name": "AlienVault OTX pulses", "configured": bool(otx_key()), "env": "OTX_API_KEY"})
    return jsonify(out)


def match_terms(it, terms, honor_prefilter=True):
    if not terms or (honor_prefilter and it.get("prefiltered")):
        return True
    hay = (it["title"] + " " + it["summary"]).lower()
    return all(t in hay for t in terms)


def search_items(q, days, wanted, refresh=False, web=False):
    """Fetch feeds (cached), apply keyword + date filters. Returns (items, errors, feed_count)."""
    feeds = [f for f in load_feeds() if not wanted or f["id"] in wanted]
    items, errors = [], []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [(f, ex.submit(fetch_feed, f, refresh)) for f in feeds]
        for f, fut in futs:
            try:
                items += fut.result()
            except Exception as e:  # noqa: BLE001
                errors.append({"source": f["name"], "error": str(e)[:110]})
    if otx_key() and (not wanted or "otx" in wanted):
        try:
            items += otx_items(q, days, refresh)
        except Exception as e:  # noqa: BLE001
            errors.append({"source": "AlienVault OTX", "error": str(e)[:110]})
    if web and q:
        try:
            items += bing_news(q)
        except Exception as e:  # noqa: BLE001
            errors.append({"source": "Web news (Bing)", "error": str(e)[:110]})
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    terms = search_terms(q)
    seen, out = set(), []
    for it in items:
        if it["link"] in seen:
            continue
        seen.add(it["link"])
        if it["date"] and it["date"] < cutoff:
            continue
        if not match_terms(it, terms):
            continue
        out.append(it)
    remember(out)
    out.sort(key=lambda x: x["date"] or datetime(1970, 1, 1, tzinfo=timezone.utc), reverse=True)
    return out, errors, len(feeds)


@bp.get("/api/news")
def api_news():
    q = request.args.get("q", "").strip()
    try:
        days = float(request.args.get("days", "7"))
    except ValueError:
        days = 7
    wanted = {x for x in request.args.get("sources", "").split(",") if x}
    out, errors, nfeeds = search_items(q, days, wanted, request.args.get("refresh") == "1",
                                       request.args.get("web") == "1")
    shown = out[:200]
    done = store.analysed_ids([i["id"] for i in shown])
    return jsonify({"items": [{"id": i["id"], "title": i["title"], "link": i["link"], "source": i["source"],
                               "date": i["date"].isoformat() if i["date"] else None, "summary": i["summary"],
                               "analyzed": i["id"] in done} for i in shown],
                    "total": len(out), "errors": errors, "feeds": nfeeds})


# --------------------------------------------------------------------------
# Safe fetching + HTML to text
# --------------------------------------------------------------------------
def check_url(u):
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only http(s) URLs are allowed")
    if p.port not in (None, 80, 443):
        raise ValueError("Only ports 80 and 443 are allowed")
    for info in socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise ValueError("That address is on a private network and is blocked")


def safe_fetch(url):
    """Fetch with SSRF guards: re-validates every redirect hop, caps size."""
    for _ in range(5):
        check_url(url)
        r = requests.get(url, timeout=15, stream=True, allow_redirects=False, headers={
            "User-Agent": "Mozilla/5.0 (compatible; ThreatLens/1.1)", "Accept": "text/html,text/plain,*/*"})
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        r.raise_for_status()
        buf = b""
        for chunk in r.iter_content(65536):
            buf += chunk
            if len(buf) > MAX_BYTES:
                break
        ctype = r.headers.get("Content-Type", "")
        enc = r.encoding or "utf-8"
        r.close()
        return buf.decode(enc, errors="replace"), ctype, url
    raise ValueError("Too many redirects")


class TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "aside", "form", "iframe", "template"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "table", "section",
             "article", "blockquote", "ul", "ol"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip, self.title, self._in_title = [], 0, "", False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        if tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False
        if tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self.skip:
            self.out.append(data)


def html_to_text(markup):
    p = TextExtractor()
    try:
        p.feed(markup)
    except Exception:  # noqa: BLE001
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.out))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return p.title.strip(), text[:MAX_TEXT]


# --------------------------------------------------------------------------
# IOC extraction
# --------------------------------------------------------------------------
def refang_text(s):
    s = re.sub(r"hxxp", "http", s, flags=re.I)
    s = re.sub(r"fxp://", "ftp://", s, flags=re.I)
    for a in (r"\[\.\]", r"\(\.\)", r"\{\.\}", r"\[dot\]", r"\(dot\)"):
        s = re.sub(a, ".", s, flags=re.I)
    s = s.replace("[:]", ":").replace("[://]", "://").replace("[@]", "@")
    return re.sub(r"\[at\]", "@", s, flags=re.I)


DEFANG_TOKEN = re.compile(r"\S*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|hxxp|\[:\]|\[://\])\S*", re.I)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\\^{}|]+", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d]|\.\d)")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DOMAIN_RE = re.compile(r"(?<![\w@./:-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![\w-])", re.I)

GTLDS = set("""com net org info biz io xyz top site online club shop store tech app dev cloud live link click work icu vip
pro gov edu mil int name mobi asia tel art bar cam cfd sbs rest fun lol one page space website world today life news
email support services solutions network systems digital agency center company zone download review stream win bid
loan men party date trade webcam gdn kim buzz monster quest wiki academy bank best blog chat city codes design direct
domains expert finance fit global group host hosting help bio llc ltd inc tools run works media team ink pw onion
gq ml cf ga tk""".split())
CCTLDS = set("""ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge
gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn
kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne
nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm
sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws
ye yt za zm zw""".split())
FILEY_TLDS = {"py", "sh", "pl", "rs", "ps", "md", "so", "cc"}
BENIGN_DOMAINS = set("""microsoft.com windows.com office.com live.com bing.com google.com googleapis.com gstatic.com github.com
githubusercontent.com gitlab.com twitter.com x.com t.co linkedin.com facebook.com youtube.com youtu.be wikipedia.org
mitre.org attack.mitre.org virustotal.com cisa.gov nist.gov nvd.nist.gov cve.org w3.org schema.org mozilla.org apple.com
amazon.com cloudflare.com medium.com reddit.com bleepingcomputer.com thehackernews.com example.com example.org
example.net symantec.com mcafee.com kaspersky.com crowdstrike.com paloaltonetworks.com talosintelligence.com
sentinelone.com fireeye.com mandiant.com trendmicro.com eset.com sophos.com proofpoint.com recordedfuture.com
abuse.ch otx.alienvault.com shodan.io censys.io urlscan.io hybrid-analysis.com any.run asp.net vb.net
feedburner.com wordpress.com wp.com bit.ly goo.gl tinyurl.com mailchimp.com archive.org web.archive.org
ibm.com oracle.com cisco.com fortinet.com vmware.com broadcom.com adobe.com zoom.us slack.com""".split())
SAFE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
CONTEXT_RE = re.compile(r"indicator|\bioc|c2|c&c|command[- ]and[- ]control|malicious|payload|download|dropper|loader|phishing|"
                        r"exfiltrat|beacon|sha-?256|sha-?1\b|md5|observed|attributed|infrastructure|callback|staging|"
                        r"resolve|connect(s|ed|ing)? to|hosted|domain|address", re.I)


def host_in(host, domains):
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def _valid_domain(d, defanged):
    d = d.lower().rstrip(".")
    if len(d) > 253 or ".." in d:
        return False
    tld = d.rsplit(".", 1)[-1]
    if tld in FILEY_TLDS and not defanged:
        return False
    if tld not in CCTLDS and tld not in GTLDS:
        return False
    if tld == "zip" or tld == "mov":
        return defanged
    return not re.fullmatch(r"[\d.]+", d)


def _scan(t, skip_hosts=()):
    """Yield (type, value, start) for everything IOC-shaped in text t (already refanged)."""
    for m in URL_RE.finditer(t):
        v = m.group(0).rstrip(".,;:!?)]}'\"")
        if len(v) > 8:
            yield "url", v, m.start()
    for m in IP_RE.finditer(t):
        yield "ip", m.group(0), m.start()
    for m in HASH_RE.finditer(t):
        v = m.group(0).lower()
        if re.search(r"[a-f]", v) and re.search(r"\d", v) and len(set(v)) > 4:
            yield "hash", v, m.start()
    for m in CVE_RE.finditer(t):
        yield "cve", m.group(0).upper(), m.start()
    for m in DOMAIN_RE.finditer(t):
        yield "domain", m.group(0).lower().rstrip("."), m.start()


def extract_iocs(text, own_hosts=()):
    refanged = refang_text(text)
    defanged = set()
    for tok in DEFANG_TOKEN.findall(text):
        for typ, val, _ in _scan(refang_text(tok)):
            defanged.add((typ, val))
    found = OrderedDict()
    for typ, val, pos in _scan(refanged):
        is_def = (typ, val) in defanged
        if typ == "domain":
            if not _valid_domain(val, is_def):
                continue
            if not is_def and (host_in(val, BENIGN_DOMAINS) or host_in(val, own_hosts)):
                continue
        elif typ == "url":
            host = urlparse(val).hostname or ""
            if not is_def and (host_in(host, BENIGN_DOMAINS) or host_in(host, own_hosts)):
                continue
        elif typ == "ip":
            try:
                ip = ipaddress.ip_address(val)
            except ValueError:
                continue
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                    or ip.is_unspecified) or (val in SAFE_IPS and not is_def):
                continue
        key = (typ, val)
        if key not in found:
            ctx = refanged[max(0, pos - 90):pos + len(val) + 90]
            window = refanged[max(0, pos - 220):pos + len(val) + 220]
            found[key] = {"value": val, "type": typ, "count": 0, "defanged": is_def,
                          "context": re.sub(r"\s+", " ", ctx).strip(), "has_context": bool(CONTEXT_RE.search(window))}
        found[key]["count"] += 1
    out = []
    for f in found.values():
        conf = "high" if (f["defanged"] or f["type"] in ("hash", "cve")) else "medium" if f["has_context"] else "low"
        out.append({"value": f["value"], "type": f["type"], "count": f["count"], "confidence": conf,
                    "defanged": f["defanged"], "context": f["context"]})
    rank = {"high": 0, "medium": 1, "low": 2}
    order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "cve": 4}
    out.sort(key=lambda x: (rank[x["confidence"]], order[x["type"]], -x["count"], x["value"]))
    return out


# --------------------------------------------------------------------------
# MITRE ATT&CK index
# --------------------------------------------------------------------------
ATTACK = {"loaded": False}
ATTACK_LOCK = threading.Lock()


def _clean_desc(s):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    return re.sub(r"\s+", " ", s).strip()


def build_attack_index(stix):
    objs = stix["objects"]
    byid = {o["id"]: o for o in objs}

    def ext(o):
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                return r.get("external_id")
        return None

    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic"}
    order = []
    matrices = [o for o in objs if o["type"] == "x-mitre-matrix"]
    if matrices:
        order = [byid[r]["x_mitre_shortname"] for r in matrices[0].get("tactic_refs", []) if r in byid]
    tactics = [{"id": s, "name": tactic_names.get(s, s)} for s in order]

    techs, stix2tid = {}, {}
    for o in objs:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = ext(o)
        if not tid:
            continue
        stix2tid[o["id"]] = tid
        techs[tid] = {"name": o["name"], "sub": "." in tid, "desc": _clean_desc(o.get("description"))[:420],
                      "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                  if p.get("kill_chain_name") == "mitre-attack"]}
    for tid, t in techs.items():
        if t["sub"]:
            parent = techs.get(tid.split(".")[0])
            t["full"] = f"{parent['name']}: {t['name']}" if parent else t["name"]
            if parent and not t["tactics"]:
                t["tactics"] = parent["tactics"]
        else:
            t["full"] = t["name"]

    groups, software = {}, {}
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] == "intrusion-set":
            groups[o["id"]] = {"id": ext(o), "name": o["name"], "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
                               "type": "group", "techniques": set()}
        elif o["type"] in ("malware", "tool"):
            software[o["id"]] = {"id": ext(o), "name": o["name"],
                                 "aliases": [a for a in o.get("x_mitre_aliases", []) if a != o["name"]],
                                 "type": o["type"], "techniques": set()}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses" and not o.get("revoked"):
            tid = stix2tid.get(o.get("target_ref"))
            if not tid:
                continue
            ent = groups.get(o["source_ref"]) or software.get(o["source_ref"])
            if ent:
                ent["techniques"].add(tid)

    def finish(d):
        return {e["id"]: {**{k: v for k, v in e.items() if k != "id"}, "techniques": sorted(e["techniques"])}
                for e in d.values() if e["id"] and e["techniques"]}

    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    return {"meta": {"version": coll.get("x_mitre_version", "unknown"), "built": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                     "techniques": len(techs)},
            "tactics": tactics, "techniques": techs, "groups": finish(groups), "software": finish(software)}


def load_attack(force=False):
    with ATTACK_LOCK:
        if ATTACK.get("loaded") and not force:
            return ATTACK
        if not os.path.exists(ATTACK_PATH):
            ATTACK.clear()
            ATTACK.update({"loaded": False})
            return ATTACK
        with open(ATTACK_PATH, encoding="utf-8") as f:
            idx = json.load(f)
        ATTACK.clear()
        ATTACK.update(idx)
        ATTACK["loaded"] = True
        ATTACK["entities"] = _prepare_entities(idx)
        ATTACK["rules"] = [(re.compile(p, re.I), [i for i in ids if i in idx["techniques"]], w, p) for p, ids, w in RULES]
        ATTACK["rules"] = [r for r in ATTACK["rules"] if r[1]]
        return ATTACK


GENERIC_SOFTWARE = {"certutil", "systeminfo", "tasklist", "netstat", "ipconfig", "nbtstat", "xcopy", "robocopy", "schtasks",
                    "dsquery", "nltest", "wevtutil", "bitsadmin", "regsvr32", "rundll32", "powershell", "windows", "linux"}


def _prepare_entities(idx):
    ents = []
    for kind in ("groups", "software"):
        for eid, e in idx[kind].items():
            names = [e["name"]] + e.get("aliases", [])
            for n in names:
                n = n.strip()
                if len(n) < 5 or n.lower() in GENERIC_SOFTWARE:
                    continue
                ents.append({"eid": eid, "name": e["name"], "alias": n, "type": e["type"], "ci": len(n) >= 8,
                             "techniques": e["techniques"], "aliases": e.get("aliases", [])[:4]})
    return ents


def refresh_attack():
    r = requests.get(STIX_URL, timeout=180, headers={"User-Agent": UA})
    r.raise_for_status()
    idx = build_attack_index(r.json())
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(ATTACK_PATH, "w", encoding="utf-8") as f:
        json.dump(idx, f)
    store.purge_results()
    return load_attack(force=True)


# (regex, technique ids, confidence weight). Unknown ids are dropped at load time, so the
# table stays safe across ATT&CK versions.
RULES = [
    (r"\bpower\s?shell\b|\bpwsh\b", ["T1059.001"], 80),
    (r"\bcmd\.exe\b|windows command shell|command prompt", ["T1059.003"], 70),
    (r"\bwscript\b|\bcscript\b|\bvbscript\b|\bvbs\b|\bvba\b", ["T1059.005"], 75),
    (r"malicious javascript|\bjscript\b|\.js (file|payload|loader|dropper)", ["T1059.007"], 65),
    (r"\bpython (script|payload|backdoor|implant|loader)", ["T1059.006"], 65),
    (r"\bbash (script|shell)|\bshell script", ["T1059.004"], 60),
    (r"\bspear-?phishing\b|\bphishing (email|campaign|message|lure|page|kit)s?\b|\bphishing\b", ["T1566"], 70),
    (r"malicious (attachment|document|office|word|excel|pdf|doc|xls)|weaponi[sz]ed (document|attachment|office)|malicious email attachment", ["T1566.001"], 78),
    (r"(malicious|phishing|spear-?phishing|credential[- ]harvesting) (link|url)s?\b|click(ing)? (on )?(a|the) (malicious )?link", ["T1566.002"], 72),
    (r"\bvishing\b|voice phishing|phone call.{0,40}(help ?desk|impersonat)", ["T1566.004"], 82),
    (r"\bqr codes?\b.{0,30}(phish|malicious)|\bquishing\b", ["T1566.002"], 72),
    (r"\bmacros?\b", ["T1204.002", "T1059.005"], 58),
    (r"\bclickfix\b|fake captcha|paste.{0,40}(powershell|command).{0,40}(run dialog|win\s?\+\s?r)", ["T1204.004"], 82),
    (r"public-facing|internet-facing|exposed (server|service|interface)|(vpn|firewall|gateway) (appliance|vulnerab)", ["T1190"], 76),
    (r"exploited in the wild|actively exploited|zero-?day", ["T1190"], 55),
    (r"\bbrute[- ]?forc(e|ing)\b", ["T1110"], 75),
    (r"\bpassword spray(ing)?\b", ["T1110.003"], 88),
    (r"\bcredential stuffing\b", ["T1110.004"], 88),
    (r"\bmimikatz\b|\blsass\b|credential dump(ing)?", ["T1003.001"], 85),
    (r"\bdcsync\b", ["T1003.006"], 92),
    (r"\bntds\.dit\b", ["T1003.003"], 88),
    (r"\bsam (hive|database)\b", ["T1003.002"], 80),
    (r"\bkerberoast(ing)?\b", ["T1558.003"], 92),
    (r"\bgolden ticket\b", ["T1558.001"], 92),
    (r"as-?rep roast", ["T1558.004"], 92),
    (r"pass[- ]the[- ]hash", ["T1550.002"], 92),
    (r"pass[- ]the[- ]ticket", ["T1550.003"], 92),
    (r"\bkeylogg(er|ing)\b|keystroke (log|captur)", ["T1056.001"], 82),
    (r"\bscreenshots?\b|screen captur", ["T1113"], 55),
    (r"scheduled tasks?\b|\bschtasks\b", ["T1053.005"], 82),
    (r"\bcron ?jobs?\b|\bcrontab\b", ["T1053.003"], 78),
    (r"\brun keys?\b|currentversion\\run|startup folder", ["T1547.001"], 86),
    (r"registry (key|value|modification)s?", ["T1112"], 50),
    (r"\bsc(\.exe)? create\b|install(ed|ing)? (it )?as a (new )?(windows )?service|new service", ["T1543.003"], 72),
    (r"dll side-?load(ing)?|dll (hijack|search order hijack)", ["T1574.001"], 92),
    (r"process hollowing", ["T1055.012"], 92),
    (r"process injection|inject(s|ed|ing)? (code |a payload |malicious code |shellcode )?into", ["T1055"], 72),
    (r"dll injection", ["T1055.001"], 86),
    (r"reflective (dll|code|loading|pe)", ["T1620"], 86),
    (r"\bobfuscat(ed|ion|e|es)\b|encoded (payload|command|script)", ["T1027"], 66),
    (r"\bbase64\b", ["T1027", "T1140"], 46),
    (r"\bpack(ed|er|ing)\b.{0,30}(binary|payload|executable|malware)|\bupx\b", ["T1027.002"], 66),
    (r"steganograph", ["T1027.003"], 86),
    (r"\brundll32\b", ["T1218.011"], 82),
    (r"\bregsvr32\b", ["T1218.010"], 86),
    (r"\bmshta\b", ["T1218.005"], 86),
    (r"\bmsiexec\b", ["T1218.007"], 72),
    (r"\bcmstp\b", ["T1218.003"], 86),
    (r"\binstallutil\b", ["T1218.004"], 86),
    (r"\bmsbuild\b", ["T1127.001"], 82),
    (r"\bcertutil\b", ["T1105", "T1140"], 68),
    (r"\bbitsadmin\b|\bbits job", ["T1197"], 86),
    (r"\bwmic\b|windows management instrumentation|\bwmi\b", ["T1047"], 76),
    (r"\bpsexec\b", ["T1569.002", "T1021.002"], 72),
    (r"\blolbins?\b|living[- ]off[- ]the[- ]land|\blolbas\b", ["T1218"], 56),
    (r"uac bypass|bypass(ing)? user account control", ["T1548.002"], 90),
    (r"token (impersonation|theft|manipulation)", ["T1134"], 82),
    (r"remote desktop|\brdp\b", ["T1021.001"], 72),
    (r"\bsmb\b.{0,30}(lateral|share)|admin\$", ["T1021.002"], 66),
    (r"\bwinrm\b|windows remote management", ["T1021.006"], 86),
    (r"\bssh\b.{0,30}(lateral|brute|login|access)|ssh (key|session|tunnel)", ["T1021.004"], 62),
    (r"\bvalid accounts?\b|stolen credentials?|compromised (credentials|accounts?)|legitimate credentials", ["T1078"], 72),
    (r"\bexternal remote services?\b|vpn.{0,30}(credentials|access|login)", ["T1133"], 58),
    (r"mfa (fatigue|bombing)|push (notification )?(bombing|fatigue|spam)", ["T1621"], 92),
    (r"adversary[- ]in[- ]the[- ]middle|\baitm\b|\bevilginx\b|\bmodlishka\b|reverse[- ]proxy phishing", ["T1557"], 86),
    (r"session (cookie|token)s?.{0,30}(steal|theft|hijack|stolen)|cookie theft|steal(s|ing)? (session )?cookies", ["T1539"], 86),
    (r"\binfo-?stealers?\b|stealer malware", ["T1555", "T1005"], 66),
    (r"(browser|chrome|firefox|edge) (credential|password|saved password|cookie)s?", ["T1555.003"], 82),
    (r"\bransomware\b|ransom note|files? (were|was|are) encrypted|encrypt(s|ed|ing) (the )?(victim'?s? )?(files|data)", ["T1486"], 82),
    (r"\bvssadmin\b|shadow cop(y|ies)|\bwbadmin\b", ["T1490"], 86),
    (r"\bwipers?\b|destructive malware|wipe(s|d)? (the )?(disk|data|files)", ["T1485"], 72),
    (r"data exfiltrat\w*|\bexfiltrat(e|es|ed|ing)\b", ["T1041"], 52),
    (r"\brclone\b|\bmega\.nz\b|\bmegasync\b|exfiltrat\w*.{0,60}(dropbox|google drive|onedrive|cloud storage|s3 bucket)", ["T1567.002"], 84),
    (r"double extortion|data leak site|leak site", ["T1657"], 62),
    (r"dns tunnel(ing)?|dns over https|dns beacon", ["T1071.004", "T1572"], 86),
    (r"(c2|command[- ]and[- ]control|beacon\w*).{0,60}\bhttps?\b|\bhttps?\b.{0,60}(c2|command[- ]and[- ]control|beacon\w*)", ["T1071.001"], 76),
    (r"\bc2\b|command[- ]and[- ]control|\bc&c\b", ["T1071"], 48),
    (r"domain generation algorithm|\bdga\b", ["T1568.002"], 92),
    (r"\btor (network|hidden service|proxy)|\.onion\b", ["T1090.003"], 72),
    (r"\breverse proxy\b|\bsocks5?\b|\bngrok\b|\bchisel\b|\bfrp\b|proxy.{0,20}(tunnel|chain|implant)", ["T1090"], 66),
    (r"\bweb ?shells?\b", ["T1505.003"], 92),
    (r"supply[- ]chain (attack|compromise)|trojani[sz]ed (update|installer|software)|malicious (npm|pypi) package", ["T1195"], 76),
    (r"\btyposquat\w*|lookalike domain|newly registered domains?|registered (the )?domain", ["T1583.001"], 62),
    (r"drive-by|watering[- ]hole|\bmalvertis\w*", ["T1189"], 82),
    (r"\bseo poisoning\b|search engine optimi[sz]ation poisoning|sponsored (ads?|search results?)", ["T1608.006"], 72),
    (r"removable media|\busb\b.{0,30}(worm|propagat|infect|drive)", ["T1091"], 72),
    (r"anti-?(vm|analysis|sandbox|debug\w*)|sandbox evasion|virtuali[sz]ation (check|detection)|debugger (check|detection)", ["T1497"], 82),
    (r"disabl(e|es|ed|ing)\b.{0,40}(defender|antivirus|\bedr\b|security (tools|software|products)|endpoint protection|tamper protection)|\bedr (killer|evasion|bypass)\b|kill(s|ed|ing)? (av|edr|security) (processes|tools)", ["T1685"], 86),
    (r"\bbyovd\b|bring your own vulnerable driver|vulnerable driver", ["T1068", "T1685"], 74),
    (r"wevtutil|clear(s|ed|ing)? (the )?(windows )?event logs?|(delet|wip|clear)\w+ (the )?(system |security )?logs", ["T1685.005"], 82),
    (r"indicator removal|delet(e|es|ed|ing) (its|the) (own )?(files|artifacts|traces)|self-delet", ["T1070"], 62),
    (r"timestomp(ing)?", ["T1070.006"], 95),
    (r"masquerad(e|es|ed|ing)|disguis(e|ed|es) as (a )?(legitimate|benign)", ["T1036"], 76),
    (r"create(s|d)? (a )?(new )?(local |domain |admin(istrator)? )?(user )?account\b|net user .{0,30}/add", ["T1136"], 66),
    (r"\bbloodhound\b|\bsharphound\b", ["T1087.002", "T1069.002", "T1482"], 74),
    (r"\bnltest\b|domain trust", ["T1482"], 82),
    (r"\bwhoami\b", ["T1033"], 76),
    (r"\bnet (user|group|localgroup)\b", ["T1087"], 70),
    (r"\bipconfig\b|\barp -a\b|route print", ["T1016"], 76),
    (r"\bnetstat\b", ["T1049"], 76),
    (r"\btasklist\b|process discovery", ["T1057"], 76),
    (r"\bsysteminfo\b", ["T1082"], 80),
    (r"port scan(ning|ner)?|\bnmap\b|\bmasscan\b|network scanning", ["T1046"], 80),
    (r"network share discovery|\bnet view\b|share enumeration", ["T1135"], 80),
    (r"\b7-?zip\b|\bwinrar\b|rar archive|password-protected archive", ["T1560.001"], 60),
    (r"data staging|stag(e|ed|ing) (the )?(data|files)", ["T1074"], 70),
    (r"(email|mail(box)?|inbox) (forwarding )?rules?", ["T1114.003"], 70),
    (r"illicit consent|consent phishing|oauth (app|application|token)s?.{0,30}(malicious|abus|phish)", ["T1528"], 86),
    (r"\bimds\b|instance metadata|metadata service", ["T1552.005"], 84),
    (r"\baws (access )?keys?\b|hard-?coded (credentials|secrets|keys)|secrets? (in|leaked)", ["T1552.001"], 70),
    (r"container escape", ["T1611"], 86),
    (r"exposed (docker|kubernetes)|docker api", ["T1610"], 62),
    (r"cryptomin(er|ing)|\bxmrig\b|cryptojack\w*|coin ?miner", ["T1496"], 90),
    (r"\bddos\b|distributed denial[- ]of[- ]service|denial of service", ["T1498"], 80),
    (r"\bdefac(e|ed|ement|ing)\b", ["T1491"], 86),
    (r"remote access (tool|trojan)|\brat\b|\banydesk\b|\bscreenconnect\b|\bconnectwise\b|\bteamviewer\b|\batera\b|\bsplashtop\b|remote monitoring and management|\brmm\b", ["T1219"], 72),
    (r"ingress tool transfer|download(s|ed|ing)? (additional |a second[- ]stage |the )?(payload|malware|tools?|stager)|second[- ]stage|\bdropper\b|\bloader\b", ["T1105"], 62),
    (r"api hooking|inline hook", ["T1056.004"], 72),
    (r"(stolen|abused|fraudulent|valid).{0,20}(code[- ]signing )?certificate|code[- ]sign(ed|ing).{0,30}(stolen|abus|malicious)", ["T1553.002"], 80),
    (r"\bbootkit\b|uefi (implant|bootkit)|firmware implant", ["T1542"], 82),
    (r"\brootkit\b", ["T1014"], 82),
    (r"hidden (file|directory|window)s?", ["T1564"], 56),
    (r"discord (cdn|webhook)|telegram (bot|api)|\bpastebin\b|dead drop", ["T1102"], 74),
    (r"compromised (legitimate )?(websites?|wordpress sites?)|compromised infrastructure", ["T1584"], 66),
    (r"\bsocial engineering\b", ["T1566", "T1204"], 50),
]


def map_attack(text):
    A = load_attack()
    if not A.get("loaded"):
        return None
    techs = A["techniques"]
    tl = text.lower()
    ev = {}  # tid -> list of (score, kind, match, snippet)

    def snippet(a, b):
        return re.sub(r"\s+", " ", text[max(0, a - 100):b + 100]).strip()

    def add(tid, score, kind, m_text, a, b):
        ev.setdefault(tid, []).append((score, kind, m_text[:60], snippet(a, b)))

    for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", text):
        tid = m.group(0)
        if tid in techs:
            add(tid, 95, "explicit ID", tid, m.start(), m.end())
    for tid, t in techs.items():
        name = t["name"].lower()
        multi = len(name.split()) > 1
        if len(name) < 7 or name in NAME_STOP:
            continue
        if set(t["tactics"]) <= PRE_ATTACK and len(name.split()) < 3:
            continue  # pre-compromise names ("Malware", "Domains") are too generic in prose
        i = tl.find(name)
        if i < 0:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![a-z0-9])", tl):
            add(tid, 60 if multi else 50, "technique name", t["name"], i, i + len(name))
    for rx, ids, w, _ in A["rules"]:
        m = rx.search(text)
        if m:
            for tid in ids:
                add(tid, w, "behaviour", m.group(0), m.start(), m.end())

    found = []
    for tid, evs in ev.items():
        evs.sort(key=lambda e: -e[0])
        kinds = {e[1] for e in evs}
        score = min(100, evs[0][0] + 5 * (len(kinds) - 1) + min(6, len(evs) - 1))
        t = techs[tid]
        found.append({"id": tid, "name": t["full"], "tactics": t["tactics"], "score": score,
                      "band": "high" if score >= 75 else "medium" if score >= 55 else "low",
                      "desc": t["desc"], "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
                      "evidence": [{"kind": e[1], "match": e[2], "snippet": e[3]} for e in evs[:3]]})
    found.sort(key=lambda x: -x["score"])

    # actor / malware profiles
    ents, seen = {}, set()
    for e in A["entities"]:
        hay, needle = (tl, e["alias"].lower()) if e["ci"] else (text, e["alias"])
        i = hay.find(needle)
        if i < 0 or e["eid"] in seen:
            continue
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(needle) + r"(?![A-Za-z0-9])", hay):
            seen.add(e["eid"])
            ents[e["eid"]] = {"id": e["eid"], "name": e["name"], "matched": e["alias"], "type": e["type"],
                              "aliases": e["aliases"], "technique_count": len(e["techniques"]),
                              "techniques": e["techniques"],
                              "url": "https://attack.mitre.org/" + ("groups/" if e["type"] == "group" else "software/") + e["eid"] + "/"}
    entities = sorted(ents.values(), key=lambda x: (x["type"] != "group", x["name"]))[:12]
    catalog = {tid: {"name": techs[tid]["full"], "tactics": techs[tid]["tactics"],
                     "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}
               for e in entities for tid in e["techniques"] if tid in techs}
    return {"techniques": found, "entities": entities, "profile_catalog": catalog,
            "tactics": [{"id": t["id"], "name": t["name"]} for t in A["tactics"]]}


PRE_ATTACK = {"reconnaissance", "resource-development"}
NAME_STOP = {"malware", "exploits", "tools", "vulnerabilities", "botnet", "domains", "server", "serverless", "web service", "data manipulation", "domain accounts", "local accounts", "cloud accounts", "email accounts",
             "default accounts", "external proxy", "internal proxy", "code signing", "indicator removal", "impersonation",
             "hidden window", "scheduled transfer", "automated collection", "data staged", "user execution"}


@bp.get("/api/attack/meta")
def api_attack_meta():
    A = load_attack()
    if not A.get("loaded"):
        return jsonify({"loaded": False})
    return jsonify({"loaded": True, **A["meta"], "groups": len(A["groups"]), "software": len(A["software"])})


@bp.post("/api/attack/refresh")
def api_attack_refresh():
    try:
        A = refresh_attack()
        return jsonify({"loaded": True, **A["meta"]})
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Could not update ATT&CK data: {str(e)[:120]}"}), 502


# --------------------------------------------------------------------------
# Analysis endpoint
# --------------------------------------------------------------------------
def own_hosts_for(link):
    hosts = set()
    h = urlparse(link or "").hostname
    if h:
        hosts.add(h.lower())
    for f in load_feeds():
        fh = urlparse(f["url"]).hostname
        if fh:
            hosts.add(fh.lower())
    return hosts


def finish(result, aid):
    """Flag indicators never seen in an earlier analysis, then remember this analysis."""
    result["aid"] = aid
    known = store.known_iocs([i["value"] for i in result["iocs"]], aid)
    for i in result["iocs"]:
        i["new"] = i["value"] not in known
    store.record_analysis(aid, result["title"], result["link"], result["source"], result["date"], result)
    return result


def run_analysis(body, refresh=False):
    """Returns (result, None) or (None, (message, http_status))."""
    title, link, source, date_, text, note = body.get("title", ""), "", "Pasted text", None, "", ""
    if body.get("text"):
        text = str(body["text"])[:MAX_TEXT]
        aid = hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:14]
    else:
        item = ARTICLES.get(body.get("id", "")) if body.get("id") else None
        link = item["link"] if item else str(body.get("url", "")).strip()
        if not link:
            return None, ("Provide an article id, a URL or pasted text", 400)
        aid = item["id"] if item else hashlib.sha1(link.encode()).hexdigest()[:14]
        if not refresh:
            hit = store.get_analysis(aid, 24)
            if hit:
                return hit, None
        if item and item.get("otx_id"):
            try:
                return finish(analyze_pulse(item), aid), None
            except Exception as e:  # noqa: BLE001
                return None, (f"Could not load the OTX pulse: {str(e)[:120]}", 422)
        if item:
            title, source, date_ = item["title"], item["source"], item["date"].isoformat() if item["date"] else None
        try:
            raw, ctype, link = safe_fetch(link)
            if "pdf" in ctype.lower():
                return None, ("That link is a PDF. Open it and paste the text instead.", 422)
            t2, text = html_to_text(raw) if "html" in ctype.lower() or "<html" in raw[:2000].lower() else ("", raw[:MAX_TEXT])
            title = title or t2
        except Exception as e:  # noqa: BLE001
            if item and item.get("body"):
                _, text = html_to_text(item["body"])
                note = f"Could not load the full page ({str(e)[:80]}); analysed the feed excerpt only."
            else:
                return None, (f"Could not load the page: {str(e)[:140]}", 422)
        else:
            if item and len(text) < 1200 and item.get("body"):
                _, alt = html_to_text(item["body"])
                if len(alt) > len(text):
                    text, note = alt, "Page text was short; used the feed content."
    if len(text.strip()) < 40:
        return None, ("Not enough text to analyse", 422)
    iocs = extract_iocs(text, own_hosts_for(link))
    attack = map_attack(text)
    result = {"title": title or "Untitled", "link": link, "source": source, "date": date_, "chars": len(text),
              "note": note, "iocs": iocs, "attack": attack, "attack_loaded": attack is not None,
              "counts": {t: sum(1 for i in iocs if i["type"] == t) for t in ("ip", "domain", "url", "hash", "cve")}}
    return finish(result, aid), None


@bp.post("/api/analyze")
def api_analyze():
    body = request.get_json(force=True, silent=True) or {}
    result, err = run_analysis(body, bool(body.get("refresh")))
    return (jsonify(result) if result else (jsonify({"error": err[0]}), err[1]))


# --------------------------------------------------------------------------
# Seen-in-news, saved searches, digest / multi-article merge
# --------------------------------------------------------------------------
@bp.post("/api/seen")
def api_seen():
    iocs = (request.get_json(force=True, silent=True) or {}).get("iocs") or []
    return jsonify(store.seen_iocs([str(i) for i in iocs[:2000]]))


@bp.get("/api/searches")
def api_searches():
    saved = store.list_searches()
    if not saved:
        return jsonify([])
    items, _, _ = search_items("", max(s_["days"] for s_ in saved), set(), False, False)
    out = []
    for sv in saved:
        terms = search_terms(sv["query"])
        since = datetime.fromisoformat(sv["last_seen"])
        cutoff = datetime.now(timezone.utc) - timedelta(days=sv["days"])
        n = sum(1 for it in items if it["date"] and it["date"] > max(since, cutoff)
                and match_terms(it, terms, honor_prefilter=False))
        out.append({**sv, "new": n})
    return jsonify(out)


@bp.post("/api/searches")
def api_searches_add():
    b = request.get_json(force=True, silent=True) or {}
    q = re.sub(r"\s+", " ", str(b.get("query", ""))).strip()[:120]
    if not q:
        return jsonify({"error": "Type a search first"}), 400
    try:
        return jsonify(store.add_search(q, float(b.get("days", 7))))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.delete("/api/searches/<int:sid>")
def api_searches_delete(sid):
    store.delete_search(sid)
    return jsonify({"ok": True})


@bp.post("/api/searches/<int:sid>/seen")
def api_searches_seen(sid):
    store.touch_search(sid)
    return jsonify({"ok": True})


PRIORITY_SOURCES = {"CISA Advisories", "Unit 42", "Cisco Talos", "Microsoft Security", "Google Threat Intel",
                    "The DFIR Report"}
HOT = re.compile(r"ransomware|zero-?day|actively exploited|exploited in the wild|\bapt\d*\b|backdoor|malware|campaign|"
                 r"supply[- ]chain|breach|vulnerabilit|cve-\d{4}-|botnet|infostealer|phishing|wiper|\brce\b", re.I)


def rank_item(it, saved_terms):
    hay = (it["title"] + " " + it["summary"]).lower()
    s_ = 3 if any(t and all(x in hay for x in t) for t in saved_terms) else 0
    s_ += 2 if HOT.search(it["title"]) else 0
    s_ += 1 if it["source"] in PRIORITY_SOURCES or it.get("otx_id") else 0
    return s_


CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def merge_results(results):
    iocs, techs, ents, catalog, tactics = {}, {}, {}, {}, None
    for it, r in results:
        title = r["title"]
        for i in r["iocs"]:
            m = iocs.setdefault((i["type"], i["value"]), {
                "value": i["value"], "type": i["type"], "count": 0, "confidence": i["confidence"],
                "defanged": i.get("defanged", False), "context": i["context"], "new": False, "n": 0})
            m["count"] += i["count"]
            m["n"] += 1
            m["new"] = m["new"] or bool(i.get("new"))
            if CONF_RANK[i["confidence"]] < CONF_RANK[m["confidence"]]:
                m["confidence"] = i["confidence"]
        at = r.get("attack")
        if at:
            tactics = tactics or at["tactics"]
            catalog.update(at.get("profile_catalog", {}))
            for t in at["techniques"]:
                m = techs.setdefault(t["id"], {k: t[k] for k in ("id", "name", "tactics", "desc", "url")}
                                     | {"score": 0, "evidence": [], "n": 0})
                m["n"] += 1
                m["score"] = max(m["score"], t["score"])
                m["evidence"] += [{**e, "article": title[:80]} for e in t["evidence"][:1]]
            for e in at["entities"]:
                m = ents.setdefault(e["id"], {**e, "mentions": 0})
                m["mentions"] += 1
    for t in techs.values():
        t["evidence"] = t["evidence"][:4]
        t["band"] = "high" if t["score"] >= 75 else "medium" if t["score"] >= 55 else "low"
    ioc_list = sorted(iocs.values(), key=lambda x: (not x["new"], CONF_RANK[x["confidence"]], -x["n"], x["type"], x["value"]))
    attack = None if tactics is None else {
        "techniques": sorted(techs.values(), key=lambda x: (-x["n"], -x["score"])),
        "entities": sorted(ents.values(), key=lambda e: -e["mentions"])[:12],
        "profile_catalog": catalog, "tactics": tactics}
    return {"title": f"Digest of {len(results)} article{'s' if len(results) != 1 else ''}", "link": "",
            "source": "multiple sources", "date": None, "chars": sum(r["chars"] for _, r in results), "note": "",
            "iocs": ioc_list, "attack": attack, "attack_loaded": attack is not None, "digest": True,
            "counts": {t: sum(1 for i in ioc_list if i["type"] == t) for t in ("ip", "domain", "url", "hash", "cve")}}


@bp.post("/api/digest")
def api_digest():
    body = request.get_json(force=True, silent=True) or {}
    ids = [i for i in (body.get("ids") or []) if isinstance(i, str)][:12]
    if ids:
        picked = [ARTICLES[i] for i in ids if i in ARTICLES]
        if not picked:
            return jsonify({"error": "Those articles are no longer in memory. Search again and retry."}), 422
    else:
        try:
            days = min(float(body.get("days", 1)), 7)
            limit = max(1, min(int(body.get("limit", 6)), 12))
        except (TypeError, ValueError):
            days, limit = 1, 6
        items, errors, _ = search_items("", days, set(), False, False)
        done = store.analysed_ids([i["id"] for i in items])
        fresh = [i for i in items if i["id"] not in done]
        saved = [search_terms(x["query"]) for x in store.list_searches()]
        fresh.sort(key=lambda i: (-rank_item(i, saved), -(i["date"].timestamp() if i["date"] else 0)))
        picked = fresh[:limit]
        if not picked:
            why = ("No articles were found in the last day. Check the feed list and your connection." if not items
                   else f"All {len(items)} articles from the last day have already been analysed.")
            return jsonify({"empty": True, "message": why, "errors": errors})
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [(it, ex.submit(run_analysis, {"id": it["id"]}, False)) for it in picked]
        results, arts = [], []
        for it, f in futs:
            r, err = f.result()
            base = {"id": it["id"], "title": it["title"], "link": it["link"], "source": it["source"]}
            if r:
                results.append((it, r))
                arts.append({**base, "counts": r["counts"], "techniques": len((r.get("attack") or {}).get("techniques", []))})
            else:
                arts.append({**base, "error": err[0]})
    if not results:
        return jsonify({"error": "None of the selected articles could be read: " + arts[0].get("error", "")}), 422
    merged = merge_results(results)
    merged["articles"] = arts
    return jsonify(merged)


@bp.post("/api/attack/layer")
def api_layer():
    body = request.get_json(force=True, silent=True) or {}
    A = load_attack()
    ver = str(A.get("meta", {}).get("version", "17")).split(".")[0]
    techs = [{"techniqueID": t["id"], "score": int(t.get("score", 50)), "comment": str(t.get("comment", ""))[:300], "enabled": True}
             for t in body.get("techniques", []) if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t.get("id", "")))]
    return jsonify({"name": str(body.get("name", "ThreatLens analysis"))[:120],
                    "versions": {"attack": ver, "navigator": "5.1.0", "layer": "4.5"},
                    "domain": "enterprise-attack",
                    "description": "Generated by ThreatLens from article text. Scores reflect evidence strength, not attribution.",
                    "sorting": 3, "layout": {"layout": "side", "showID": True, "showName": True},
                    "hideDisabled": False, "techniques": techs,
                    "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 100},
                    "legendItems": [], "selectTechniquesAcrossTactics": True})
