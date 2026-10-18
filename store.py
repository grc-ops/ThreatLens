"""SQLite persistence: analysed articles, IOC sightings, saved searches, checked batches.

Everything lives in data/threatlens.db next to the app. Safe to delete; it is rebuilt on start.
"""
import contextlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "threatlens.db")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))
MAX_BATCHES = 50
MAX_SEARCHES = 20

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, title TEXT, link TEXT, source TEXT,
  published TEXT, analyzed_at TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS sightings(ioc TEXT, type TEXT, analysis_id TEXT, confidence TEXT, seen_at TEXT,
  PRIMARY KEY(ioc, analysis_id));
CREATE INDEX IF NOT EXISTS idx_sight_ioc ON sightings(ioc);
CREATE TABLE IF NOT EXISTS searches(id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT UNIQUE, days REAL,
  created TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, label TEXT,
  total INTEGER, malicious INTEGER, suspicious INTEGER, results TEXT);
"""
_ready = False
_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextlib.contextmanager
def db():
    global _ready
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        with _lock:
            if not _ready:
                c.execute("PRAGMA journal_mode=WAL")
                c.executescript(SCHEMA)
                _ready = True
        yield c
        c.commit()
    finally:
        c.close()


def _chunks(seq, n=400):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ---- analyses and sightings -------------------------------------------------
def record_analysis(aid, title, link, source, published, result):
    t = now()
    with db() as c:
        c.execute("INSERT OR REPLACE INTO analyses VALUES (?,?,?,?,?,?,?)",
                  (aid, title, link, source, published, t, json.dumps(result)))
        c.execute("DELETE FROM sightings WHERE analysis_id=?", (aid,))
        c.executemany("INSERT OR REPLACE INTO sightings VALUES (?,?,?,?,?)",
                      [(i["value"], i["type"], aid, i["confidence"], t) for i in result.get("iocs", [])
                       if i["confidence"] in ("high", "medium")])
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
        c.execute("DELETE FROM sightings WHERE analysis_id IN (SELECT id FROM analyses WHERE analyzed_at<?)", (cutoff,))
        c.execute("DELETE FROM analyses WHERE analyzed_at<?", (cutoff,))


def get_analysis(aid, max_age_hours=24):
    with db() as c:
        row = c.execute("SELECT result, analyzed_at FROM analyses WHERE id=?", (aid,)).fetchone()
    if not row or not row["result"]:
        return None
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row["analyzed_at"])
    except ValueError:
        return None
    return json.loads(row["result"]) if age <= timedelta(hours=max_age_hours) else None


def analysed_ids(ids):
    out = set()
    with db() as c:
        for ch in _chunks(ids):
            q = ",".join("?" * len(ch))
            out.update(r["id"] for r in c.execute(f"SELECT id FROM analyses WHERE id IN ({q})", ch))
    return out


def known_iocs(values, exclude_aid=""):
    out = set()
    with db() as c:
        for ch in _chunks(values):
            q = ",".join("?" * len(ch))
            out.update(r["ioc"] for r in c.execute(
                f"SELECT DISTINCT ioc FROM sightings WHERE ioc IN ({q}) AND analysis_id != ?", [*ch, exclude_aid]))
    return out


def seen_iocs(values):
    """ioc -> [{title, link, when, confidence}] (newest first, max 5 each)."""
    out = {}
    with db() as c:
        for ch in _chunks(values):
            q = ",".join("?" * len(ch))
            rows = c.execute(
                f"SELECT s.ioc, s.confidence, a.title, a.link, a.analyzed_at FROM sightings s "
                f"JOIN analyses a ON a.id = s.analysis_id WHERE s.ioc IN ({q}) ORDER BY a.analyzed_at DESC", ch)
            for r in rows:
                lst = out.setdefault(r["ioc"], [])
                if len(lst) < 5:
                    lst.append({"title": r["title"], "link": r["link"], "when": r["analyzed_at"],
                                "confidence": r["confidence"]})
    return out


def purge_results():
    """Called after the ATT&CK data is refreshed so old mappings are recomputed."""
    with db() as c:
        c.execute("UPDATE analyses SET result=NULL")


# ---- saved searches -----------------------------------------------------------
def list_searches():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT id, query, days, created, last_seen FROM searches ORDER BY id")]


def add_search(query, days):
    with db() as c:
        if c.execute("SELECT COUNT(*) FROM searches").fetchone()[0] >= MAX_SEARCHES:
            raise ValueError(f"You can keep up to {MAX_SEARCHES} saved searches")
        t = now()
        c.execute("INSERT OR IGNORE INTO searches(query, days, created, last_seen) VALUES (?,?,?,?)", (query, days, t, t))
        return dict(c.execute("SELECT id, query, days, created, last_seen FROM searches WHERE query=?", (query,)).fetchone())


def delete_search(sid):
    with db() as c:
        c.execute("DELETE FROM searches WHERE id=?", (sid,))


def touch_search(sid):
    with db() as c:
        c.execute("UPDATE searches SET last_seen=? WHERE id=?", (now(), sid))


# ---- batches (IOC check history) -----------------------------------------------
def add_batch(label, total, malicious, suspicious, results):
    with db() as c:
        cur = c.execute("INSERT INTO batches(created,label,total,malicious,suspicious,results) VALUES (?,?,?,?,?,?)",
                        (now(), label, total, malicious, suspicious, json.dumps(results)))
        c.execute("DELETE FROM batches WHERE id NOT IN (SELECT id FROM batches ORDER BY id DESC LIMIT ?)", (MAX_BATCHES,))
        return cur.lastrowid


def list_batches():
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, created, label, total, malicious, suspicious FROM batches ORDER BY id DESC")]


def get_batch(bid):
    with db() as c:
        row = c.execute("SELECT results FROM batches WHERE id=?", (bid,)).fetchone()
    return json.loads(row["results"]) if row else None


def delete_batch(bid):
    with db() as c:
        c.execute("DELETE FROM batches WHERE id=?", (bid,))
