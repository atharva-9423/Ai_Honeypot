"""SQLite persistence (stdlib sqlite3). Stores sessions/events/indicators/deception actions."""
from __future__ import annotations
import os
import sqlite3
import threading
import time
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "sentinel.db")

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS sessions(
          id TEXT PRIMARY KEY, created_at REAL, ended_at REAL, status TEXT);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, timestamp REAL,
          type TEXT, severity TEXT, stage TEXT, command TEXT, evidence TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS indicators(
          id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, type TEXT, value TEXT, source TEXT);
        CREATE TABLE IF NOT EXISTS deception_actions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, timestamp REAL,
          action TEXT, target TEXT, reason TEXT);
        """)


def upsert_session(sid: str, status: str = "active"):
    with _lock, _conn() as c:
        row = c.execute("SELECT id FROM sessions WHERE id=?", (sid,)).fetchone()
        if row:
            c.execute("UPDATE sessions SET status=? WHERE id=?", (status, sid))
        else:
            c.execute("INSERT INTO sessions(id,created_at,ended_at,status) VALUES(?,?,?,?)",
                      (sid, time.time(), None, status))


def end_session(sid: str):
    with _lock, _conn() as c:
        c.execute("UPDATE sessions SET status='closed', ended_at=? WHERE id=?", (time.time(), sid))


def clear_session_data(sid: str):
    with _lock, _conn() as c:
        c.execute("DELETE FROM events WHERE session_id=?", (sid,))
        c.execute("DELETE FROM indicators WHERE session_id=?", (sid,))
        c.execute("DELETE FROM deception_actions WHERE session_id=?", (sid,))


def clear_all_data() -> dict:
    """Wipe every honeypot record (sessions, events, indicators, deceptions).

    The real-system reference is static code and is never touched."""
    with _lock, _conn() as c:
        counts = {}
        for table in ("events", "indicators", "deception_actions", "sessions"):
            cur = c.execute(f"DELETE FROM {table}")
            counts[table] = cur.rowcount
        return counts


def log_event(sid: str, ev: dict):
    with _lock, _conn() as c:
        c.execute("""INSERT INTO events(session_id,timestamp,type,severity,stage,command,evidence,detail)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (sid, time.time(), ev.get("event_type"), ev.get("severity"), ev.get("stage"),
                   (ev.get("evidence") or [""])[0], json.dumps(ev.get("evidence", [])),
                   ev.get("detail", "")))


def log_indicator(sid: str, itype: str, value: str, source: str = "terminal"):
    with _lock, _conn() as c:
        exists = c.execute("SELECT id FROM indicators WHERE session_id=? AND type=? AND value=?",
                           (sid, itype, value)).fetchone()
        if not exists:
            c.execute("INSERT INTO indicators(session_id,type,value,source) VALUES(?,?,?,?)",
                      (sid, itype, value, source))


def log_deception(sid: str, action: dict):
    with _lock, _conn() as c:
        c.execute("""INSERT INTO deception_actions(session_id,timestamp,action,target,reason)
                     VALUES(?,?,?,?,?)""",
                  (sid, action.get("timestamp", time.time()), action.get("action"),
                   action.get("target", ""), action.get("reason", "")))


def get_events(sid: str) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM events WHERE session_id=? ORDER BY timestamp ASC", (sid,)).fetchall()
        return [dict(r) for r in rows]


def get_indicators(sid: str) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM indicators WHERE session_id=?", (sid,)).fetchall()
        return [dict(r) for r in rows]


def get_deceptions(sid: str) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM deception_actions WHERE session_id=? ORDER BY timestamp ASC", (sid,)).fetchall()
        return [dict(r) for r in rows]


def dashboard_counts() -> dict:
    with _lock, _conn() as c:
        s = c.execute("SELECT COUNT(*) n FROM sessions WHERE status='active'").fetchone()["n"]
        e = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        h = c.execute("SELECT COUNT(*) n FROM events WHERE type='honeytoken_accessed'").fetchone()["n"]
        r = c.execute("SELECT COUNT(DISTINCT session_id) n FROM events").fetchone()["n"]
        return {"active_sessions": s, "events": e, "honeytokens_triggered": h,
                "sessions_with_events": r}


def recent_events(limit: int = 20) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
