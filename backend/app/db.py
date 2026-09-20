"""SQLite persistence: users, cases, action decisions and an audit trail."""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .security import hash_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('viewer','analyst','admin')), created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY, alert_id TEXT, title TEXT, severity TEXT, risk INTEGER, verdict TEXT,
  created REAL NOT NULL, created_by TEXT, facts TEXT, result_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at REAL,
  UNIQUE(case_id, idx));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT, event TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created DESC);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    def _run(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock, self._conn:
            return self._conn.execute(sql, args)

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    # ----------------------------------------------------------------- meta --
    def secret(self) -> str:
        """Signing secret for tokens, generated once and stored in the database."""
        row = self._all("SELECT value FROM meta WHERE key='jwt_secret'")
        if row:
            return row[0]["value"]
        value = secrets.token_hex(32)
        self._run("INSERT OR IGNORE INTO meta(key,value) VALUES('jwt_secret',?)", (value,))
        return self._all("SELECT value FROM meta WHERE key='jwt_secret'")[0]["value"]

    # ---------------------------------------------------------------- users --
    def count_users(self) -> int:
        return self._all("SELECT COUNT(*) AS n FROM users")[0]["n"]

    def create_user(self, username: str, password: str, role: str) -> None:
        self._run("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)",
                  (username, hash_password(password), role, time.time()))

    def get_user(self, username: str) -> dict | None:
        rows = self._all("SELECT * FROM users WHERE username=?", (username,))
        return rows[0] if rows else None

    # ---------------------------------------------------------------- cases --
    def save_case(self, alert: dict, result: dict, actor: str) -> int:
        rep = result["report"]
        cur = self._run(
            "INSERT INTO cases(alert_id,title,severity,risk,verdict,created,created_by,facts,result_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (alert.get("id"), alert.get("title"), rep["severity"], rep["risk_score"], rep["verdict"],
             time.time(), actor, rep.get("facts", ""), json.dumps(result)))
        case_id = cur.lastrowid
        for i, rec in enumerate(rep["recommendations"]):
            self._run("INSERT INTO actions(case_id,idx,action,status) VALUES(?,?,?,?)",
                      (case_id, i, rec["action"], rec["status"]))
        return case_id

    def case_corpus(self, limit: int = 500) -> list[dict]:
        return self._all("SELECT id,alert_id,title,severity,risk,verdict,facts FROM cases ORDER BY id DESC LIMIT ?", (limit,))

    def list_cases(self, limit: int = 50) -> list[dict]:
        return self._all(
            "SELECT c.id,c.alert_id,c.title,c.severity,c.risk,c.verdict,c.created,c.created_by,"
            "(SELECT COUNT(*) FROM actions a WHERE a.case_id=c.id AND a.status='pending_approval') AS pending "
            "FROM cases c ORDER BY c.created DESC LIMIT ?", (max(1, min(limit, 200)),))

    def get_case(self, case_id: int) -> dict | None:
        rows = self._all("SELECT * FROM cases WHERE id=?", (case_id,))
        if not rows:
            return None
        row = rows[0]
        result = json.loads(row["result_json"])
        acts = {a["idx"]: a for a in self._all("SELECT * FROM actions WHERE case_id=?", (case_id,))}
        for i, rec in enumerate(result["report"]["recommendations"]):
            if i in acts:
                rec["status"] = acts[i]["status"]
                rec["decided_by"] = acts[i]["decided_by"]
        result["case_id"] = case_id
        result["created"] = row["created"]
        return result

    def decide_action(self, case_id: int, idx: int, decision: str, actor: str) -> bool:
        status = "approved" if decision == "approve" else "rejected"
        cur = self._run("UPDATE actions SET status=?,decided_by=?,decided_at=? WHERE case_id=? AND idx=? "
                        "AND status IN ('pending_approval','proposed')", (status, actor, time.time(), case_id, idx))
        return cur.rowcount == 1

    def stats(self) -> dict:
        by_sev = {r["severity"]: r["n"] for r in self._all("SELECT severity, COUNT(*) AS n FROM cases GROUP BY severity")}
        total = self._all("SELECT COUNT(*) AS n, COALESCE(AVG(risk),0) AS avg FROM cases")[0]
        pend = self._all("SELECT COUNT(*) AS n FROM actions WHERE status='pending_approval'")[0]["n"]
        return {"cases": total["n"], "average_risk": round(total["avg"], 1), "pending_actions": pend,
                "by_severity": {k: by_sev.get(k, 0) for k in ("critical", "high", "medium", "low")}}

    # ---------------------------------------------------------------- audit --
    def audit(self, actor: str, event: str, detail: str = "") -> None:
        self._run("INSERT INTO audit(ts,actor,event,detail) VALUES(?,?,?,?)", (time.time(), actor, event, detail[:500]))

    def audit_log(self, limit: int = 100) -> list[dict]:
        return self._all("SELECT ts,actor,event,detail FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),))
