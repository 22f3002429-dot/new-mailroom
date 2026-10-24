import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

_DB_PATH = os.getenv("DATABASE_PATH", "./data/mailroom.db")
_LOCK = threading.RLock()


def _connect():
    path = Path(_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def db():
    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db():
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS evaluations (
              evaluation_id TEXT PRIMARY KEY,
              input_digest TEXT NOT NULL,
              verifier_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS dossier_cache (
              content_fingerprint TEXT PRIMARY KEY,
              proposal_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS proposals (
              evaluation_id TEXT NOT NULL,
              dossier_id TEXT NOT NULL,
              call_id TEXT NOT NULL,
              proposal_json TEXT NOT NULL,
              proposal_digest TEXT NOT NULL,
              PRIMARY KEY (evaluation_id, dossier_id),
              UNIQUE (evaluation_id, call_id)
            );

            CREATE TABLE IF NOT EXISTS receipts (
              evaluation_id TEXT NOT NULL,
              dossier_id TEXT NOT NULL,
              call_id TEXT NOT NULL,
              receipt_id TEXT NOT NULL,
              accepted INTEGER NOT NULL,
              receipt_json TEXT NOT NULL,
              PRIMARY KEY (evaluation_id, dossier_id),
              UNIQUE (evaluation_id, receipt_id)
            );

            CREATE TABLE IF NOT EXISTS outcomes (
              evaluation_id TEXT NOT NULL,
              dossier_id TEXT NOT NULL,
              outcome_json TEXT NOT NULL,
              PRIMARY KEY (evaluation_id, dossier_id)
            );
            """
        )


def get_evaluation(evaluation_id: str):
    with db() as c:
        row = c.execute(
            "SELECT * FROM evaluations WHERE evaluation_id=?", (evaluation_id,)
        ).fetchone()
    return dict(row) if row else None


def save_evaluation(evaluation_id: str, input_digest: str, verifier: dict):
    with db() as c:
        c.execute(
            "INSERT OR IGNORE INTO evaluations(evaluation_id,input_digest,verifier_json) VALUES(?,?,?)",
            (evaluation_id, input_digest, json.dumps(verifier, separators=(",", ":"))),
        )


def get_cached_proposal(fingerprint: str):
    with db() as c:
        row = c.execute(
            "SELECT proposal_json FROM dossier_cache WHERE content_fingerprint=?",
            (fingerprint,),
        ).fetchone()
    return json.loads(row["proposal_json"]) if row else None


def save_cached_proposal(fingerprint: str, proposal: dict):
    with db() as c:
        c.execute(
            "INSERT OR IGNORE INTO dossier_cache(content_fingerprint,proposal_json) VALUES(?,?)",
            (fingerprint, json.dumps(proposal, separators=(",", ":"))),
        )


def save_proposals(evaluation_id: str, proposals: list[dict], digests: dict):
    with db() as c:
        for p in proposals:
            c.execute(
                """INSERT OR IGNORE INTO proposals
                   (evaluation_id,dossier_id,call_id,proposal_json,proposal_digest)
                   VALUES(?,?,?,?,?)""",
                (
                    evaluation_id,
                    p["dossierId"],
                    p["callId"],
                    json.dumps(p, separators=(",", ":")),
                    digests[p["dossierId"]],
                ),
            )


def get_proposals(evaluation_id: str):
    with db() as c:
        rows = c.execute(
            "SELECT * FROM proposals WHERE evaluation_id=?", (evaluation_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_proposal(evaluation_id: str, dossier_id: str):
    with db() as c:
        row = c.execute(
            "SELECT * FROM proposals WHERE evaluation_id=? AND dossier_id=?",
            (evaluation_id, dossier_id),
        ).fetchone()
    return dict(row) if row else None


def receipt_exists(evaluation_id: str, receipt_id: str) -> bool:
    with db() as c:
        row = c.execute(
            "SELECT 1 FROM receipts WHERE evaluation_id=? AND receipt_id=?",
            (evaluation_id, receipt_id),
        ).fetchone()
    return row is not None


def save_receipt(evaluation_id: str, receipt: dict):
    with db() as c:
        c.execute(
            """INSERT INTO receipts
               (evaluation_id,dossier_id,call_id,receipt_id,accepted,receipt_json)
               VALUES(?,?,?,?,?,?)""",
            (
                evaluation_id,
                receipt["dossierId"],
                receipt["callId"],
                receipt["receiptId"],
                1 if receipt["accepted"] else 0,
                json.dumps(receipt, separators=(",", ":")),
            ),
        )


def save_outcome(evaluation_id: str, outcome: dict):
    with db() as c:
        c.execute(
            """INSERT OR REPLACE INTO outcomes(evaluation_id,dossier_id,outcome_json)
               VALUES(?,?,?)""",
            (
                evaluation_id,
                outcome["dossierId"],
                json.dumps(outcome, separators=(",", ":")),
            ),
        )


def get_outcomes(evaluation_id: str):
    with db() as c:
        rows = c.execute(
            "SELECT outcome_json FROM outcomes WHERE evaluation_id=?", (evaluation_id,)
        ).fetchall()
    return [json.loads(r["outcome_json"]) for r in rows]
