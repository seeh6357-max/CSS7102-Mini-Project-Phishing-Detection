import sqlite3
import os
from datetime import datetime

class AuditLogger:
    def __init__(self, db_path="app/audit_logs.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_score REAL NOT NULL,
                latency_ms REAL NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def log_scan(self, url: str, verdict: str, source: str, risk_score: float, latency_ms: float):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (url, verdict, source, risk_score, latency_ms, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (url, verdict, source, risk_score, latency_ms, datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Database Error: {e}")

    def get_recent_logs(self, limit=15):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, url, verdict, source, risk_score, latency_ms, timestamp FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception:
            return []
