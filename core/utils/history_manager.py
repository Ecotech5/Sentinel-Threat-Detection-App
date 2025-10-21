# utils/history_manager.py
import sqlite3
import os
from typing import List, Tuple

DB_PATH = os.path.join(os.getcwd(), "sentinel_history.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            url TEXT,
            verdict TEXT,
            score INTEGER,
            data TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_entry(timestamp: str, url: str, verdict: str, score: int, data: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO history (timestamp, url, verdict, score, data) VALUES (?, ?, ?, ?, ?)",
              (timestamp, url, verdict, score, data))
    conn.commit()
    conn.close()


def load_history(limit: int = 200) -> List[Tuple]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, url, verdict, score, data FROM history ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def clear_history() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM history")
    conn.commit()
    conn.close()
