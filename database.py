import sqlite3

def init_db():
    conn = sqlite3.connect("sentinel.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            verdict TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(url, verdict):
    conn = sqlite3.connect("sentinel.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, verdict) VALUES (?, ?)", (url, verdict))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect("sentinel.db")
    c = conn.cursor()
    c.execute("SELECT url, verdict, date FROM scans ORDER BY date DESC")
    data = c.fetchall()
    conn.close()
    return data
