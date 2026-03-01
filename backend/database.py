import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Scans History table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        input_data TEXT,
        risk_score REAL,
        result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Feedback table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        rating INTEGER,
        feedback_text TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    )
    """)

    conn.commit()
    conn.close()


def log_scan(type, input_data, risk_score, result):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (type, input_data, risk_score, result) VALUES (?, ?, ?, ?)",
        (type, input_data, risk_score, result),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def log_feedback(scan_id, rating, feedback_text):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO feedback (scan_id, rating, feedback_text) VALUES (?, ?, ?)",
        (scan_id, rating, feedback_text),
    )
    conn.commit()
    conn.close()


def get_scan_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_all_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Join with feedback to get full details for SOC
    cursor.execute("""
        SELECT s.id, s.timestamp as date, s.type, s.risk_score as risk, s.result,
               COALESCE(f.rating, 0) as rating,
               COALESCE(f.feedback_text, '') as feedback
        FROM scans s
        LEFT JOIN feedback f ON s.id = f.scan_id
        ORDER BY s.timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    cursor.execute("DELETE FROM feedback")
    conn.commit()
    conn.close()
    return True


# Initialize on import
init_db()
