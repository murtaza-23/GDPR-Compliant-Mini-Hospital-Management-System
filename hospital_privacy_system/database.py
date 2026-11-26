import sqlite3
import hashlib
import csv
import os
import io
from datetime import datetime, timedelta

DB_NAME = "hospital.db"

def get_connection():
    # Creates a database connection with foreign keys enabled
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Lets us access columns by name like row['role']
    conn.execute("PRAGMA foreign_keys = ON;")   # Foreign keys enabled
    return conn

def hash_password(password: str) -> str:
    # Returns a SHA-256 hex digest of a plain-text password
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    # Creates the users, patients, and logs tables and seeds initial users
    conn = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        # 1. Users Table (RBAC roles enforced via CHECK constraint)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist'))
            );
        """)

        # 2. Patients Table (Supports Fernet encryption, masking, & GDPR retention timer)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                contact TEXT NOT NULL,
                diagnosis TEXT NOT NULL,
                anonymized_name TEXT NOT NULL,
                anonymized_contact TEXT NOT NULL,
                anonymized_diagnosis TEXT NOT NULL,
                is_anonymized INTEGER DEFAULT 1,
                date_added TEXT NOT NULL,
                retention_expires_at TEXT NOT NULL
            );
        """)

        # 3. Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            );
        """)

        # user seeding
        default_users = [
            (1, "admin", hash_password("admin123"), "admin"),
            (2, "Dr. Bob", hash_password("doc123"), "doctor"),
            (3, "Alice_recep", hash_password("rec123"), "receptionist"),
        ]

        # The reason to do this is because anything written inside """ is considered an SQL built-in function
        # So the hash_password() function will not be considered as a Python function!

        cursor.executemany("""
            INSERT OR IGNORE INTO users (user_id, username, password, role)
            VALUES (?, ?, ?, ?);
        """, default_users)

        conn.commit()

    except sqlite3.Error as e:
        print(f"[DB Error] Initialization failed: {e}")
    finally:
        if conn:
            conn.close()

# Exports a valid table ('patients' or 'logs') to a CSV string for backup/download.
def export_table_to_csv(table_name: str) -> str:
    # Security check: prevent SQL injection since table names cannot be parameterized
    if table_name not in ("patients", "logs"):
        raise ValueError("Invalid table name for export.")

    conn = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        query = f"SELECT * FROM {table_name};"
        cursor.execute(query)

        rows = cursor.fetchall()

        headers = [description[0] for description in cursor.description] if cursor.description else []

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)

        return output.getvalue()

    except sqlite3.Error as e:
        print(f"[DB Error] failed to export '{table_name}': {e}")
        return ""
    finally:
            if conn:
                conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")