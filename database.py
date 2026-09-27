import sqlite3
import hashlib

def hash_text(text: str) -> str:
    """Converts a password into a SHA-256 hash."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def update_database():
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()

    # Table 1: Email breaches
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS breaches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        breach_name TEXT NOT NULL,
        breach_date TEXT NOT NULL,
        leaked_info TEXT NOT NULL,
        risk_level TEXT NOT NULL
    )
    """)

    # Table 2: Leaked passwords
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS leaked_passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT UNIQUE NOT NULL,
        times_seen INTEGER NOT NULL
    )
    """)

    cursor.execute("DELETE FROM breaches")
    cursor.execute("DELETE FROM leaked_passwords")

    # Sample breached accounts (including multiple college.edu emails)
    email_data = [
        ("student@college.edu", "University Portal Leak", "2024-03-12", "Passwords, Student ID", "High"),
        ("student@college.edu", "Online Library Hack", "2023-09-18", "Email, Reading History", "Low"),
        ("prof.smith@college.edu", "Academic Research Forum", "2023-05-10", "Password, Name", "High"),
        ("admin@college.edu", "IT Services Database Leak", "2024-01-14", "Email, Server Logs", "Medium"),
        ("rahul@gmail.com", "MegaMart Data Leak", "2022-11-05", "Phone Number, Home Address", "Medium"),
        ("priya@yahoo.com", "CryptoApp Dump", "2023-01-20", "Passwords, Credit Card Info", "Critical")
    ]
    cursor.executemany("""
    INSERT INTO breaches (email, breach_name, breach_date, leaked_info, risk_level)
    VALUES (?, ?, ?, ?, ?)
    """, email_data)

    # Sample hashed passwords
    common_passwords = [
        ("password123", 542010),
        ("123456", 2314500),
        ("admin@123", 124300),
        ("college@2024", 8940),
        ("qwerty", 983200),
        ("iloveyou", 412030)
    ]
    password_records = [(hash_text(p), c) for p, c in common_passwords]

    cursor.executemany("""
    INSERT INTO leaked_passwords (password_hash, times_seen)
    VALUES (?, ?)
    """, password_records)

    conn.commit()
    conn.close()
    print("Database updated with domain scanner test data!")

if __name__ == "__main__":
    update_database()