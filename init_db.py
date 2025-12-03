import sqlite3
import bcrypt
import secrets

DB = "e_voting.db"
conn = sqlite3.connect(DB)
c = conn.cursor()

# Enforce foreign keys for sqlite sessions created by this script
c.execute("PRAGMA foreign_keys = ON")

# Users
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    cnic TEXT UNIQUE CHECK(length(cnic)=13),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# Admins
c.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
""")

# Eligible Voters
c.execute("""
CREATE TABLE IF NOT EXISTS eligible_voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cnic TEXT UNIQUE NOT NULL CHECK(length(cnic)=13)
);
""")

# Registered CNIC (links to users table, optional)
c.execute("""
CREATE TABLE IF NOT EXISTS registered_cnic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cnic TEXT UNIQUE NOT NULL CHECK(length(cnic)=13),
    user_id INTEGER UNIQUE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
""")

# Authority Keys
c.execute("""
CREATE TABLE IF NOT EXISTS authority_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    n TEXT NOT NULL,
    e INTEGER NOT NULL,
    d TEXT NOT NULL
);
""")

# Votes
c.execute("""
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL
);
""")

# Used Tokens
c.execute("""
CREATE TABLE IF NOT EXISTS used_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL
);
""")

# MFA
c.execute("""
CREATE TABLE IF NOT EXISTS mfa_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
""")

# Logs
c.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    info TEXT,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
""")

# Indices
c.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);")
c.execute("CREATE INDEX IF NOT EXISTS idx_users_cnic ON users(cnic);")
c.execute("CREATE INDEX IF NOT EXISTS idx_registered_cnic_cnic ON registered_cnic(cnic);")

# Seed eligible voters
sample_voters = ["1234567890123", "9876543210987", "5555555555555"]
for cnic in sample_voters:
    try:
        c.execute("INSERT INTO eligible_voters (cnic) VALUES (?)", (cnic,))
    except sqlite3.IntegrityError:
        pass

# Default admin (bcrypt)
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin123"

hashed = bcrypt.hashpw(DEFAULT_ADMIN_PASS.encode(), bcrypt.gensalt()).decode()

c.execute("SELECT COUNT(*) FROM admins")
if c.fetchone()[0] == 0:
    c.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
        (DEFAULT_ADMIN_USER, hashed)
    )

conn.commit()
conn.close()

print("Database initialized successfully!")
