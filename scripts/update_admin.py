import sqlite3
from werkzeug.security import generate_password_hash

DB = "e_voting.db"

NEW_ADMIN_USER = "javeriahfaheem"
NEW_ADMIN_PASS = "thisismystrongpass"

conn = sqlite3.connect(DB)
cur = conn.cursor()

hashed = generate_password_hash(NEW_ADMIN_PASS, method="pbkdf2:sha256")

cur.execute("SELECT id FROM admins LIMIT 1")
row = cur.fetchone()

if row:
    cur.execute("""
        UPDATE admins
        SET username = ?, password_hash = ?
        WHERE id = ?
    """, (NEW_ADMIN_USER, hashed, row[0]))
    print("[OK] Updated admin with PBKDF2 hashing")
else:
    cur.execute("""
        INSERT INTO admins (username, password_hash)
        VALUES (?, ?)
    """, (NEW_ADMIN_USER, hashed))
    print("[OK] Inserted new admin with PBKDF2 hashing")

conn.commit()
conn.close()

print("✔ Admin credentials fixed")
