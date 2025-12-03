import sqlite3

DB = "e_voting.db"

conn = sqlite3.connect(DB)
cur = conn.cursor()

new_voters = [
    "1111111111111",
    "2222222222222",
    "3333333333333",
    "4444444444444",
    "6666666666666",
    "6666888777979",
    "7777777777777",
    "8888888888888"
]

for cnic in new_voters:
    try:
        cur.execute("INSERT INTO eligible_voters (cnic) VALUES (?)", (cnic,))
        print(f"Added {cnic}")
    except Exception as e:
        print(f"Skipped {cnic}: {e}")

conn.commit()
conn.close()

print("Done.")
