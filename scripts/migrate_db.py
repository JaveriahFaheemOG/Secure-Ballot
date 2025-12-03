import os
import sqlite3
import shutil
import time
import sys

DB_PATH = os.getenv("DATABASE", "e_voting.db")
BACKUP_SUFFIX = time.strftime("%Y%m%d_%H%M%S")


def backup_db(db_path: str):
    if not os.path.exists(db_path):
        print(f"No DB at {db_path} to backup.")
        return
    bak = f"{db_path}.bak.{BACKUP_SUFFIX}"
    shutil.copyfile(db_path, bak)
    print(f"Backup created: {bak}")


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (name,)
    )
    return cur.fetchone() is not None


def get_table_columns(conn: sqlite3.Connection, table: str):
    cur = conn.execute(f"PRAGMA table_info({table});")
    return [row[1] for row in cur.fetchall()]


def add_column_if_missing(conn: sqlite3.Connection, table: str, col_name: str, col_def: str):
    cols = get_table_columns(conn, table)
    if col_name in cols:
        print(f"Column {table}.{col_name} already exists.")
        return False
    sql = f"ALTER TABLE {table} ADD COLUMN {col_def};"
    print(f"Adding column {table}.{col_name} using: {sql}")
    conn.execute(sql)
    conn.commit()
    return True


def recreate_table_with_schema(conn: sqlite3.Connection, table: str, new_create_sql: str, desired_cols: list):
    """
    Recreate 'table' using new_create_sql (CREATE TABLE statement). Copies data from
    the old table to the new table by mapping columns where present and defaulting others to NULL.
    """
    cur = conn.cursor()
    old_cols = get_table_columns(conn, table)
    print(f"Recreating table {table}. Old columns: {old_cols}")
    temp = f"{table}_new_mig"
    # Create new table
    print(f"Creating temporary table {temp}")
    cur.execute(
        new_create_sql.replace(f"CREATE TABLE IF NOT EXISTS {table}", f"CREATE TABLE IF NOT EXISTS {temp}")
    )
    # Build select list to copy columns
    select_list = []
    for c in desired_cols:
        if c in old_cols:
            select_list.append(c)
        else:
            select_list.append(f"NULL AS {c}")
    select_sql = ", ".join(select_list)
    insert_sql = f"INSERT INTO {temp} ({', '.join(desired_cols)}) SELECT {select_sql} FROM {table};"
    print("Copying data into temporary table:", insert_sql)
    conn.execute("BEGIN")
    try:
        conn.execute(insert_sql)
        conn.execute(f"DROP TABLE {table};")
        conn.execute(f"ALTER TABLE {temp} RENAME TO {table};")
        conn.commit()
        print(f"Recreated table {table} successfully.")
    except Exception as e:
        conn.rollback()
        print(f"Failed recreating {table}: {e}")
        raise


def ensure_users_table_has_cnic_and_mfa(conn: sqlite3.Connection):
    # Desired users schema for migration
    desired_users_cols = [
        "id",
        "username",
        "email",
        "password_hash",
        "cnic",
        "failed_mfa_attempts",
        "mfa_locked_until",
        "created_at",
    ]
    users_create_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        cnic TEXT UNIQUE CHECK(length(cnic)=13),
        failed_mfa_attempts INTEGER DEFAULT 0,
        mfa_locked_until INTEGER DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    if not table_exists(conn, "users"):
        print("Table 'users' missing; creating from template.")
        conn.execute(users_create_sql)
        conn.commit()
        return

    cols = get_table_columns(conn, "users")
    print("Users columns:", cols)

    # If cnic not present, we must recreate table (to add UNIQUE + CHECK),
    # because ALTER TABLE ADD COLUMN cannot cleanly add UNIQUE CHECK constraints.
    if "cnic" not in cols:
        print("Users.cnic missing; recreating users table with CNIC + MFA fields.")
        recreate_table_with_schema(conn, "users", users_create_sql, desired_users_cols)
    else:
        # Ensure MFA columns exist: we can ALTER ADD these
        add_column_if_missing(conn, "users", "failed_mfa_attempts", "failed_mfa_attempts INTEGER DEFAULT 0")
        add_column_if_missing(conn, "users", "mfa_locked_until", "mfa_locked_until INTEGER DEFAULT NULL")

    # Ensure index on users.cnic exists:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_users_cnic'")
    if not cur.fetchone():
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_cnic ON users(cnic)")
            conn.commit()
            print("Created index idx_users_cnic")
        except Exception as e:
            print("Failed to create idx_users_cnic:", e)


def ensure_registered_cnic_has_userid(conn: sqlite3.Connection):
    desired_cols = ["id", "cnic", "user_id"]
    reg_create_sql = """
    CREATE TABLE IF NOT EXISTS registered_cnic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cnic TEXT UNIQUE NOT NULL CHECK(length(cnic)=13),
        user_id INTEGER UNIQUE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """
    if not table_exists(conn, "registered_cnic"):
        print("registered_cnic table missing; creating.")
        conn.execute(reg_create_sql)
        conn.commit()
        return

    cols = get_table_columns(conn, "registered_cnic")
    print("registered_cnic columns:", cols)

    if "user_id" not in cols:
        print("registered_cnic.user_id missing; attempting to ALTER ADD COLUMN user_id")
        try:
            conn.execute("ALTER TABLE registered_cnic ADD COLUMN user_id INTEGER;")
            conn.commit()
            print("Added registered_cnic.user_id column.")
        except Exception as e:
            # If ALTER fails, recreate table with FK
            print("ALTER TABLE failed for registered_cnic, recreating table with new schema:", e)
            recreate_table_with_schema(conn, "registered_cnic", reg_create_sql, desired_cols)

    # Attempt to link user_id for existing rows where user has matching cnic
    print("Linking existing registered_cnic rows to users (by cnic)...")
    conn.execute(
        """
    UPDATE registered_cnic
    SET user_id = (
        SELECT id FROM users WHERE users.cnic = registered_cnic.cnic
    )
    WHERE user_id IS NULL;
    """
    )
    conn.commit()

    # Optionally create index on user_id for quick lookups if not existing
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_registered_cnic_user'")
    if not cur.fetchone():
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_registered_cnic_user ON registered_cnic(user_id)")
            conn.commit()
            print("Created unique index idx_registered_cnic_user on registered_cnic(user_id)")
        except Exception as e:
            # if index creation fails because of duplicate values, report and skip
            print("Failed creating idx_registered_cnic_user:", e)


def ensure_admins_table_has_lockout(conn: sqlite3.Connection):
    """
    Ensure admins table includes failed_login_attempts and locked_until.
    Add columns if missing, or recreate table if it didn't exist.
    """
    desired_admin_cols = ["id", "username", "password_hash", "failed_login_attempts", "locked_until"]
    admins_create_sql = """
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until INTEGER DEFAULT NULL
    );
    """
    if not table_exists(conn, "admins"):
        print("admins table missing; creating with lockout columns.")
        conn.execute(admins_create_sql)
        conn.commit()
        return

    cols = get_table_columns(conn, "admins")
    print("admins columns:", cols)
    if "failed_login_attempts" not in cols:
        add_column_if_missing(conn, "admins", "failed_login_attempts", "failed_login_attempts INTEGER DEFAULT 0")
    if "locked_until" not in cols:
        add_column_if_missing(conn, "admins", "locked_until", "locked_until INTEGER DEFAULT NULL")


def ensure_indices(conn: sqlite3.Connection):
    cur = conn.cursor()
    idxs = {
        "idx_logs_event_type": ("logs", "event_type"),
        "idx_users_cnic": ("users", "cnic"),
        "idx_registered_cnic_cnic": ("registered_cnic", "cnic"),
    }
    for idx_name, (table, col) in idxs.items():
        cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (idx_name,))
        if not cur.fetchone():
            try:
                conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({col});")
                conn.commit()
                print(f"Created index {idx_name} on {table}({col})")
            except Exception as e:
                print(f"Failed creating index {idx_name}: {e}")


def ensure_authority_key_big_enough(conn: sqlite3.Connection):
    # This helper will notify if the authority key primes are too small,
    # but won't attempt to change keys automatically.
    cur = conn.cursor()
    cur.execute("SELECT n FROM authority_keys LIMIT 1")
    row = cur.fetchone()
    if not row:
        print("No authority keys present - create them via init_db or admin flow (create_authority_keys).")
        return
    try:
        n = int(row[0])
        bits = n.bit_length()
        print(f"Authority modulus n is {bits} bits.")
        if bits < 2048:
            print("WARNING: authority key modulus < 2048 bits. Consider rotating keys to at least 2048-bit modulus for production.")
    except Exception:
        print("Could not parse authority key modulus; check authority_keys table.")


def run_migrations(db_path: str):
    if not os.path.exists(db_path):
        print(f"No DB found at {db_path}. Will call init_db to create base schema.")
        # Try to run init_db.py
        init_py = os.path.join(os.path.dirname(__file__), "init_db.py")
        if os.path.exists(init_py):
            print("Running init_db.py to create initial schema...")
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("init_db", init_py)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                print("init_db executed successfully.")
            except Exception as e:
                print("Failed to run init_db.py:", e)
                return
        else:
            print("init_db.py not found; aborting migration.")
            return

    backup_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        ensure_users_table_has_cnic_and_mfa(conn)
        ensure_registered_cnic_has_userid(conn)
        ensure_admins_table_has_lockout(conn)
        ensure_indices(conn)
        ensure_authority_key_big_enough(conn)
        print("Schema migration complete.")
    except Exception as e:
        print("Migration failed:", e)
        print("Restoring backup...")
        bak = f"{db_path}.bak.{BACKUP_SUFFIX}"
        if os.path.exists(bak):
            shutil.copyfile(bak, db_path)
            print("Restored from backup.")
        else:
            print("Backup not found; manual intervention required.")
    finally:
        conn.close()


if __name__ == "__main__":
    # Ensure path exists and run migration
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_file = os.path.join(base_dir, DB_PATH) if not os.path.isabs(DB_PATH) else DB_PATH
    print(f"Running migrations against DB: {db_file}")
    print("Stop the application (app.py) while running migration to avoid concurrent writes.")
    run_migrations(db_file)
    print("Done.")