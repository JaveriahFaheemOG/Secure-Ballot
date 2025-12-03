# app.py
import os
import sqlite3
import hashlib
import bcrypt
import smtplib
import time
import secrets
import re
import random
import hmac
from datetime import datetime
from email.message import EmailMessage
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask import Flask, g, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import check_password_hash  # for admin (init_db used werkzeug)
from Crypto.Util.number import getPrime
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from functools import wraps
from flask import abort


# Load .env (optional)
load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")


# Config
DATABASE = os.getenv("DATABASE", "e_voting.db")
APP_SECRET = os.getenv("FLASK_SECRET") or secrets.token_hex(16)

app = Flask(__name__)
app.secret_key = APP_SECRET

# SMTP / MFA config (set in .env)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

# OTP settings
OTP_LENGTH = 6
OTP_TTL_SECONDS = 180  # 3 minutes

# MFA brute-force/lockout policy
MAX_MFA_ATTEMPTS = int(os.getenv("MAX_MFA_ATTEMPTS", "5"))
MFA_LOCKOUT_SECONDS = int(os.getenv("MFA_LOCKOUT_SECONDS", "900"))  # 15 minutes

def mfa_rate_limit_key():
    # Prefer user-specific key if available, fallback to IP
    return str(session.get("mfa_user_id") or get_remote_address())

def reset_mfa_failures(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET failed_mfa_attempts = 0, mfa_locked_until = NULL WHERE id = ?", (user_id,))
    db.commit()

def increment_mfa_failure(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET failed_mfa_attempts = COALESCE(failed_mfa_attempts, 0) + 1 WHERE id = ?", (user_id,))
    db.commit()
    cur.execute("SELECT failed_mfa_attempts FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return False
    failed = row["failed_mfa_attempts"] or 0
    if failed >= MAX_MFA_ATTEMPTS:
        lock_until = int(time.time()) + MFA_LOCKOUT_SECONDS
        cur.execute("UPDATE users SET failed_mfa_attempts = 0, mfa_locked_until = ? WHERE id = ?", (lock_until, user_id))
        db.commit()
        return True
    return False

def is_mfa_locked(user_row):
    if not user_row:
        return False
    try:
        # sqlite3.Row doesn't support .get(); use indexing
        locked_until = user_row["mfa_locked_until"]
    except Exception:
        locked_until = None
    if locked_until is None:
        return False
    try:
        return int(locked_until) > int(time.time())
    except Exception:
        return False
# Admin lockout settings (env-overridable)
ADMIN_MAX_LOGIN_ATTEMPTS = int(os.getenv("ADMIN_MAX_LOGIN_ATTEMPTS", "5"))
ADMIN_LOCKOUT_SECONDS = int(os.getenv("ADMIN_LOCKOUT_SECONDS", "900"))  # 15 minutes

def reset_admin_failures(admin_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE admins SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (admin_id,))
    db.commit()

def increment_admin_failure(admin_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE admins SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1 WHERE id = ?", (admin_id,))
    db.commit()
    cur.execute("SELECT failed_login_attempts FROM admins WHERE id = ?", (admin_id,))
    row = cur.fetchone()
    if not row:
        return False
    failed = row["failed_login_attempts"] or 0
    if failed >= ADMIN_MAX_LOGIN_ATTEMPTS:
        lock_until = int(time.time()) + ADMIN_LOCKOUT_SECONDS
        cur.execute("UPDATE admins SET failed_login_attempts = 0, locked_until = ? WHERE id = ?", (lock_until, admin_id))
        db.commit()
        return True
    return False

def is_admin_locked(admin_row):
    if not admin_row:
        return False
    try:
        locked_until = admin_row["locked_until"]
    except Exception:
        locked_until = None
    if locked_until is None:
        return False
    try:
        return int(locked_until) > int(time.time())
    except Exception:
        return False
# ...existing code...

Talisman(app, content_security_policy=None)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

# Optional vote encryption key.
VOTE_FERNET_KEY = os.getenv("VOTE_FERNET_KEY", "")
if VOTE_FERNET_KEY:
    try:
        FERNET = Fernet(VOTE_FERNET_KEY.encode())
    except Exception:
        FERNET = None
else:
    FERNET = None
    
def encrypt_vote(candidate_plain):
    if not FERNET:
        return candidate_plain  # plain for demo
    return FERNET.encrypt(candidate_plain.encode()).decode()

def decrypt_vote(candidate_cipher):
    if not FERNET:
        return candidate_cipher
    try:
        return FERNET.decrypt(candidate_cipher.encode()).decode()
    except Exception:
        return "[decryption error]"
    
    

# --- Utility DB functions ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")  # enforce FKs
    return db

def get_user_by_id(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
        
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("You must be logged in to perform this action", "error")
            return redirect(url_for("user_login"))
        return f(*args, **kwargs)
    return wrapped

# --- Logging utility (non-linkable) ---
def create_log(event_type, info=""):
    import re
    safe_info = str(info)

    # remove CNIC-like patterns
    safe_info = re.sub(r"\b\d{13}\b", "[REDACTED_CNIC]", safe_info)

    # redact long integers (tokens, signatures)
    safe_info = re.sub(r"\b\d{20,}\b", "[REDACTED_BIGINT]", safe_info)

    # redact any SHA-256 sized hex
    safe_info = re.sub(r"[0-9a-fA-F]{64}", "[REDACTED_HASH]", safe_info)

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO logs (event_type, info) VALUES (?, ?)", (event_type, safe_info))
    db.commit()
    
# --- Email utility ---
def send_email(to_email, subject, body):
    """Send email via SMTP. If SMTP not configured, logs OTP to server log (dev fallback)."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        app.logger.info(f"SMTP not configured. Email to {to_email} would contain:\n{subject}\n{body}")
        return False
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception:
        app.logger.exception("Failed to send email")
        return False

# --- Password helpers for user accounts (bcrypt) ---
def hash_password(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_user_password(hashed, plain):
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# --- Authority / Chaum-style minimal keys ---
def create_authority_keys():
    """
    Create RSA-like keys and store n, e, d in DB.
    Keys are small-ish for speed. For assignment/demo only.
    """
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM authority_keys LIMIT 1")
    if cur.fetchone():
        return

    # generate two primes
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    # calculate d
    d = pow(e, -1, phi)
    cur.execute("INSERT INTO authority_keys (n, e, d) VALUES (?, ?, ?)", (str(n), e, str(d)))
    db.commit()

def get_authority_keys():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM authority_keys LIMIT 1")
    row = cur.fetchone()
    if not row:
        create_authority_keys()
        cur.execute("SELECT * FROM authority_keys LIMIT 1")
        row = cur.fetchone()
    return row

def get_public_key_only():
    row = get_authority_keys()
    return {"n": row["n"], "e": row["e"]}

# --- CSRF Protection ---
#CSRF tokens defend against cross-site request forgery reliably.
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]

def validate_csrf(token):
    return token and hmac.compare_digest(str(token), str(session.get("_csrf_token", "")))

@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token()}

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

# Registration page: shows CNIC input, instructions for blind signing flow
@app.route("/register", methods=["GET"])
@login_required
def register():
    return render_template("register.html")

# Endpoint: server receives blinded token from client and signs it (blind signing)
@limiter.limit("5 per minute")
@app.route("/blind_sign", methods=["POST"])
def blind_sign():
    """
    Client sends JSON: { cnic: "<cnic>", blinded: "<int-as-string>" }
    Server: verify CNIC is eligible and not previously registered, sign the blinded integer
    Returns signed_blinded as string.

    Requires authentication: session['user_id'] must exist and that user's cnic must match the payload cnic.
    """
    now = time.time()
    last = session.get("last_blind_sign_ts", 0)
    if now - last < 5:   # 5 seconds throttle
       return jsonify({"error":"Too many requests"}), 429
    session["last_blind_sign_ts"] = now

    if not session.get("user_id"):
        return jsonify({"error": "authentication required"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON provided"}), 400
    cnic = (data.get("cnic") or "").strip()
    blinded_str = (data.get("blinded") or "").strip()
    if not cnic or not blinded_str:
        return jsonify({"error": "cnic and blinded required"}), 400

    # Basic format validation for CNIC - 13 digits
    if not re.fullmatch(r"\d{13}", cnic):
        return jsonify({"error": "invalid cnic format"}), 400

    db = get_db()
    cur = db.cursor()

    # Ensure cnic is in eligible_voters
    cur.execute("SELECT 1 FROM eligible_voters WHERE cnic = ?", (cnic,))
    if not cur.fetchone():
        create_log("blind_sign_failed", "cnic not eligible")
        return jsonify({"error": "CNIC not eligible"}), 403

    # Must be the owner of the CNIC
    user = get_user_by_id(session.get("user_id"))
    if not user or not user["cnic"] or str(user["cnic"]).strip() != cnic:
        create_log("blind_sign_failed", "cnic mismatch with user account")
        return jsonify({"error": "CNIC mismatch with your account"}), 403

    # Check registration table: if there's a row bound to this CNIC already:
    cur.execute("SELECT id, user_id FROM registered_cnic WHERE cnic = ?", (cnic,))
    reg_row = cur.fetchone()
    if reg_row:
        # if already assigned to a different user -> reject
        if reg_row["user_id"] not in (None, user["id"]):
            create_log("blind_sign_failed", "cnic already registered to another account")
            return jsonify({"error": "CNIC already registered"}), 403
        # if row exists but already bound to same user -> reject (idempotent)
        if reg_row["user_id"] == user["id"]:
            create_log("blind_sign_failed", "cnic already registered to this account")
            return jsonify({"error": "CNIC already registered"}), 403

    # parse blinded integer
    try:
        blinded = int(blinded_str)
    except Exception:
        return jsonify({"error": "invalid blinded integer"}), 400

    # get authority keys
    row = get_authority_keys()
    n = int(row["n"])
    d = int(row["d"])

    # ensure blinded value in range (0, n)
    if not (0 < blinded < n):
        return jsonify({"error": "invalid blinded integer range"}), 400

    # sign blinded value: s' = blinded^d mod n
    signed_blinded = pow(blinded, d, n)

    # Insert or bind the CNIC -> user_id; handle race conditions
    try:
        if reg_row and reg_row["user_id"] is None:
            # Attempt to bind existing row where user_id is NULL
            cur.execute("UPDATE registered_cnic SET user_id = ? WHERE id = ? AND user_id IS NULL", (user["id"], reg_row["id"]))
            if cur.rowcount == 0:
                # race or concurrent update occurred
                db.commit()
                create_log("blind_sign_failed", "race while binding cnic")
                return jsonify({"error": "CNIC already registered"}), 403
        else:
            # No row exists: insert new mapping
            cur.execute("INSERT INTO registered_cnic (cnic, user_id) VALUES (?, ?)", (cnic, user["id"]))
        db.commit()
    except sqlite3.IntegrityError:
        # If a unique or FK constraint fired, treat as already registered or a race
        db.rollback()
        create_log("blind_sign_failed", "cnic already registered (integrity error)")
        return jsonify({"error": "CNIC already registered"}), 403
    except Exception:
        db.rollback()
        app.logger.exception("Unexpected error in blind_sign")
        return jsonify({"error": "internal server error"}), 500

    create_log("blind_sign_success", "signed blinded value for authenticated user")
    return jsonify({"signed_blinded": str(signed_blinded)})

# Voting verification page (where user posts token + signature)
@app.route("/vote", methods=["GET"])
@login_required
def vote_page():
    return render_template("verify_and_vote.html", candidates=["Candidate A", "Candidate B", "Candidate C"])

@app.route("/submit_vote", methods=["POST"])
@login_required
def submit_vote():
    """
    Expect form: token (int), signature (int), candidate (str)
    Verify signature: pow(signature, e, n) == token  (int equality)
    Ensure token not used yet (check used_tokens by token_hash).
    If OK, store vote with token_hash and return success.
    """
    token_csrf = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not validate_csrf(token_csrf):
        abort(403)
        
    #if request.method == "POST" and request.host != "127.0.0.1:5000":
    #   abort(403) #Protect /submit_vote from CSRF
    
    token_str = request.form.get("token", "").strip()
    signature_str = request.form.get("signature", "").strip()
    candidate = request.form.get("candidate")

    if not token_str or not signature_str or not candidate:
        flash("Missing field", "error")
        return redirect(url_for("vote_page"))

    try:
        token = int(token_str)
        signature = int(signature_str)
    except:
        flash("Invalid token/signature format", "error")
        create_log("vote_failed", "invalid token/signature format")
        return redirect(url_for("vote_page"))

    row = get_authority_keys()
    n = int(row["n"])
    e = int(row["e"])

    # verify signature
    if pow(signature, e, n) != token:
        flash("Invalid signature for token", "error")
        create_log("vote_failed", "invalid signature")
        return redirect(url_for("vote_page"))

    # one-time-use: store hash of token/signature
    token_hash = hashlib.sha256(f"{token}|{signature}".encode()).hexdigest()
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM used_tokens WHERE token_hash = ?", (token_hash,))
    if cur.fetchone():
        flash("This token has already been used", "error")
        create_log("vote_failed", "token already used")
        return redirect(url_for("vote_page"))

    # store vote (we do not store voter identity to mimic unlinkability)
    # Phase 2: we'll encrypt votes at rest. For now store candidate plain (later replace with encrypted bytes).
    enc = encrypt_vote(candidate)
    cur.execute("INSERT INTO votes (candidate, token_hash) VALUES (?, ?)", (enc, token_hash))
    cur.execute("INSERT INTO used_tokens (token_hash) VALUES (?)", (token_hash,))
    db.commit()
    create_log("vote_cast", "signature verified and stored")
    flash("Vote cast successfully", "success")
    return redirect(url_for("vote_page"))

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapped


# Admin login & panel
@limiter.limit("5 per minute")
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        token_csrf = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf(token_csrf):
            abort(403)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM admins WHERE username = ?", (username,))
        row = cur.fetchone()

        # If admin exists and is locked — show lock message (avoid revealing if user exists)
        if row and is_admin_locked(row):
            create_log("admin_login_failed", f"locked admin login attempt username={username}")
            flash("Account temporarily locked due to too many failed attempts. Try again later.", "error")
            return render_template("admin_login.html")

        if row and check_password_hash(row["password_hash"], password):
            # success -> reset failure counters and rotate session
            reset_admin_failures(row["id"])
            session.clear()
            session["admin_logged_in"] = True
            create_log("admin_login", "admin logged in")
            return redirect(url_for("admin_panel"))

        # if we get here login failed
        if row:
            locked = increment_admin_failure(row["id"])
            if locked:
                create_log("admin_login_locked", f"admin locked username={username}")
                flash("Account locked due to too many failed attempts. Try again later.", "error")
                return render_template("admin_login.html")
        create_log("admin_login_failed", "invalid admin credentials")
        flash("Invalid credentials", "error")
    return render_template("admin_login.html")

@app.route("/admin/panel")
def admin_panel():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT candidate FROM votes")
    rows = cur.fetchall()
    counts = {}
    for r in rows:
       cand = decrypt_vote(r["candidate"])
       counts[cand] = counts.get(cand, 0) + 1
    # convert to list of dicts for template compatibility
    tallies = [{"candidate": k, "cnt": v} for k, v in counts.items()]
    cur.execute("SELECT COUNT(*) as total FROM votes")
    total = cur.fetchone()["total"]
    return render_template("admin_panel.html", tallies=tallies, total=total)

@app.route("/admin/logs")
@admin_required
def admin_logs():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, event_type, info, created_at FROM logs ORDER BY id DESC LIMIT 200")
    logs = cur.fetchall()

    # map event_type → severity
    severity_map = {
        "admin_login_failed": "high",
        "login_failed":"medium",
        "mfa_failed": "high",
        "vote_failed": "high",
        "blind_sign_failed": "high",
        "otp_sent": "low",
        "user_registered": "low",
        "mfa_success": "low",
        "admin_login": "low",
        "admin_logout": "low",
        "user_login": "low",
        "user_logout": "low",
        "vote_cast": "low",
        "blind_sign_success": "low"
    }

    # Attach severity level to each row
    log_rows = []
    for row in logs:
        sev = severity_map.get(row["event_type"], "low")
        log_rows.append({
            "id": row["id"],
            "event_type": row["event_type"],
            "info": row["info"],
            "created_at": row["created_at"],
            "severity": sev
        })

    return render_template("admin_logs.html", logs=log_rows)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    create_log("admin_logout", "admin logged out")
    return redirect(url_for("index"))

# Small route to show authority public key (for client-side verification)
@app.route("/authority_pub")
def authority_pub():
    return jsonify(get_public_key_only())


# ------------------
# User account + MFA routes (Phase 1)
# ------------------
@limiter.limit("5 per hour") #Prevent automated account creation.
@app.route("/user/register", methods=["GET", "POST"])
def user_register():
        
    if request.method == "POST":
        # CSRF protection: verify token (POST only) 
        token_csrf = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf(token_csrf):
            app.logger.warning("CSRF validation failed for /user/register - token=%s session_token=%s", token_csrf, session.get("_csrf_token"))
            abort(403)
            
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        cnic = request.form.get("cnic", "").strip()
        
        # Basic CNIC format validation: 13 digits
        if not re.fullmatch(r"\d{13}", cnic):
            flash("Enter a valid 13-digit CNIC", "error")
            return render_template("user_register.html")
        
        # basic password policy
        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash("Password must be ≥8 chars, include uppercase and digits", "error")
            return render_template("user_register.html")

        db = get_db()
        cur = db.cursor()

        # ensure CNIC present in eligible_voters
        cur.execute("SELECT 1 FROM eligible_voters WHERE cnic = ?", (cnic,))
        if not cur.fetchone():
            # generic message to avoid enumeration
            flash("Invalid CNIC or not eligible", "error")
            return render_template("user_register.html")

        # ensure CNIC not already associated with a user
        cur.execute("SELECT id FROM users WHERE cnic = ?", (cnic,))
        if cur.fetchone():
            flash("This CNIC is already registered to an account", "warning")
            return render_template("user_register.html")

        # ensure CNIC not previously used for blind_sign if your policy requires it.
        cur.execute("SELECT 1 FROM registered_cnic WHERE cnic = ?", (cnic,))
        if cur.fetchone():
            # If registered_cnic rows are inserted during blind_sign then this prevents duplicate
            flash("This CNIC has already been used to register", "warning")
            return render_template("user_register.html")


        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, cnic) VALUES (?, ?, ?, ?)",
                (username, email, hash_password(password), cnic)
            )
            db.commit()
            create_log("user_registered", f"Account created username={username} cnic=[REDACTED_CNIC]")
            flash("Account created. Please log in.", "success")
            return redirect(url_for("user_login"))

        except sqlite3.IntegrityError:
            # duplicate email or username (DB unique constraint)
            flash("This email or username is already registered.", "warning")
            return render_template("user_register.html")

        except Exception as e:
            # log full traceback internally but don't show the error to users
            app.logger.exception(f"Unexpected error during registration for email={email}")
            flash("An unexpected error occurred. Please try again later.", "danger")
            return render_template("user_register.html")

    return render_template("user_register.html")

@limiter.limit("50 per minute")
@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    #rate limiting on login
    if session.get("last_login_attempt") and time.time() - session["last_login_attempt"] < 3:
       flash("Slow down. Try again.", "error")
       return render_template("user_login.html")
    session["last_login_attempt"] = time.time()
    
    if request.method == "POST":
        # CSRF protection: verify token (POST only)
        token_csrf = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf(token_csrf):
           abort(403)
        
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if not user or not check_user_password(user["password_hash"], password):
            create_log("login_failed", "username/password mismatch")
            flash("Invalid credentials", "error")
            return render_template("user_login.html")
        
        cleanup_expired_otps() #first cleaning up expired OTPs
        # user valid — generate OTP, send email
        otp = "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH)) #secrets.randbelow is cryptographically secure; hmac.compare_digest prevents timing attacks on comparisons
        store_otp_for_user(user["id"], otp)
        subject = "Your E-Voting OTP"
        body = f"Your OTP is: {otp}\nIt will expire in {OTP_TTL_SECONDS//60} minutes."
        if not send_email(user["email"], subject, body):
            # fallback to server log for dev
            app.logger.info(f"OTP for {user['email']}: {otp}")
        create_log("otp_sent", "MFA OTP sent")
        session["mfa_user_id"] = user["id"]
        return redirect(url_for("mfa_verify"))
    return render_template("user_login.html")

# OTP helpers and routes
def store_otp_for_user(user_id, otp_plain):
    otp_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
    expires = int(time.time()) + OTP_TTL_SECONDS
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM mfa_otps WHERE user_id = ?", (user_id,))
    cur.execute("INSERT INTO mfa_otps (user_id, otp_hash, expires_at) VALUES (?, ?, ?)", (user_id, otp_hash, expires))
    db.commit()


@app.route("/user/mfa", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("mfa_user_id")
    if not user_id:
        flash("No login in progress", "error")
        return redirect(url_for("user_login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = cur.fetchone()

    # If account locked due to repeated MFA failures
    if is_mfa_locked(user_row):
        # remove authentication in progress and notify user
        session.pop("mfa_user_id", None)
        create_log("mfa_lock", f"user_id={user_id} mfa locked")
        flash("Too many incorrect OTP attempts. Account locked for a short time.", "error")
        return redirect(url_for("user_login"))

    if request.method == "POST":
        # validate CSRF token (form or header)
        token_csrf = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf(token_csrf):
            app.logger.warning("CSRF validation failed for /user/mfa - token=%s session_token=%s", token_csrf, session.get("_csrf_token"))
            abort(403)
        otp = request.form.get("otp", "").strip()
        if not otp:
            flash("Enter OTP", "error")
            return render_template("mfa_verify.html")

        cleanup_expired_otps()
        cur.execute("SELECT * FROM mfa_otps WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1", (user_id,))
        row = cur.fetchone()
        if not row:
            flash("OTP not found or expired", "error")
            return render_template("mfa_verify.html")
        if int(row["expires_at"]) < int(time.time()):
            flash("OTP expired", "error")
            return render_template("mfa_verify.html")
        if not hmac.compare_digest(hashlib.sha256(otp.encode()).hexdigest(), row["otp_hash"]):
           # record failure and possibly lock account
           locked = increment_mfa_failure(user_id)
           create_log("mfa_failed", f"invalid otp for user_id={user_id}")
           if locked:
               # lockout triggered: drop auth flow and notify
               session.pop("mfa_user_id", None)
               create_log("mfa_lock", f"user_id={user_id} locked due to too many failed otps")
               flash("Too many incorrect OTP attempts. Account locked for a short time.", "error")
               return redirect(url_for("user_login"))
           else:
               flash("Invalid OTP", "error")
               return render_template("mfa_verify.html")
        # success: mark used, reset failures, establish session login
        cur.execute("UPDATE mfa_otps SET used = 1 WHERE id = ?", (row["id"],))
        reset_mfa_failures(user_id)
        db.commit()
        session.pop("mfa_user_id", None)
        session["user_id"] = user_id
        create_log("mfa_success", f"user_id={user_id} logged in")
        flash("Logged in", "success")
        return redirect(url_for("index"))
    return render_template("mfa_verify.html")

def cleanup_expired_otps():
    now = int(time.time())
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM mfa_otps WHERE expires_at < ?", (now,))
    db.commit()

@app.route("/user/logout")
def user_logout():
    session.pop("user_id", None)
    flash("Logged out", "success")
    create_log("user_logout", "user logged out")
    return redirect(url_for("index"))

# ---------------------------
# Add the test mail route HERE
# ---------------------------
@app.route("/testmail")
def testmail():
    try:
        send_email("your_email@gmail.com", "Test Email", "This is a test email.")
        return "Mail sent (or attempted)!"
    except Exception as e:
        return f"Error: {e}"

@app.route("/api/live_votes")
def api_live_votes():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "unauthorized"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT candidate FROM votes")
    rows = cur.fetchall()

    counts = {}
    for r in rows:
        cand = decrypt_vote(r["candidate"])
        counts[cand] = counts.get(cand, 0) + 1

    return jsonify(counts)


# ------------------
# End user account + MFA
# ------------------

if __name__ == "__main__":
    # Create DB first time if missing
    if not os.path.exists(DATABASE):
        print("Database not found — creating tables...")
        import init_db  # this should create tables (init_db.py)
    app.run(debug=True, host="127.0.0.1", port=5000)
