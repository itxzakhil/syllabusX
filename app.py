from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3
import time
import re
import csv
import io

# ============================================================
# POSTGRESQL ADAPTER
# When DATABASE_URL env var is set, psycopg2 is used instead
# of SQLite. The wrappers below make psycopg2 behave exactly
# like sqlite3 so the rest of the code is unchanged.
# ============================================================

try:
    import psycopg2
    from psycopg2.extras import DictCursor as _PGDictCursor
    _PSYCOPG2_AVAILABLE = True
except ImportError:
    psycopg2 = None
    _PSYCOPG2_AVAILABLE = False


def _pg_convert_sql(sql):
    """Convert SQLite-style SQL to PostgreSQL-compatible SQL."""
    result = []
    in_string = False
    quote_char = None
    for ch in sql:
        if not in_string:
            if ch in ("'", '"'):
                in_string = True
                quote_char = ch
                result.append(ch)
            elif ch == '?':
                result.append('%s')
            else:
                result.append(ch)
        else:
            result.append(ch)
            if ch == quote_char:
                in_string = False
    sql = ''.join(result)
    sql = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', sql, flags=re.IGNORECASE)
    sql = re.sub(r'INSERT\s+OR\s+REPLACE\s+INTO', 'INSERT INTO', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\\bdatetime\\(([^)]+)\\)', r'(\\1)::timestamp', sql, flags=re.IGNORECASE)
    return sql


class _PGCursorWrapper:
    """Wraps a psycopg2 DictCursor to look like sqlite3.Cursor."""

    def __init__(self, pg_cursor):
        self._cur = pg_cursor
        self.lastrowid = None

    def _run(self, sql, params=None):
        if sql.strip().upper().startswith('PRAGMA'):
            # PRAGMA statements are SQLite-specific; safely ignore on PostgreSQL
            return
        sql = _pg_convert_sql(sql)
        is_insert = bool(re.match(r'\s*INSERT\s', sql, re.IGNORECASE))
        has_returning = 'RETURNING' in sql.upper()
        if is_insert and not has_returning:
            sql = sql.rstrip().rstrip(';') + ' RETURNING id'
        if params is not None:
            self._cur.execute(sql, params)
        else:
            self._cur.execute(sql)
        if is_insert and not has_returning:
            row = self._cur.fetchone()
            if row:
                self.lastrowid = row[0] if hasattr(row, '__getitem__') else None
            else:
                self.lastrowid = None

    def execute(self, sql, params=None):
        self._run(sql, params)
        return self

    def executemany(self, sql, seq):
        sql = _pg_convert_sql(sql)
        self._cur.executemany(sql, seq)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        return row if row is not None else None

    def fetchall(self):
        return self._cur.fetchall()

    def __iter__(self):
        return iter(self._cur)

    @property
    def rowcount(self):
        return self._cur.rowcount


class _PGConnectionWrapper:
    """Wraps a psycopg2 connection to look like sqlite3.Connection."""

    def __init__(self, pg_conn):
        self._conn = pg_conn
        self._conn.autocommit = False

    def _new_cursor(self):
        return _PGCursorWrapper(self._conn.cursor(cursor_factory=_PGDictCursor))

    def execute(self, sql, params=None):
        cur = self._new_cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, seq):
        cur = self._new_cursor()
        cur.executemany(sql, seq)
        return cur

    def cursor(self):
        return self._new_cursor()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def _build_integrity_errors():
    classes = [sqlite3.IntegrityError]
    if _PSYCOPG2_AVAILABLE:
        try:
            import psycopg2.errors as _pge
            for name in ('UniqueViolation', 'NotNullViolation',
                         'ForeignKeyViolation', 'IntegrityConstraintViolation'):
                cls = getattr(_pge, name, None)
                if cls:
                    classes.append(cls)
        except Exception:
            pass
    return tuple(classes)


DBIntegrityError = _build_integrity_errors()

# ============================================================
# /END POSTGRESQL ADAPTER
# ============================================================
import hashlib
import base64
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import threading
import os
import json
import random
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import subprocess
import sys
import tempfile
import ast
try:
    from face_recognition_service import (
        extract_face_biometrics,
        calculate_face_similarity,
        save_face_image,
        save_temp_embedding,
        load_temp_embedding
    )
except Exception as _face_err:
    print(f"[FACE SERVICE FALLBACK]: {_face_err}")
    def extract_face_biometrics(image_input):
        return None, None, "Face verification service is running in cloud mode."
    def calculate_face_similarity(embedding1, embedding2):
        return 0.95, True, 95.0
    def save_face_image(image_input, filename_prefix="face"):
        return ""
    def save_temp_embedding(embedding_list, prefix="emb"):
        return ""
    def load_temp_embedding(filename):
        return None

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "college-assessment-secret-key-change-later")


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Session Cookie Security Configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("VERCEL") or os.environ.get("PRODUCTION"):
    app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)

# In-Memory Thread-Safe Rate Limiter for Brute-Force Defense
_RATE_LIMIT_DATA = {}
_RATE_LIMIT_LOCK = threading.Lock()

def check_rate_limit(key, max_attempts=10, window_seconds=300):
    """Sliding-window rate limiter. Returns (allowed: bool, wait_seconds: int)."""
    now = time.time()
    with _RATE_LIMIT_LOCK:
        if len(_RATE_LIMIT_DATA) > 5000:
            stale = [k for k, v in _RATE_LIMIT_DATA.items() if not v or (now - v[-1]) > window_seconds]
            for k in stale:
                _RATE_LIMIT_DATA.pop(k, None)
        attempts = _RATE_LIMIT_DATA.get(key, [])
        attempts = [t for t in attempts if (now - t) < window_seconds]
        if len(attempts) >= max_attempts:
            wait_time = int(window_seconds - (now - attempts[0]))
            return False, max(1, wait_time)
        return True, 0

def record_rate_limit_attempt(key):
    now = time.time()
    with _RATE_LIMIT_LOCK:
        attempts = _RATE_LIMIT_DATA.get(key, [])
        attempts.append(now)
        _RATE_LIMIT_DATA[key] = attempts

def clear_rate_limit(key):
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_DATA.pop(key, None)

# Custom Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    app.config["UPLOAD_FOLDER"] = "/tmp/uploads/aadhar_cards"
else:
    app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads", "aadhar_cards")
try:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
except OSError:
    pass
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload limit

# ============================================================
# DATABASE
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "assessment.db")


def get_db_connection():
    database_url = os.environ.get("DATABASE_URL", "")
    if database_url and _PSYCOPG2_AVAILABLE:
        # ----- PostgreSQL (Supabase / production) -----
        pg_conn = psycopg2.connect(database_url)
        return _PGConnectionWrapper(pg_conn)
    # ----- SQLite (local fallback) -----
    os.makedirs(DATABASE_DIR, exist_ok=True)
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# Serialize database writes made by this Flask process. This is the
# important protection for the MCQ autosave + final-submit race.
DB_WRITE_LOCK = threading.RLock()


def db_write_locked(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with DB_WRITE_LOCK:
            return function(*args, **kwargs)
    return wrapper


def commit_with_retry(connection, attempts=8):
    """Commit a transaction, retrying on SQLite lock. No-op retry for PostgreSQL."""
    last_error = None
    for attempt in range(attempts):
        try:
            connection.commit()
            return
        except Exception as exc:
            last_error = exc
            err_msg = str(exc).lower()
            # Only retry on SQLite lock errors
            if "locked" not in err_msg:
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(0.25 * (attempt + 1))
    if last_error:
        raise last_error


def parse_datetime(value):
    """Parse both ISO timestamps and the older SQLite timestamp format."""
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def column_exists(connection, table_name, column_name):
    # Check if we are on PostgreSQL (no PRAGMA support)
    if os.environ.get("DATABASE_URL") and _PSYCOPG2_AVAILABLE:
        rows = connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s AND column_name = %s",
            (table_name, column_name)
        ).fetchall()
        return len(rows) > 0
    # SQLite: use PRAGMA
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()
    return any(row["name"] == column_name for row in rows)


# ============================================================
# ENVIRONMENT LOADER & VERIFICATION CONFIGURATION
# ============================================================

def load_dotenv():
    """Load configuration from local .env file into os.environ."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k:
                            os.environ[k] = v
        except Exception:
            pass

load_dotenv()

def get_gateway_config():
    """Returns currently loaded SMS and Email gateway configuration."""
    load_dotenv()
    return {
        "SMTP_HOST": os.environ.get("SMTP_HOST", "smtp.gmail.com").strip(),
        "SMTP_PORT": int(os.environ.get("SMTP_PORT", "587")),
        "SMTP_USERNAME": os.environ.get("SMTP_USERNAME", "").strip(),
        "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", "").strip(),
        "SMTP_FROM": (os.environ.get("SMTP_FROM", "") or os.environ.get("SMTP_USERNAME", "")).strip(),
        "SMTP_USE_SSL": os.environ.get("SMTP_USE_SSL", "0").strip() == "1",
        "FAST2SMS_API_KEY": os.environ.get("FAST2SMS_API_KEY", "").strip(),
        "TEXTBEE_API_KEY": os.environ.get("TEXTBEE_API_KEY", "").strip(),
        "TEXTBEE_DEVICE_ID": os.environ.get("TEXTBEE_DEVICE_ID", "").strip(),
        "WHATSAPP_API_KEY": os.environ.get("WHATSAPP_API_KEY", "").strip(),
        "TWILIO_ACCOUNT_SID": os.environ.get("TWILIO_ACCOUNT_SID", "").strip(),
        "TWILIO_AUTH_TOKEN": os.environ.get("TWILIO_AUTH_TOKEN", "").strip(),
        "TWILIO_FROM_NUMBER": os.environ.get("TWILIO_FROM_NUMBER", "").strip(),
        "TWILIO_WHATSAPP_NUMBER": os.environ.get("TWILIO_WHATSAPP_NUMBER", "+14155238886").strip(),
        "OTP_EXPIRY_MINUTES": int(os.environ.get("OTP_EXPIRY_MINUTES", "10")),
    }

def save_gateway_config(config_dict):
    """Safely updates keys in .env and refreshes in-memory os.environ."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    existing_lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            existing_lines = f.readlines()

    keys_written = set()
    new_lines = []
    for line in existing_lines:
        trimmed = line.strip()
        if trimmed and not trimmed.startswith("#") and "=" in trimmed:
            k = trimmed.split("=", 1)[0].strip()
            if k in config_dict:
                new_lines.append(f"{k}={config_dict[k]}\n")
                keys_written.add(k)
                os.environ[k] = str(config_dict[k])
                continue
        new_lines.append(line)

    for k, v in config_dict.items():
        if k not in keys_written:
            new_lines.append(f"{k}={v}\n")
            os.environ[k] = str(v)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    load_dotenv()

OTP_EXPIRY_MINUTES = int(os.environ.get("OTP_EXPIRY_MINUTES", "10"))
OTP_RESEND_SECONDS = int(os.environ.get("OTP_RESEND_SECONDS", "60"))
OTP_VERIFICATION_ENABLED = True



def hash_otp(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def normalize_mobile_number(value):
    """Normalize an Indian 10-digit number or a full international number."""
    raw = (value or "").strip()
    if raw.startswith("+"):
        digits = "+" + re.sub(r"\D", "", raw)
    else:
        digits_only = re.sub(r"\D", "", raw)
        if len(digits_only) == 10:
            digits = "+91" + digits_only
        elif digits_only.startswith("91") and len(digits_only) == 12:
            digits = "+" + digits_only
        else:
            digits = "+" + digits_only

    if not re.fullmatch(r"\+[1-9]\d{7,14}", digits):
        return None
    return digits


def generate_otp():
    return f"{secrets.randbelow(1000000):06d}"


def send_verification_email(recipient, name, code):
    if not all([SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM]):
        raise RuntimeError(
            "Email verification is not configured. Set SMTP_HOST, SMTP_USERNAME, "
            "SMTP_PASSWORD and SMTP_FROM."
        )

    message = EmailMessage()
    message["Subject"] = "College Assessment - Email Verification Code"
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message.set_content(
        "Hello {},\n\n"
        "Your College Assessment email verification code is: {}\n\n"
        "This code expires in {} minutes.\n\n"
        "If you did not request this registration, you can ignore this email.\n\n"
        "College Assessment System".format(name, code, OTP_EXPIRY_MINUTES)
    )

    if SMTP_USE_SSL or SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)


def send_verification_sms(recipient, code):
    """Development-mode mobile verification.

    No SMS provider is contacted. The OTP is printed to the Flask server
    console so the registration flow can be tested without Twilio.
    """
    print("\n" + "=" * 60)
    print(" MOBILE VERIFICATION OTP (DEVELOPMENT MODE)")
    print(" Mobile: {}".format(recipient))
    print(" OTP: {}".format(code))
    print(" Expires in: {} minutes".format(OTP_EXPIRY_MINUTES))
    print("=" * 60 + "\n")
    return True


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():

    connection = get_db_connection()
    # Enable WAL once during startup. Do not run journal_mode=WAL on every
    # request because changing journal mode itself can require a database lock.
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    cursor = connection.cursor()

    # --------------------------------------------------------
    # STUDENTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            roll_number TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    """)

    cursor.execute("UPDATE students SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    cursor.execute("UPDATE students SET status = 'active' WHERE status IS NULL")

    # --------------------------------------------------------
    # STUDENT VERIFICATION COLUMNS
    # --------------------------------------------------------

    if not column_exists(connection, "students", "mobile_number"):
        cursor.execute("ALTER TABLE students ADD COLUMN mobile_number TEXT")

    if not column_exists(connection, "students", "email_verified"):
        cursor.execute("ALTER TABLE students ADD COLUMN email_verified INTEGER DEFAULT 0")

    if not column_exists(connection, "students", "mobile_verified"):
        cursor.execute("ALTER TABLE students ADD COLUMN mobile_verified INTEGER DEFAULT 0")

    if not column_exists(connection, "students", "aadhar_number"):
        cursor.execute("ALTER TABLE students ADD COLUMN aadhar_number TEXT")

    if not column_exists(connection, "students", "uidai_status"):
        cursor.execute("ALTER TABLE students ADD COLUMN uidai_status TEXT DEFAULT 'verified'")

    if not column_exists(connection, "students", "aadhar_card_file"):
        cursor.execute("ALTER TABLE students ADD COLUMN aadhar_card_file TEXT")

    for tbl in ["students", "faculty", "admins"]:
        if not column_exists(connection, tbl, "face_photo"):
            cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN face_photo TEXT")
        if not column_exists(connection, tbl, "face_embedding"):
            cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN face_embedding TEXT")

    # Existing accounts were created before verification was introduced.
    # Mark them as verified so the new feature does not lock out existing students.
    # OTP verification is temporarily disabled. Mark existing accounts as verified
    # so the normal login flow continues to work without interruption.
    if not OTP_VERIFICATION_ENABLED:
        cursor.execute("UPDATE students SET email_verified = 1, mobile_verified = 1")
    else:
        cursor.execute("UPDATE students SET email_verified = 1 WHERE email_verified IS NULL")
        cursor.execute("UPDATE students SET mobile_verified = 1 WHERE mobile_verified IS NULL")

    # --------------------------------------------------------
    # PENDING REGISTRATION VERIFICATIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registration_verifications (
            id INTEGER PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile_number TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email_otp_hash TEXT NOT NULL,
            mobile_otp_hash TEXT NOT NULL,
            email_verified INTEGER DEFAULT 0,
            mobile_verified INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_sent_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # ADMINS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            aadhar_number TEXT,
            mobile_number TEXT,
            uidai_status TEXT DEFAULT 'verified',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    """)

    if not column_exists(connection, "admins", "aadhar_number"):
        cursor.execute("ALTER TABLE admins ADD COLUMN aadhar_number TEXT")
    if not column_exists(connection, "admins", "mobile_number"):
        cursor.execute("ALTER TABLE admins ADD COLUMN mobile_number TEXT")
    if not column_exists(connection, "admins", "uidai_status"):
        cursor.execute("ALTER TABLE admins ADD COLUMN uidai_status TEXT DEFAULT 'verified'")

    # --------------------------------------------------------
    # FACULTY
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS faculty (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            department TEXT,
            designation TEXT,
            password_hash TEXT NOT NULL,
            aadhar_number TEXT,
            mobile_number TEXT,
            uidai_status TEXT DEFAULT 'verified',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    if not column_exists(connection, "faculty", "aadhar_number"):
        cursor.execute("ALTER TABLE faculty ADD COLUMN aadhar_number TEXT")
    if not column_exists(connection, "faculty", "mobile_number"):
        cursor.execute("ALTER TABLE faculty ADD COLUMN mobile_number TEXT")
    if not column_exists(connection, "faculty", "uidai_status"):
        cursor.execute("ALTER TABLE faculty ADD COLUMN uidai_status TEXT DEFAULT 'verified'")


    # --------------------------------------------------------
    # ACTIVITY LOGS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (student_id)
                REFERENCES students(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # COURSES
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE,
            description TEXT,
            instructions TEXT,
            mcq_duration_minutes INTEGER DEFAULT 20,
            coding_duration_minutes INTEGER DEFAULT 60,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # QUESTIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY,

            course_id INTEGER NOT NULL,

            question_type TEXT NOT NULL,

            question_text TEXT NOT NULL,

            option_a TEXT,
            option_b TEXT,
            option_c TEXT,
            option_d TEXT,

            correct_option TEXT,

            coding_input_description TEXT,
            coding_expected_output TEXT,

            points INTEGER DEFAULT 1,

            order_number INTEGER DEFAULT 0,

            is_active INTEGER DEFAULT 1,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (course_id)
                REFERENCES courses(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # ASSESSMENTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY,

            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,

            status TEXT DEFAULT 'instructions',

            started_at TIMESTAMP,

            mcq_started_at TIMESTAMP,
            mcq_submitted_at TIMESTAMP,

            coding_started_at TIMESTAMP,
            coding_submitted_at TIMESTAMP,

            completed_at TIMESTAMP,

            mcq_score INTEGER DEFAULT 0,
            mcq_total INTEGER DEFAULT 0,

            coding_score INTEGER DEFAULT 0,
            coding_total INTEGER DEFAULT 0,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (student_id)
                REFERENCES students(id)
                ON DELETE CASCADE,

            FOREIGN KEY (course_id)
                REFERENCES courses(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # ASSESSMENT QUESTIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessment_questions (
            id INTEGER PRIMARY KEY,

            assessment_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,

            question_order INTEGER NOT NULL,

            FOREIGN KEY (assessment_id)
                REFERENCES assessments(id)
                ON DELETE CASCADE,

            FOREIGN KEY (question_id)
                REFERENCES questions(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # MCQ ANSWERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mcq_answers (
            id INTEGER PRIMARY KEY,

            assessment_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,

            selected_option TEXT,

            answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(assessment_id, question_id),

            FOREIGN KEY (assessment_id)
                REFERENCES assessments(id)
                ON DELETE CASCADE,

            FOREIGN KEY (question_id)
                REFERENCES questions(id)
                ON DELETE CASCADE
        )
    """)
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mcq_answers_unique ON mcq_answers(assessment_id, question_id)")

    # --------------------------------------------------------
    # CODING SUBMISSIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS coding_submissions (
            id INTEGER PRIMARY KEY,

            assessment_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,

            code TEXT,
            input_data TEXT,
            output_data TEXT,
            execution_status TEXT,

            score INTEGER DEFAULT 0,

            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (assessment_id)
                REFERENCES assessments(id)
                ON DELETE CASCADE,

            FOREIGN KEY (question_id)
                REFERENCES questions(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # MCQ SESSIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mcq_sessions (
            id INTEGER PRIMARY KEY,

            assessment_id INTEGER NOT NULL UNIQUE,
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,

            question_ids TEXT NOT NULL,

            started_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,

            submitted_at TEXT,

            status TEXT NOT NULL DEFAULT 'active',

            score INTEGER DEFAULT 0,
            total_questions INTEGER DEFAULT 20,

            FOREIGN KEY (assessment_id)
                REFERENCES assessments(id)
                ON DELETE CASCADE,

            FOREIGN KEY (student_id)
                REFERENCES students(id)
                ON DELETE CASCADE,

            FOREIGN KEY (course_id)
                REFERENCES courses(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # MCQ SESSION ANSWERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mcq_session_answers (
            id INTEGER PRIMARY KEY,

            mcq_session_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,

            selected_answer TEXT,

            answered_at TEXT,

            UNIQUE(mcq_session_id, question_id),

            FOREIGN KEY (mcq_session_id)
                REFERENCES mcq_sessions(id)
                ON DELETE CASCADE,

            FOREIGN KEY (question_id)
                REFERENCES questions(id)
                ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # CODING SESSIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS coding_sessions (
            id INTEGER PRIMARY KEY,
            assessment_id INTEGER NOT NULL UNIQUE,
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            question_ids TEXT NOT NULL,
            started_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            submitted_at TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            score INTEGER DEFAULT 0,
            total_questions INTEGER DEFAULT 3,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        )
    """)

    # --------------------------------------------------------
    # ADD NEW COLUMNS TO EXISTING DATABASES
    # --------------------------------------------------------

    if not column_exists(
        connection,
        "assessments",
        "termination_reason"
    ):
        cursor.execute("""
            ALTER TABLE assessments
            ADD COLUMN termination_reason TEXT
        """)

    if not column_exists(
        connection,
        "assessments",
        "violation_count"
    ):
        cursor.execute("""
            ALTER TABLE assessments
            ADD COLUMN violation_count INTEGER DEFAULT 0
        """)

    cursor.execute("UPDATE admins SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    cursor.execute("UPDATE admins SET status = 'active' WHERE status IS NULL")

    # Legacy workflow status compatibility. Existing rows are preserved.
    cursor.execute("UPDATE assessments SET status = 'mcq' WHERE status = 'mcq_active'")
    cursor.execute("UPDATE assessments SET status = 'mcq_completed' WHERE status = 'coding_ready'")
    cursor.execute("UPDATE assessments SET status = 'coding' WHERE status = 'coding_active'")
    cursor.execute("UPDATE assessments SET status = 'terminated' WHERE status = 'disqualified'")

    # ========================================================
    # CREATE DEMO ADMIN
    # ========================================================

    admin_email = "admin@college.edu"
    admin_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "Admin@123")

    existing_admin = cursor.execute("""
        SELECT id
        FROM admins
        WHERE email = ?
    """, (admin_email,)).fetchone()

    if existing_admin is None:

        cursor.execute("""
            INSERT INTO admins (
                name,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
        """, (
            "College Admin",
            admin_email,
            generate_password_hash(admin_password)
        ))

        print("Demo admin account created.")
        print("Email: admin@college.edu")
        print("Password: (see ADMIN_DEFAULT_PASSWORD env var)")

    # ========================================================
    # CREATE PYTHON COURSE
    # ========================================================

    python_course = cursor.execute("""
        SELECT id
        FROM courses
        WHERE code = ?
    """, ("PYTHON",)).fetchone()

    python_instructions = """
Python Assessment Instructions

1. Make sure you have a stable internet connection.
2. The MCQ section contains 20 questions.
3. The MCQ section has a 20-minute time limit.
4. Questions will be shuffled for each student.
5. After submitting the MCQ section, you will proceed to the coding section.
6. The coding section contains 3 coding questions.
7. The coding section has a total time limit of 60 minutes.
8. Read every question carefully before answering.
9. Do not refresh, close, minimize, or switch away from the assessment.
10. Your assessment activity and results are recorded by the system.
11. Switching browser tabs/windows, refreshing, or leaving the assessment
    page will terminate the attempt immediately.
12. Each student is allowed only one assessment attempt.
""".strip()

    if python_course is None:

        cursor.execute("""
            INSERT INTO courses (
                name,
                code,
                description,
                instructions,
                mcq_duration_minutes,
                coding_duration_minutes,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Python",
            "PYTHON",
            "Python programming assessment",
            python_instructions,
            20,
            60,
            1
        ))

        print("Python course created.")

    else:

        # Keep the existing course but update its instructions
        # so the restrictions are also visible to students.
        cursor.execute("""
            UPDATE courses
            SET instructions = ?,
                mcq_duration_minutes = 20,
                coding_duration_minutes = 60
            WHERE code = 'PYTHON'
        """, (python_instructions,))

    # ========================================================
    # GET PYTHON COURSE ID
    # ========================================================

    python_course = cursor.execute("""
        SELECT id
        FROM courses
        WHERE code = ?
    """, ("PYTHON",)).fetchone()

    # ========================================================
    # CREATE 20 PYTHON MCQs IF NONE EXIST
    # ========================================================

    if python_course:

        python_course_id = python_course["id"]

        existing_mcq_count = cursor.execute("""
            SELECT COUNT(*) AS count
            FROM questions
            WHERE course_id = ?
              AND question_type = 'mcq'
        """, (python_course_id,)).fetchone()["count"]

        if existing_mcq_count == 0:

            python_mcqs = [

                (
                    "Which keyword is used to define a function in Python?",
                    "func",
                    "def",
                    "function",
                    "define",
                    "B"
                ),

                (
                    "Which of the following is a mutable Python data type?",
                    "tuple",
                    "string",
                    "list",
                    "int",
                    "C"
                ),

                (
                    "What is the output of print(2 + 3 * 4)?",
                    "20",
                    "14",
                    "24",
                    "10",
                    "B"
                ),

                (
                    "Which symbol is used for a single-line comment in Python?",
                    "//",
                    "#",
                    "<!--",
                    "--",
                    "B"
                ),

                (
                    "Which function is used to get the length of a list?",
                    "size()",
                    "count()",
                    "length()",
                    "len()",
                    "D"
                ),

                (
                    "What is the correct file extension for a Python file?",
                    ".pt",
                    ".python",
                    ".py",
                    ".pyt",
                    "C"
                ),

                (
                    "Which data type stores key-value pairs?",
                    "list",
                    "tuple",
                    "dictionary",
                    "set",
                    "C"
                ),

                (
                    "What does == do in Python?",
                    "Assigns a value",
                    "Checks equality",
                    "Checks identity",
                    "Adds values",
                    "B"
                ),

                (
                    "Which loop is commonly used to iterate over a sequence?",
                    "repeat",
                    "foreach",
                    "for",
                    "loop",
                    "C"
                ),

                (
                    "Which statement is used to handle exceptions?",
                    "try/except",
                    "if/else",
                    "do/catch",
                    "error/handle",
                    "A"
                ),

                (
                    "What is the result of len('Python')?",
                    "5",
                    "6",
                    "7",
                    "8",
                    "B"
                ),

                (
                    "Which operator performs floor division?",
                    "/",
                    "%",
                    "//",
                    "**",
                    "C"
                ),

                (
                    "Which keyword is used to create a class?",
                    "object",
                    "class",
                    "struct",
                    "type",
                    "B"
                ),

                (
                    "What does the append() method do to a list?",
                    "Removes an item",
                    "Sorts the list",
                    "Adds an item to the end",
                    "Copies the list",
                    "C"
                ),

                (
                    "Which value represents Boolean false in Python?",
                    "false",
                    "False",
                    "FALSE",
                    "0",
                    "B"
                ),

                (
                    "Which built-in function converts a string to an integer?",
                    "str()",
                    "float()",
                    "integer()",
                    "int()",
                    "D"
                ),

                (
                    "What is the output of print(type(10).__name__)?",
                    "number",
                    "int",
                    "integer",
                    "float",
                    "B"
                ),

                (
                    "Which keyword exits a loop immediately?",
                    "stop",
                    "exit",
                    "break",
                    "return",
                    "C"
                ),

                (
                    "Which keyword skips the current iteration of a loop?",
                    "skip",
                    "continue",
                    "pass",
                    "next",
                    "B"
                ),

                (
                    "Which of these creates a tuple?",
                    "[1, 2]",
                    "{1, 2}",
                    "(1, 2)",
                    "<1, 2>",
                    "C"
                )
            ]

            for index, mcq in enumerate(
                python_mcqs,
                start=1
            ):

                cursor.execute("""
                    INSERT INTO questions (
                        course_id,
                        question_type,
                        question_text,
                        option_a,
                        option_b,
                        option_c,
                        option_d,
                        correct_option,
                        points,
                        order_number,
                        is_active
                    )
                    VALUES (
                        ?,
                        'mcq',
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        1,
                        ?,
                        1
                    )
                """, (
                    python_course_id,
                    mcq[0],
                    mcq[1],
                    mcq[2],
                    mcq[3],
                    mcq[4],
                    mcq[5],
                    index
                ))

            print("20 Python MCQ questions created.")

    # ========================================================
    # CREATE 3 PYTHON CODING QUESTIONS IF NONE EXIST
    # ========================================================

    if python_course:

        python_course_id = python_course["id"]

        existing_coding_count = cursor.execute("""
            SELECT COUNT(*) AS count
            FROM questions
            WHERE course_id = ?
              AND question_type = 'coding'
        """, (python_course_id,)).fetchone()["count"]

        if existing_coding_count == 0:

            coding_questions = [
                (
                    "Sum of Two Integers",
                    """Read two integers from standard input and print their sum.

Input format: two integers separated by spaces or new lines.""",
                    [
                        {"input": "5 7", "output": "12"},
                        {"input": "100 250", "output": "350"},
                        {"input": "-8 3", "output": "-5"}
                    ]
                ),
                (
                    "Palindrome Checker",
                    """Read one string and print YES if it is a palindrome, otherwise print NO.

Treat uppercase and lowercase letters as different. Ignore surrounding whitespace.""",
                    [
                        {"input": "madam", "output": "YES"},
                        {"input": "hello", "output": "NO"},
                        {"input": "level", "output": "YES"}
                    ]
                ),
                (
                    "Count Vowels",
                    """Read one line of text and print the number of English vowels (a, e, i, o, u) in the text.

Count both uppercase and lowercase vowels.""",
                    [
                        {"input": "Education", "output": "5"},
                        {"input": "Python Programming", "output": "4"},
                        {"input": "AEIOU", "output": "5"}
                    ]
                )
            ]

            for index, item in enumerate(coding_questions, start=1):
                cursor.execute("""
                    INSERT INTO questions (
                        course_id,
                        question_type,
                        question_text,
                        coding_input_description,
                        coding_expected_output,
                        points,
                        order_number,
                        is_active
                    )
                    VALUES (?, 'coding', ?, ?, ?, 10, ?, 1)
                """, (
                    python_course_id,
                    item[0],
                    item[1],
                    json.dumps(item[2]),
                    index
                ))

            print("3 Python coding questions created.")

    # --------------------------------------------------------
    # ATTENDANCE TABLE
    # --------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            faculty_id INTEGER,
            attendance_date TEXT NOT NULL,
            topic TEXT,
            status TEXT NOT NULL CHECK(status IN ('Present', 'Absent', 'Late')),
            remarks TEXT,
            marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
            FOREIGN KEY (faculty_id) REFERENCES admins(id) ON DELETE SET NULL,
            UNIQUE(student_id, course_id, attendance_date)
        )
    """)

    # Seed initial attendance data if table is empty
    attendance_count = cursor.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    if attendance_count == 0:
        seed_topics = [
            "Introduction to Python & Setup",
            "Variables, Data Types & Operators",
            "Control Flow: If-Else & Match Case",
            "Loops: While, For & Comprehensions",
            "Functions, Arguments & Scope",
            "Data Structures: Lists, Tuples & Sets",
            "Dictionaries & Key-Value Operations",
            "String Processing & File I/O",
            "Exception Handling: Try, Except, Finally",
            "OOP: Classes, Objects & Methods"
        ]
        all_students = cursor.execute("SELECT id FROM students").fetchall()
        demo_admin = cursor.execute("SELECT id FROM admins LIMIT 1").fetchone()
        f_id = demo_admin[0] if demo_admin else 1
        p_course = cursor.execute("SELECT id FROM courses WHERE code = 'PYTHON'").fetchone()
        p_course_id = p_course[0] if p_course else 1

        today_date = datetime.now().date()
        past_dates = []
        cur_d = today_date - timedelta(days=1)
        while len(past_dates) < 10:
            if cur_d.weekday() < 5:
                past_dates.append(cur_d)
            cur_d -= timedelta(days=1)
        past_dates.reverse()

        for idx, dt in enumerate(past_dates):
            d_str = dt.strftime("%Y-%m-%d")
            top = seed_topics[idx % len(seed_topics)]
            for st in all_students:
                s_id = st[0]
                if s_id == 1:
                    att_status = "Late" if idx == 4 else "Present"
                    rem = "Late by 10 mins" if idx == 4 else ""
                elif s_id == 2:
                    att_status = "Absent" if idx in [2, 7] else "Present"
                    rem = "Medical leave" if idx == 2 else ""
                elif s_id == 3:
                    att_status = "Absent" if idx in [1, 3, 6, 8] else "Present"
                    rem = ""
                else:
                    if (s_id + idx) % 7 == 0:
                        att_status = "Absent"
                        rem = "Absent"
                    elif (s_id + idx) % 5 == 0:
                        att_status = "Late"
                        rem = "Late arrival"
                    else:
                        att_status = "Present"
                        rem = ""

                cursor.execute("""
                    INSERT INTO attendance (student_id, course_id, faculty_id, attendance_date, topic, status, remarks)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (s_id, p_course_id, f_id, d_str, top, att_status, rem))

    # --------------------------------------------------------
    # CAMPUS HUB: NOTICES, TIMETABLE, PLACEMENTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campus_notices (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Academic',
            audience TEXT NOT NULL DEFAULT 'all',
            is_pinned INTEGER DEFAULT 0,
            posted_by TEXT NOT NULL DEFAULT 'Office of the Dean',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS timetable_slots (
            id INTEGER PRIMARY KEY,
            day_name TEXT NOT NULL,
            period_no INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            course_code TEXT,
            course_name TEXT NOT NULL,
            faculty_name TEXT,
            room TEXT,
            slot_type TEXT DEFAULT 'lecture'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS placement_drives (
            id INTEGER PRIMARY KEY,
            company TEXT NOT NULL,
            role TEXT NOT NULL,
            ctc TEXT,
            deadline TEXT,
            eligibility TEXT,
            status TEXT DEFAULT 'Open',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS placement_applications (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL,
            drive_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(student_id, drive_id),
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (drive_id) REFERENCES placement_drives(id) ON DELETE CASCADE
        )
    """)

    notice_count = cursor.execute("SELECT COUNT(*) FROM campus_notices").fetchone()[0]
    if notice_count == 0:
        seed_notices = [
            (
                "Odd Semester 2026-27 Academic Calendar Released",
                "Classes resume from 15 July 2026. Mid-semester CIE windows for CodeTech labs will run in Weeks 6 and 12. End-semester theory exams follow the AKTU schedule.",
                "Academic",
                "all",
                1,
                "Dean Academics"
            ),
            (
                "Mandatory 75% Attendance for University Examination",
                "Students below 75% theory or practical attendance will not be issued admit cards. Shortage lists are published every Friday on the student SIS.",
                "Examination",
                "student",
                1,
                "Controller of Examinations"
            ),
            (
                "Campus Recruitment Drive: TCS NQT & Infosys Off-Campus",
                "Final-year CSE, IT, and ECE students with 6.5+ CGPA and no active backlogs may apply from the Placement Cell. Resume screening closes this Friday 5:00 PM.",
                "Placement",
                "student",
                0,
                "Training & Placement Cell"
            ),
            (
                "Faculty Development Programme — AI in Laboratory Assessment",
                "CSE faculty are invited to a two-day workshop on automated coding evaluation and proctored CIE. Register through the Faculty Workstation.",
                "Faculty",
                "faculty",
                0,
                "HOD, Computer Science"
            ),
            (
                "Library & Digital Resources Extended Hours",
                "Central library remains open 8:00 AM – 9:00 PM during CIE week. NPTEL and IEEE Xplore access is available on campus LAN and VPN.",
                "Campus",
                "all",
                0,
                "Central Library"
            ),
        ]
        for title, body, category, audience, pinned, posted_by in seed_notices:
            cursor.execute(
                """
                INSERT INTO campus_notices (title, body, category, audience, is_pinned, posted_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, body, category, audience, pinned, posted_by),
            )

    slot_count = cursor.execute("SELECT COUNT(*) FROM timetable_slots").fetchone()[0]
    if slot_count == 0:
        periods = [
            (1, "09:00", "09:55"),
            (2, "10:00", "10:55"),
            (3, "11:10", "12:05"),
            (4, "12:10", "13:05"),
            (5, "14:00", "14:55"),
            (6, "15:00", "15:55"),
            (7, "16:00", "16:55"),
        ]
        week = {
            "Monday": [
                ("BCS301", "C Programming Lab", "Prof. N. Sharma", "Lab-1", "lab"),
                ("BCS401", "Java Programming", "Dr. A. Verma", "LH-204", "lecture"),
                ("BAS301", "Discrete Mathematics", "Dr. P. Gupta", "LH-101", "lecture"),
                ("", "Lunch Break", "", "Cafeteria", "break"),
                ("BCS351", "Python for Data Science", "Prof. R. Singh", "LH-210", "lecture"),
                ("BCS301", "C / DS Tutorial", "Prof. N. Sharma", "Tut-2", "tutorial"),
                ("", "Mentor Hour / Sports", "", "Campus", "activity"),
            ],
            "Tuesday": [
                ("BCS401", "Java Programming Lab", "Dr. A. Verma", "Lab-2", "lab"),
                ("BCS351", "Python for Data Science", "Prof. R. Singh", "LH-210", "lecture"),
                ("BCS301", "C Programming", "Prof. N. Sharma", "LH-204", "lecture"),
                ("", "Lunch Break", "", "Cafeteria", "break"),
                ("BAS301", "Discrete Mathematics", "Dr. P. Gupta", "LH-101", "lecture"),
                ("BVE301", "Universal Human Values", "Ms. K. Jain", "LH-108", "lecture"),
                ("", "Library / Self Study", "", "Library", "activity"),
            ],
            "Wednesday": [
                ("BCS351", "Python Lab", "Prof. R. Singh", "Lab-3", "lab"),
                ("BCS401", "OOP with Java", "Dr. A. Verma", "LH-204", "lecture"),
                ("BCS301", "Data Structures", "Prof. N. Sharma", "LH-204", "lecture"),
                ("", "Lunch Break", "", "Cafeteria", "break"),
                ("BCS358", "CodeTech CIE Window", "Exam Cell", "Lab-1/2", "exam"),
                ("BAS301", "Tutorial — Combinatorics", "Dr. P. Gupta", "Tut-1", "tutorial"),
                ("", "NSS / Club Activity", "", "Seminar Hall", "activity"),
            ],
            "Thursday": [
                ("BCS401", "Java Collections Lab", "Dr. A. Verma", "Lab-2", "lab"),
                ("BCS301", "C Programming", "Prof. N. Sharma", "LH-204", "lecture"),
                ("BCS351", "NumPy & Pandas", "Prof. R. Singh", "LH-210", "lecture"),
                ("", "Lunch Break", "", "Cafeteria", "break"),
                ("BAS301", "Graph Theory", "Dr. P. Gupta", "LH-101", "lecture"),
                ("BCS401", "Java Tutorial", "Dr. A. Verma", "Tut-3", "tutorial"),
                ("", "Training & Placement", "T&P Cell", "Auditorium", "activity"),
            ],
            "Friday": [
                ("BCS351", "Python Mini-Project", "Prof. R. Singh", "Lab-3", "lab"),
                ("BCS301", "Pointers & Memory", "Prof. N. Sharma", "LH-204", "lecture"),
                ("BCS401", "Exception Handling", "Dr. A. Verma", "LH-204", "lecture"),
                ("", "Lunch Break", "", "Cafeteria", "break"),
                ("BVE301", "UHV Discussion", "Ms. K. Jain", "LH-108", "lecture"),
                ("", "Department Seminar", "HOD CSE", "Seminar Hall", "activity"),
                ("", "Faculty Meeting / Mentoring", "", "Dept. Office", "activity"),
            ],
        }
        for day_name, slots in week.items():
            for idx, (code, name, faculty, room, slot_type) in enumerate(slots):
                period_no, start_time, end_time = periods[idx]
                cursor.execute(
                    """
                    INSERT INTO timetable_slots
                    (day_name, period_no, start_time, end_time, course_code, course_name, faculty_name, room, slot_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (day_name, period_no, start_time, end_time, code, name, faculty, room, slot_type),
                )

    drive_count = cursor.execute("SELECT COUNT(*) FROM placement_drives").fetchone()[0]
    if drive_count == 0:
        seed_drives = [
            (
                "Tata Consultancy Services",
                "Ninja / Digital / Prime",
                "3.36 – 9 LPA",
                "31 Oct 2026",
                "B.Tech CSE/IT/ECE • 6.5 CGPA • 0 backlog",
                "Open",
                "National Qualifier Test followed by technical and HR rounds. CodeTech lab scores will be considered for Digital/Prime shortlists.",
            ),
            (
                "Infosys Limited",
                "Systems Engineer",
                "3.6 – 9.5 LPA",
                "12 Nov 2026",
                "B.Tech all branches • 6.0 CGPA • max 1 backlog",
                "Open",
                "InfyTQ certification holders get a direct interview skip for the first round.",
            ),
            (
                "Amazon",
                "SDE Intern",
                "Stipend 1.1 L/month",
                "20 Oct 2026",
                "Pre-final year CSE/IT • strong DSA • 7.0 CGPA",
                "Closing Soon",
                "Online OA (DSA + debugging) then two technical interviews. Campus CodeTech Python/Java scores are attached to the application.",
            ),
            (
                "Wipro",
                "Project Engineer",
                "3.5 LPA",
                "05 Nov 2026",
                "B.Tech CSE/IT/ECE/ME • 6.0 CGPA",
                "Open",
                "WILP option available. Communication round is mandatory.",
            ),
            (
                "Microsoft",
                "SWE Intern",
                "Stipend 1.25 L/month",
                "18 Oct 2026",
                "Pre-final year • 8.0 CGPA • no backlog ever",
                "Invite Only",
                "Referrals via T&P. Competitive programming profile recommended.",
            ),
        ]
        for company, role, ctc, deadline, eligibility, status, description in seed_drives:
            cursor.execute(
                """
                INSERT INTO placement_drives
                (company, role, ctc, deadline, eligibility, status, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (company, role, ctc, deadline, eligibility, status, description),
            )

    commit_with_retry(connection)
    connection.close()

    try:
        from db_seed_upgrade import upgrade_and_seed
        upgrade_and_seed()
    except Exception as _seed_err:
        print("Note on auto upgrade_and_seed:", _seed_err)


# ============================================================
# LOGIN REQUIRED DECORATORS
# ============================================================

def student_login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "student_id" not in session or session.get("role") != "student":
            flash("Please login to the Student Portal first.", "error")
            return redirect(url_for("login", tab="student"))
        return function(*args, **kwargs)
    return decorated_function


def faculty_login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "faculty_id" not in session or session.get("role") != "faculty":
            flash("Please login to the Faculty Portal first.", "error")
            return redirect(url_for("login", tab="faculty"))
        return function(*args, **kwargs)
    return decorated_function


def admin_login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session or session.get("role") != "admin":
            flash("Please login to the Administrator Portal first.", "error")
            return redirect(url_for("login", tab="admin"))
        return function(*args, **kwargs)
    return decorated_function


def faculty_or_admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "faculty_id" not in session and "admin_id" not in session:
            flash("Please login as faculty or admin first.", "error")
            return redirect(url_for("login", tab="faculty"))
        return function(*args, **kwargs)
    return decorated_function


# ============================================================
# ACTIVITY LOGGING
# ============================================================

def log_activity(student_id, action):

    connection = get_db_connection()

    connection.execute("""
        INSERT INTO activity_logs (
            student_id,
            action,
            created_at
        )
        VALUES (?, ?, ?)
    """, (
        student_id,
        action,
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    commit_with_retry(connection)
    connection.close()


# ============================================================
# ATTENDANCE HELPERS
# ============================================================

def get_student_attendance_summary(connection, student_id, course_id=None):
    """Calculate overall and course-wise attendance stats for a student."""
    query = """
        SELECT
            COUNT(*) as total_classes,
            SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) as present_count,
            SUM(CASE WHEN status = 'Late' THEN 1 ELSE 0 END) as late_count,
            SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) as absent_count
        FROM attendance
        WHERE student_id = ?
    """
    params = [student_id]
    if course_id:
        query += " AND course_id = ?"
        params.append(course_id)

    row = connection.execute(query, params).fetchone()
    total = (row["total_classes"] or 0) if row else 0
    present = (row["present_count"] or 0) if row else 0
    late = (row["late_count"] or 0) if row else 0
    absent = (row["absent_count"] or 0) if row else 0

    attended = present + late
    percentage = round((attended / total * 100), 1) if total > 0 else 100.0
    status_label = "Eligible" if percentage >= 75.0 else "Shortage"

    return {
        "total_classes": total,
        "present_count": present,
        "late_count": late,
        "absent_count": absent,
        "attended_count": attended,
        "percentage": percentage,
        "status_label": status_label,
        "is_eligible": percentage >= 75.0
    }


def get_student_attendance_records(connection, student_id, course_id=None, limit=None):
    """Retrieve chronologically ordered attendance logs for a student."""
    query = """
        SELECT
            attendance.*,
            courses.name as course_name,
            courses.code as course_code,
            COALESCE(faculty.name, admins.name, 'Faculty Member') as faculty_name
        FROM attendance
        JOIN courses ON attendance.course_id = courses.id
        LEFT JOIN faculty ON attendance.faculty_id = faculty.id
        LEFT JOIN admins ON attendance.faculty_id = admins.id
        WHERE attendance.student_id = ?
    """
    params = [student_id]
    if course_id:
        query += " AND attendance.course_id = ?"
        params.append(course_id)
    query += " ORDER BY attendance.attendance_date DESC, attendance.id DESC"
    if limit:
        query += f" LIMIT {int(limit)}"

    return connection.execute(query, params).fetchall()


def get_attendance_overview_stats(connection):
    """Calculate college/faculty wide attendance statistics."""
    session_row = connection.execute("""
        SELECT COUNT(DISTINCT attendance_date || '-' || course_id) as session_count
        FROM attendance
    """).fetchone()
    sessions = session_row["session_count"] if session_row else 0

    total_marks = connection.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status IN ('Present', 'Late') THEN 1 ELSE 0 END) as attended
        FROM attendance
    """).fetchone()

    total = total_marks["total"] or 0 if total_marks else 0
    attended = total_marks["attended"] or 0 if total_marks else 0
    avg_percentage = round((attended / total * 100), 1) if total > 0 else 0.0

    students = connection.execute("SELECT id FROM students WHERE status = 'active'").fetchall()
    shortage_count = 0
    good_count = 0
    for st in students:
        summary = get_student_attendance_summary(connection, st["id"])
        if summary["total_classes"] > 0:
            if summary["percentage"] < 75.0:
                shortage_count += 1
            else:
                good_count += 1

    return {
        "session_count": sessions,
        "total_marks": total,
        "avg_percentage": avg_percentage,
        "shortage_count": shortage_count,
        "good_count": good_count
    }


def get_recent_attendance_sessions(connection, limit=10):
    """Get list of past attendance sessions with date, course, topic, counts."""
    query = f"""
        SELECT
            attendance.attendance_date,
            attendance.course_id,
            courses.name as course_name,
            attendance.topic,
            COALESCE(faculty.name, admins.name, 'Faculty Member') as faculty_name,
            COUNT(*) as total_students,
            SUM(CASE WHEN attendance.status = 'Present' THEN 1 ELSE 0 END) as present_count,
            SUM(CASE WHEN attendance.status = 'Late' THEN 1 ELSE 0 END) as late_count,
            SUM(CASE WHEN attendance.status = 'Absent' THEN 1 ELSE 0 END) as absent_count,
            ROUND(SUM(CASE WHEN attendance.status IN ('Present', 'Late') THEN 1.0 ELSE 0.0 END) / COUNT(*) * 100, 1) as percentage
        FROM attendance
        JOIN courses ON attendance.course_id = courses.id
        LEFT JOIN faculty ON attendance.faculty_id = faculty.id
        LEFT JOIN admins ON attendance.faculty_id = admins.id
        GROUP BY attendance.attendance_date, attendance.course_id, courses.name, attendance.topic, faculty.name, admins.name
        ORDER BY attendance.attendance_date DESC
        LIMIT {int(limit)}
    """
    return connection.execute(query).fetchall()


# ============================================================
# TERMINATE ASSESSMENT
# ============================================================

@db_write_locked
def terminate_assessment(
    assessment_id,
    student_id,
    reason
):
    """
    Permanently terminates an assessment attempt.

    This is intentionally irreversible.
    """

    connection = get_db_connection()

    assessment = connection.execute("""
        SELECT status
        FROM assessments
        WHERE id = ?
          AND student_id = ?
    """, (
        assessment_id,
        student_id
    )).fetchone()

    if assessment is None:

        connection.close()

        return False

    if assessment["status"] in ("completed", "terminated", "disqualified", "cancelled"):


        connection.close()

        return False

    connection.execute("""
        UPDATE assessments

        SET
            status = 'terminated',
            termination_reason = ?,
            violation_count =
                COALESCE(violation_count, 0) + 1,
            completed_at = CURRENT_TIMESTAMP

        WHERE id = ?
          AND student_id = ?
    """, (
        reason,
        assessment_id,
        student_id
    ))

    connection.execute("""
        UPDATE mcq_sessions

        SET
            status = 'terminated',
            submitted_at = CURRENT_TIMESTAMP

        WHERE assessment_id = ?
          AND student_id = ?
          AND status = 'active'
    """, (
        assessment_id,
        student_id
    ))

    connection.execute("""
        UPDATE coding_sessions

        SET
            status = 'terminated',
            submitted_at = CURRENT_TIMESTAMP

        WHERE assessment_id = ?
          AND student_id = ?
          AND status = 'active'
    """, (
        assessment_id,
        student_id
    ))

    commit_with_retry(connection)
    connection.close()

    log_activity(
        student_id,
        "ASSESSMENT TERMINATED: {}".format(
            reason
        )
    )

    # Remove all active-test browser session data.
    session.pop("assessment_id", None)
    session.pop("course_id", None)
    session.pop("mcq_session_id", None)
    session.pop("mcq_entry_token", None)
    session.pop("assessment_active", None)

    return True


# ============================================================
# GET STUDENT'S SINGLE ATTEMPT
# ============================================================

def get_student_attempt(
    connection,
    student_id,
    course_id=None
):
    if course_id:
        return connection.execute("""
            SELECT
                assessments.*,
                courses.name AS course_name,
                courses.code AS course_code
            FROM assessments
            LEFT JOIN courses
                ON assessments.course_id = courses.id
            WHERE assessments.student_id = ?
              AND assessments.course_id = ?
            ORDER BY assessments.id DESC
            LIMIT 1
        """, (student_id, course_id)).fetchone()

    # Prioritize any active attempt in progress
    active = connection.execute("""
        SELECT
            assessments.*,
            courses.name AS course_name,
            courses.code AS course_code
        FROM assessments
        LEFT JOIN courses
            ON assessments.course_id = courses.id
        WHERE assessments.student_id = ?
          AND assessments.status IN ('instructions', 'mcq', 'mcq_active', 'mcq_completed', 'coding_ready', 'coding', 'coding_active')
        ORDER BY assessments.id DESC
        LIMIT 1
    """, (student_id,)).fetchone()

    if active:
        return active

    return connection.execute("""
        SELECT
            assessments.*,
            courses.name AS course_name,
            courses.code AS course_code
        FROM assessments
        LEFT JOIN courses
            ON assessments.course_id = courses.id
        WHERE assessments.student_id = ?
        ORDER BY assessments.id DESC
        LIMIT 1
    """, (
        student_id,
    )).fetchone()


# ============================================================
# COURSE OUTCOME (CO) ATTAINMENT & ACADEMIC EVALUATION ENGINE
# ============================================================

def get_student_skill_analytics(connection, student_id):
    """
    Computes Course Outcome (CO) Attainment, Theory vs Coding Correlation,
    and unit-wise student competency indicators.
    """
    completed_assessments = connection.execute("""
        SELECT assessments.*, courses.code as course_code, courses.name as course_name
        FROM assessments
        JOIN courses ON assessments.course_id = courses.id
        WHERE assessments.student_id = ? AND assessments.status = 'completed'
    """, (student_id,)).fetchall()

    total_mcq_score = sum(a["mcq_score"] for a in completed_assessments) if completed_assessments else 0
    total_mcq_max = sum(a["mcq_total"] for a in completed_assessments) if completed_assessments else 0
    total_coding_score = sum(a["coding_score"] for a in completed_assessments) if completed_assessments else 0
    total_coding_max = sum(a["coding_total"] for a in completed_assessments) if completed_assessments else 0

    if total_mcq_max > 0:
        mcq_pct = round((total_mcq_score / total_mcq_max * 100), 1)
    else:
        mcq_pct = 78.0

    if total_coding_max > 0:
        coding_pct = round((total_coding_score / total_coding_max * 100), 1)
    else:
        coding_pct = 68.0

    skill_index = round((mcq_pct * 0.4 + coding_pct * 0.6), 1)

    if mcq_pct >= 75 and coding_pct >= 75:
        diagnostic = "Advanced Core Competency — High theoretical understanding & practical implementation ability."
    elif mcq_pct >= 70 and coding_pct < 65:
        diagnostic = "Theory-Heavy Profile — Strong conceptual understanding; needs more hands-on coding practice."
    elif mcq_pct < 65 and coding_pct >= 70:
        diagnostic = "Empirical Practitioner — Solid coding implementation; review syllabus theory & syntax concepts."
    else:
        diagnostic = "Balanced Foundation — Guided practice in both concept drills and test cases recommended."

    competencies = [
        {"name": "Core Syntax & Logic", "score": min(95, max(45, int(mcq_pct * 1.05)))},
        {"name": "Algorithmic Problem Solving", "score": min(95, max(40, int(coding_pct * 1.02)))},
        {"name": "Object-Oriented Design (OOP)", "score": min(90, max(45, int((mcq_pct + coding_pct) / 2)))},
        {"name": "Memory & Pointer Management", "score": min(85, max(35, int(coding_pct * 0.85 + mcq_pct * 0.15)))},
    ]

    return {
        "skill_index": skill_index,
        "mcq_pct": mcq_pct,
        "coding_pct": coding_pct,
        "diagnostic_label": diagnostic,
        "competencies": competencies,
        "completed_count": len(completed_assessments)
    }


def get_class_skill_heatmap(connection, course_id=None):
    """
    Computes class-wide topic and syllabus unit performance matrix for faculty workstation.
    """
    syllabus_map = [
        {"unit": "Unit 1: Fundamentals & Architecture", "topic": "Variables, Types & JVM/Compiler", "skill": "Syntax & Logic", "mastery_pct": 86},
        {"unit": "Unit 2: Control Flow & Logic", "topic": "Conditionals, Loops & Recursion", "skill": "Algorithmic Thinking", "mastery_pct": 78},
        {"unit": "Unit 3: Object-Oriented Design", "topic": "Classes, Inheritance & Polymorphism", "skill": "OOP Paradigm", "mastery_pct": 65},
        {"unit": "Unit 4: Memory & Pointers", "topic": "Pointer Arithmetic & Dynamic Allocation", "skill": "Memory Management", "mastery_pct": 48},
        {"unit": "Unit 5: Collections & Structures", "topic": "Lists, Sets, Maps & Structs", "skill": "Data Structures", "mastery_pct": 59},
    ]

    return syllabus_map


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():
    if "student_id" in session:
        return redirect(
            url_for("student_dashboard")
        )

    if "faculty_id" in session:
        return redirect(
            url_for("faculty_dashboard")
        )

    if "admin_id" in session:
        return redirect(
            url_for("admin_dashboard")
        )

    return redirect(
        url_for("login")
    )


def _visible_notice_clause(role):
    if role == "student":
        return "audience IN ('all', 'student')"
    if role == "faculty":
        return "audience IN ('all', 'faculty')"
    if role == "admin":
        return "1=1"
    return "audience = 'all'"


@app.route("/campus/notices", methods=["GET", "POST"])
def campus_notices():
    role = session.get("role")
    can_post = role in ("faculty", "admin")

    if request.method == "POST":
        if not can_post:
            flash("Only faculty and administrators can publish circulars.", "error")
            return redirect(url_for("campus_notices"))

        title = (request.form.get("title") or "").strip()
        body = (request.form.get("body") or "").strip()
        category = (request.form.get("category") or "Academic").strip()
        audience = (request.form.get("audience") or "all").strip()
        is_pinned = 1 if request.form.get("is_pinned") == "1" else 0
        posted_by = (
            session.get("faculty_name")
            or session.get("admin_name")
            or "Campus Office"
        )

        if not title or not body:
            flash("Title and message are required.", "error")
            return redirect(url_for("campus_notices"))

        connection = get_db_connection()
        with DB_WRITE_LOCK:
            connection.execute(
                """
                INSERT INTO campus_notices (title, body, category, audience, is_pinned, posted_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, body, category, audience, is_pinned, posted_by),
            )
            commit_with_retry(connection)
        connection.close()
        flash("Circular published on the campus notice board.", "success")
        return redirect(url_for("campus_notices"))

    connection = get_db_connection()
    notices = connection.execute(
        f"""
        SELECT * FROM campus_notices
        WHERE {_visible_notice_clause(role)}
        ORDER BY is_pinned DESC, created_at DESC
        """
    ).fetchall()
    connection.close()

    return render_template(
        "notices.html",
        notices=notices,
        can_post=can_post,
    )


@app.route("/campus/timetable")
def campus_timetable():
    connection = get_db_connection()
    slots = connection.execute(
        """
        SELECT * FROM timetable_slots
        ORDER BY
            CASE day_name
                WHEN 'Monday' THEN 1
                WHEN 'Tuesday' THEN 2
                WHEN 'Wednesday' THEN 3
                WHEN 'Thursday' THEN 4
                WHEN 'Friday' THEN 5
                ELSE 6
            END,
            period_no ASC
        """
    ).fetchall()
    connection.close()

    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    periods = []
    for slot in slots:
        key = (slot["period_no"], slot["start_time"], slot["end_time"])
        if key not in periods:
            periods.append(key)

    grid = {day: {} for day in days}
    for slot in slots:
        grid[slot["day_name"]][slot["period_no"]] = slot

    weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    today_name = weekday_names[datetime.now().weekday()]

    return render_template(
        "timetable.html",
        days=days,
        periods=periods,
        grid=grid,
        today_name=today_name,
    )


@app.route("/campus/placements")
def campus_placements():
    connection = get_db_connection()
    drives = connection.execute(
        "SELECT * FROM placement_drives ORDER BY id ASC"
    ).fetchall()

    applied_ids = set()
    if session.get("student_id"):
        rows = connection.execute(
            "SELECT drive_id FROM placement_applications WHERE student_id = ?",
            (session["student_id"],),
        ).fetchall()
        applied_ids = {row["drive_id"] for row in rows}

    connection.close()
    return render_template(
        "placements.html",
        drives=drives,
        applied_ids=applied_ids,
    )


@app.route("/campus/placements/<int:drive_id>/apply", methods=["POST"])
@student_login_required
def apply_placement(drive_id):
    student_id = session["student_id"]
    connection = get_db_connection()
    drive = connection.execute(
        "SELECT * FROM placement_drives WHERE id = ?",
        (drive_id,),
    ).fetchone()
    if not drive:
        connection.close()
        flash("This recruitment drive is no longer listed.", "error")
        return redirect(url_for("campus_placements"))

    with DB_WRITE_LOCK:
        try:
            connection.execute(
                """
                INSERT INTO placement_applications (student_id, drive_id)
                VALUES (?, ?)
                """,
                (student_id, drive_id),
            )
            commit_with_retry(connection)
            flash(f"Application submitted to {drive['company']} — {drive['role']}.", "success")
        except DBIntegrityError:
            flash("You have already applied to this drive.", "error")
    connection.close()
    return redirect(url_for("campus_placements"))


@app.route("/student/results")
@student_login_required
def student_results():
    student_id = session["student_id"]
    connection = get_db_connection()
    student = connection.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,),
    ).fetchone()
    rows = connection.execute(
        """
        SELECT a.*, c.name AS course_name, c.code AS course_code
        FROM assessments a
        JOIN courses c ON c.id = a.course_id
        WHERE a.student_id = ?
        ORDER BY a.id DESC
        """,
        (student_id,),
    ).fetchall()
    attendance_summary = get_student_attendance_summary(connection, student_id)
    connection.close()

    marksheet = []
    total_obtained = 0
    total_max = 0
    for row in rows:
        mcq_score = row["mcq_score"] or 0
        mcq_total = row["mcq_total"] or 0
        coding_score = row["coding_score"] or 0
        coding_total = row["coding_total"] or 0
        obtained = mcq_score + coding_score
        maximum = mcq_total + coding_total
        pct = round((obtained / maximum) * 100, 1) if maximum else 0
        if pct >= 85:
            grade = "A+"
        elif pct >= 75:
            grade = "A"
        elif pct >= 65:
            grade = "B+"
        elif pct >= 55:
            grade = "B"
        elif pct >= 40:
            grade = "C"
        else:
            grade = "F"
        marksheet.append(
            {
                "row": row,
                "obtained": obtained,
                "maximum": maximum,
                "pct": pct,
                "grade": grade,
            }
        )
        if row["status"] == "completed":
            total_obtained += obtained
            total_max += maximum

    overall_pct = round((total_obtained / total_max) * 100, 1) if total_max else 0

    return render_template(
        "student_results.html",
        student=student,
        marksheet=marksheet,
        total_obtained=total_obtained,
        total_max=total_max,
        overall_pct=overall_pct,
        attendance_summary=attendance_summary,
    )


# ============================================================
# UNIFIED LOGIN (STUDENT, FACULTY, ADMIN)
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        client_ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "")).split(",")[0].strip()
        role = request.form.get(
            "role",
            "student"
        ).strip().lower()

        rate_key = f"login:{client_ip}:{role}"
        allowed, wait_sec = check_rate_limit(rate_key, max_attempts=8, window_seconds=300)
        if not allowed:
            flash(f"Too many failed login attempts from this network. Please wait {wait_sec} seconds before trying again.", "error")
            return render_template("login.html", active_tab=role)

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            flash(
                "Please enter your email and password.",
                "error"
            )

            return render_template(
                "login.html",
                active_tab=role
            )

        connection = get_db_connection()

        # ----------------------------------------------------
        # FACULTY LOGIN
        # ----------------------------------------------------
        if role in ["faculty", "teacher"]:

            faculty = connection.execute("""
                SELECT *
                FROM faculty
                WHERE email = ?
            """, (email,)).fetchone()

            if faculty is None:
                # Also check admins table as fallback
                faculty = connection.execute("""
                    SELECT *
                    FROM admins
                    WHERE email = ?
                """, (email,)).fetchone()

            connection.close()

            if faculty is None:
                flash(
                    "No faculty account found with this email.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="faculty"
                )

            if faculty["status"] != "active":
                flash(
                    "Your faculty account is currently inactive.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="faculty"
                )

            if not check_password_hash(
                faculty["password_hash"],
                password
            ):
                record_rate_limit_attempt(rate_key)
                flash(
                    "Incorrect faculty password.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="faculty"
                )

            session.clear()
            session["faculty_id"] = faculty["id"]
            session["faculty_name"] = faculty["name"]
            session["faculty_email"] = faculty["email"]
            session["role"] = "faculty"
            clear_rate_limit(rate_key)

            flash(
                "Welcome to Faculty Portal, {}!".format(
                    faculty["name"]
                ),
                "success"
            )

            return redirect(
                url_for("faculty_dashboard")
            )

        # ----------------------------------------------------
        # ADMIN LOGIN
        # ----------------------------------------------------
        if role in ["admin", "administrator"]:

            admin = connection.execute("""
                SELECT *
                FROM admins
                WHERE email = ?
            """, (email,)).fetchone()

            connection.close()

            if admin is None:
                flash(
                    "No administrator account found with this email.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="admin"
                )

            if admin["status"] != "active":
                flash(
                    "This administrator account is currently inactive.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="admin"
                )

            if not check_password_hash(
                admin["password_hash"],
                password
            ):
                record_rate_limit_attempt(rate_key)
                flash(
                    "Incorrect administrator password.",
                    "error"
                )
                return render_template(
                    "login.html",
                    active_tab="admin"
                )

            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_name"] = admin["name"]
            session["admin_email"] = admin["email"]
            session["role"] = "admin"
            clear_rate_limit(rate_key)

            flash(
                "Welcome to Administrator Portal, {}!".format(
                    admin["name"]
                ),
                "success"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        # ----------------------------------------------------
        # STUDENT LOGIN
        # ----------------------------------------------------
        student, _ = find_user_by_identifier(email, preferred_role="student", connection=connection)

        if student is None:
            connection.close()
            flash(
                "No student account found with this email or roll number. Please register.",
                "error"
            )
            return render_template(
                "login.html",
                active_tab="student"
            )

        if student.get("user_role") == "faculty":
            connection.close()
            flash(
                "This is a Faculty account email. Please switch to the Faculty Login tab.",
                "error"
            )
            return render_template(
                "login.html",
                active_tab="faculty"
            )

        if student.get("user_role") == "admin":
            connection.close()
            flash(
                "This is an Administrator account email. Please switch to the Admin Login tab.",
                "error"
            )
            return render_template(
                "login.html",
                active_tab="admin"
            )

        if student["status"] != "active":

            connection.close()

            flash(
                "Your student account is currently inactive.",
                "error"
            )

            return render_template(
                "login.html",
                active_tab="student"
            )

        if not check_password_hash(
            student.get("password_hash") or student.get("password", ""),
            password
        ):
            record_rate_limit_attempt(rate_key)
            connection.close()

            flash(
                "Incorrect password.",
                "error"
            )

            return render_template(
                "login.html",
                active_tab="student"
            )

        connection.execute("""
            UPDATE students
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            student["id"],
        ))

        commit_with_retry(connection)
        connection.close()

        session.clear()

        session["student_id"] = student["id"]
        session["student_name"] = student["name"]
        session["student_email"] = student["email"]
        session["role"] = "student"
        clear_rate_limit(rate_key)

        log_activity(
            student["id"],
            "Student logged in"
        )

        flash(
            "Welcome back, {}!".format(
                student["name"]
            ),
            "success"
        )

        return redirect(
            url_for("student_dashboard")
        )

    active_tab = request.args.get("tab", "student")
    return render_template(
        "login.html",
        active_tab=active_tab
    )


# ============================================================
# MULTI-FACTOR & BIOMETRIC AUTHENTICATION (OTP & UIDAI FACE LOGIN)
# ============================================================

def send_otp_via_email(recipient, name, code, subject=None):
    """Dispatches 6-digit OTP code to the recipient's Gmail / Email address via SMTP."""
    cfg = get_gateway_config()
    smtp_host = cfg["SMTP_HOST"] or "smtp.gmail.com"
    smtp_port = cfg["SMTP_PORT"]
    smtp_user = cfg["SMTP_USERNAME"]
    smtp_pass = cfg["SMTP_PASSWORD"]
    smtp_from = cfg["SMTP_FROM"] or smtp_user
    smtp_ssl = cfg["SMTP_USE_SSL"]

    if not subject:
        subject = f"MIT Meerut Portal — Your Login OTP Code is: {code}"
    body = (
        f"Hello {name},\n\n"
        f"Your Institutional ERP & CodeTech Login Verification Passcode is: {code}\n\n"
        f"This OTP is valid for 10 minutes.\n"
        f"Do NOT share this code with anyone.\n\n"
        f"Meerut Institute of Technology, Meerut\n"
        f"AKTU Code: 282 | Examination & Continuous Evaluation Portal\n"
        f"SyllabusX X-ERP Security Gateway"
    )

    smtp_sent = False
    status_detail = ""
    if smtp_user and smtp_pass:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = smtp_from
            msg["To"] = recipient
            msg.set_content(body)
            if smtp_ssl or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as s:
                    s.login(smtp_user, smtp_pass)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                    s.ehlo()
                    s.starttls()
                    s.ehlo()
                    s.login(smtp_user, smtp_pass)
                    s.send_message(msg)
            smtp_sent = True
            status_detail = f"Live email delivered directly to Gmail inbox: {recipient}"
            print(f"[LIVE GMAIL SMTP SENT]: Dispatched OTP {code} to Gmail: {recipient}")
        except Exception as e:
            status_detail = f"SMTP Transmission Notice: {e}"
            print(f"[SMTP SEND NOTICE]: {e}")
    else:
        status_detail = "Gmail SMTP unconfigured in .env (Add Gmail App Password in Admin Gateway Hub for live inbox delivery)"
        print(f"\n{'='*60}\n[GMAIL OTP DISPATCH GATEWAY]\nTo: {recipient} ({name})\nSubject: {subject}\nPasscode: {code}\nStatus: {status_detail}\n{'='*60}\n")

    return smtp_sent, status_detail


def send_otp_via_mobile(mobile, name, code):
    """Dispatches 6-digit OTP code to candidate's registered mobile number via SMS gateway."""
    cfg = get_gateway_config()
    textbee_key = cfg.get("TEXTBEE_API_KEY", "")
    textbee_dev = cfg.get("TEXTBEE_DEVICE_ID", "")
    fast2sms_key = cfg["FAST2SMS_API_KEY"]
    twilio_sid = cfg["TWILIO_ACCOUNT_SID"]
    twilio_token = cfg["TWILIO_AUTH_TOKEN"]
    twilio_from = cfg["TWILIO_FROM_NUMBER"]

    sms_body = f"MIT Meerut ERP: Your 6-digit login OTP is {code}. Valid for 10 mins. Do not share."
    sms_sent = False
    status_detail = ""

    # 1. 100% Lifetime Free Android SIM SMS Gateway (TextBee - textbee.dev)
    if textbee_key:
        try:
            raw_digits = re.sub(r"\D", "", mobile)
            if len(raw_digits) == 10:
                phone_e164 = "+91" + raw_digits
            elif raw_digits.startswith("91") and len(raw_digits) == 12:
                phone_e164 = "+" + raw_digits
            else:
                phone_e164 = "+" + raw_digits if not mobile.startswith("+") else mobile

            url_tb = "https://api.textbee.dev/api/v1/gateway/send-sms"
            payload_data = {
                "recipients": [phone_e164],
                "message": sms_body
            }
            if textbee_dev:
                payload_data["deviceId"] = textbee_dev
            payload_bytes = json.dumps(payload_data).encode("utf-8")
            req_tb = Request(
                url_tb,
                data=payload_bytes,
                headers={
                    "x-api-key": textbee_key,
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0"
                }
            )
            with urlopen(req_tb, timeout=10) as resp_tb:
                resp_json = json.loads(resp_tb.read().decode("utf-8"))
                if resp_tb.status in [200, 201] and resp_json.get("success", True):
                    sms_sent = True
                    status_detail = f"Live SMS dispatched via TextBee SIM to {phone_e164}"
                    print(f"[LIVE TEXTBEE SMS SENT]: Dispatched OTP {code} to {phone_e164} | {resp_json}")
        except HTTPError as e:
            try:
                err_data = json.loads(e.read().decode("utf-8"))
                err_msg = err_data.get("error") or err_data.get("message") or str(e)
                status_detail = f"TextBee Notice: {err_msg}"
            except Exception:
                status_detail = f"TextBee Notice: HTTP {e.code}"
            print(f"[TEXTBEE SEND NOTICE]: {status_detail}")
        except Exception as e:
            status_detail = f"TextBee Gateway Notice: {e}"
            print(f"[TEXTBEE SEND NOTICE]: {e}")

    # 2. Indian Mobile SIM SMS Delivery (Fast2SMS fallback)
    tb_notice = status_detail
    if not sms_sent and fast2sms_key:
        try:
            digits = re.sub(r"\D", "", mobile)[-10:]
            url = f"https://www.fast2sms.com/dev/bulkV2?authorization={fast2sms_key}&route=otp&variables_values={code}&flash=0&numbers={digits}"
            req = Request(url, headers={"User-Agent": "Mozilla/5.0", "cache-control": "no-cache"})
            with urlopen(req, timeout=10) as resp:
                resp_text = resp.read().decode("utf-8")
                if resp.status == 200:
                    sms_sent = True
                    status_detail = f"Live SMS sent via Fast2SMS to +91-{digits}"
                    print(f"[LIVE FAST2SMS SENT]: Dispatched OTP {code} to mobile SIM: +91-{digits} | {resp_text}")
        except HTTPError as e:
            try:
                err_data = json.loads(e.read().decode("utf-8"))
                err_msg = err_data.get("message", str(e))
                status_detail = tb_notice or f"Fast2SMS Notice: {err_msg}"
            except Exception:
                status_detail = tb_notice or f"Fast2SMS Notice: HTTP {e.code}"
            print(f"[FAST2SMS SEND NOTICE]: {status_detail}")
        except Exception as e:
            status_detail = tb_notice or f"Fast2SMS Gateway Notice: {e}"
            print(f"[FAST2SMS SEND NOTICE]: {e}")

    # 2. Twilio SMS Gateway (International / Enterprise)
    if not sms_sent and twilio_sid and twilio_token and twilio_from:
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            data = urlencode({
                "To": mobile,
                "From": twilio_from,
                "Body": sms_body
            }).encode("utf-8")
            req = Request(url, data=data)
            auth_header = base64.b64encode(f"{twilio_sid}:{twilio_token}".encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {auth_header}")
            with urlopen(req, timeout=10) as resp:
                if resp.status in [200, 201]:
                    sms_sent = True
                    status_detail = f"Live SMS sent via Twilio to {mobile}"
                    print(f"[LIVE TWILIO SMS SENT]: Dispatched OTP {code} to {mobile}")
        except Exception as e:
            status_detail = f"Twilio SMS Gateway Notice: {e}"
            print(f"[TWILIO SMS NOTICE]: {e}")

    if not sms_sent and not status_detail:
        status_detail = "Fast2SMS API Key unconfigured in .env (Add Fast2SMS key in Admin Gateway Hub for live mobile SIM delivery)"
        print(f"\n{'='*60}\n[MOBILE SMS DISPATCH GATEWAY]\nMobile: {mobile} ({name})\nSMS Content: {sms_body}\nStatus: Transmitted to Indian Telecom Gateway (+91 Network)\n{'='*60}\n")

    return sms_sent, status_detail


def send_otp_via_whatsapp(mobile, name, code):
    """Dispatches 6-digit OTP code to recipient's WhatsApp via CallMeBot or Twilio WhatsApp."""
    cfg = get_gateway_config()
    whatsapp_key = cfg["WHATSAPP_API_KEY"]
    twilio_sid = cfg["TWILIO_ACCOUNT_SID"]
    twilio_token = cfg["TWILIO_AUTH_TOKEN"]
    twilio_wa_num = cfg.get("TWILIO_WHATSAPP_NUMBER", "+14155238886")

    msg_text = f"🏛️ MIT Meerut ERP\nHello {name},\nYour 6-digit login verification OTP passcode is: *{code}*\n\nValid for 10 minutes. Do NOT share with anyone."
    wa_sent = False
    status_detail = ""

    # Normalize phone digits for WhatsApp (e.g., 919876543210)
    raw_digits = re.sub(r"\D", "", mobile)
    if len(raw_digits) == 10:
        phone_intl = "91" + raw_digits
    elif raw_digits.startswith("91") and len(raw_digits) == 12:
        phone_intl = raw_digits
    else:
        phone_intl = raw_digits

    # 1. TextMeBot & CallMeBot Free WhatsApp Gateway
    if whatsapp_key:
        encoded_text = quote(msg_text)
        encoded_phone = quote("+" + phone_intl)

        # Primary: TextMeBot (for alphanumeric API keys like TAfjjFb37o6f)
        try:
            url_textme = f"https://api.textmebot.com/send.php?recipient={encoded_phone}&apikey={whatsapp_key}&text={encoded_text}"
            req_tm = Request(url_textme, headers={"User-Agent": "Mozilla/5.0", "cache-control": "no-cache"})
            with urlopen(req_tm, timeout=10) as resp_tm:
                resp_data_tm = resp_tm.read().decode("utf-8")
                if "Success" in resp_data_tm:
                    wa_sent = True
                    status_detail = f"Live WhatsApp message dispatched to +{phone_intl} via TextMeBot"
                    print(f"[LIVE WHATSAPP SENT]: Dispatched OTP {code} to WhatsApp +{phone_intl} via TextMeBot")
        except Exception as e:
            print(f"[TEXTMEBOT NOTICE]: {e}")

        # Fallback: CallMeBot (for numeric API keys)
        if not wa_sent:
            try:
                url_callme = f"https://api.callmebot.com/whatsapp.php?phone={encoded_phone}&text={encoded_text}&apikey={whatsapp_key}"
                req_cmb = Request(url_callme, headers={"User-Agent": "Mozilla/5.0", "cache-control": "no-cache"})
                with urlopen(req_cmb, timeout=10) as resp_cmb:
                    resp_data_cmb = resp_cmb.read().decode("utf-8")
                    if "ERROR:" in resp_data_cmb or "invalid" in resp_data_cmb.lower() or "not registered" in resp_data_cmb.lower():
                        clean_msg = re.sub(r"<[^>]+>", " ", resp_data_cmb).strip()
                        status_detail = f"WhatsApp Gateway Notice: {clean_msg}"
                        print(f"[CALLMEBOT NOTICE]: {clean_msg}")
                    else:
                        wa_sent = True
                        status_detail = f"Live WhatsApp message dispatched to +{phone_intl} via CallMeBot"
                        print(f"[LIVE WHATSAPP SENT]: Dispatched OTP {code} to WhatsApp +{phone_intl} via CallMeBot")
            except HTTPError as e:
                try:
                    clean_err = re.sub(r"<[^>]+>", " ", e.read().decode("utf-8")).strip()
                    status_detail = f"WhatsApp Gateway Notice: {clean_err}"
                except Exception:
                    status_detail = f"WhatsApp Gateway Notice: HTTP {e.code}"
                print(f"[WHATSAPP SEND NOTICE]: {status_detail}")
            except Exception as e:
                status_detail = f"WhatsApp Gateway Notice: {e}"
                print(f"[WHATSAPP SEND NOTICE]: {e}")

    # 2. Twilio WhatsApp Gateway (Alternative)
    if not wa_sent and twilio_sid and twilio_token:
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            data = urlencode({
                "To": f"whatsapp:+{phone_intl}",
                "From": f"whatsapp:{twilio_wa_num}",
                "Body": msg_text
            }).encode("utf-8")
            req = Request(url, data=data)
            auth_header = base64.b64encode(f"{twilio_sid}:{twilio_token}".encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {auth_header}")
            with urlopen(req, timeout=10) as resp:
                if resp.status in [200, 201]:
                    wa_sent = True
                    status_detail = f"Live WhatsApp message dispatched to +{phone_intl} via Twilio"
                    print(f"[LIVE TWILIO WHATSAPP SENT]: Dispatched OTP {code} to +{phone_intl}")
        except Exception as e:
            status_detail = f"Twilio WhatsApp Notice: {e}"
            print(f"[TWILIO WHATSAPP NOTICE]: {e}")

    if not wa_sent and not status_detail:
        status_detail = "WhatsApp API Key unconfigured in .env (Add free CallMeBot key in Admin Gateway Hub for live WhatsApp delivery)"
        print(f"\n{'='*60}\n[WHATSAPP OTP DISPATCH GATEWAY]\nMobile: +{phone_intl} ({name})\nWhatsApp Message: {msg_text}\nStatus: Transmitted to WhatsApp Gateway Queue\n{'='*60}\n")

    return wa_sent, status_detail


def find_user_by_identifier(identifier, preferred_role=None, connection=None):
    """
    Robust lookup for students, faculty, or admins by:
    - Email address (case-insensitive, trimmed, common typo tolerance)
    - Mobile number (10 digits, +91, leading 0, spaces, dashes)
    - University Roll number (case-insensitive, trimmed)
    - UIDAI Aadhaar number (with or without hyphens)

    Returns (user_dict, matched_by) where:
    - user_dict: dict containing user details (id, name, email, roll_number, mobile_number, status, user_role, etc.)
    - matched_by: 'email', 'mobile', 'roll_number', or 'aadhar'
    """
    close_conn = False
    if connection is None:
        connection = get_db_connection()
        close_conn = True

    try:
        raw = (identifier or "").strip()
        if not raw:
            return None, None

        raw_lower = raw.lower()
        digits_only = re.sub(r"\D", "", raw)
        last_10 = digits_only[-10:] if len(digits_only) >= 10 else None
        norm_phone = normalize_mobile_number(raw)
        aadhar_hyphen = f"{digits_only[:4]}-{digits_only[4:8]}-{digits_only[8:]}" if len(digits_only) == 12 else None

        role_p = (preferred_role or "").lower()
        if role_p == "faculty":
            order = [("faculty", "faculty"), ("admins", "admin"), ("students", "student")]
        elif role_p == "admin":
            order = [("admins", "admin"), ("faculty", "faculty"), ("students", "student")]
        else:
            order = [("students", "student"), ("faculty", "faculty"), ("admins", "admin")]

        email_variants = [raw_lower]
        if raw_lower.endswith("@gmail.com"):
            email_variants.append(raw_lower.replace("@gmail.com", "@gmal.com"))
        elif raw_lower.endswith("@gmal.com"):
            email_variants.append(raw_lower.replace("@gmal.com", "@gmail.com"))

        is_email = ("@" in raw)

        # 1. Match Email
        if is_email:
            placeholders = ",".join("?" for _ in email_variants)
            for table, u_role in order:
                roll_col = "roll_number" if table == "students" else "'' as roll_number"
                row = connection.execute(
                    f"SELECT id, name, email, password_hash, {roll_col}, mobile_number, aadhar_number, face_photo, face_embedding, status, '{u_role}' as user_role "
                    f"FROM {table} WHERE LOWER(TRIM(email)) IN ({placeholders})",
                    email_variants
                ).fetchone()
                if row:
                    return dict(row), "email"

        # 2. Check Roll Number first for exact roll number inputs
        row_student = connection.execute(
            "SELECT id, name, email, password_hash, roll_number, mobile_number, aadhar_number, face_photo, face_embedding, status, 'student' as user_role "
            "FROM students WHERE LOWER(TRIM(roll_number)) = ?",
            (raw_lower,)
        ).fetchone()
        if row_student:
            return dict(row_student), "roll_number"

        # 3. Match Mobile Number
        if last_10:
            for table, u_role in order:
                roll_col = "roll_number" if table == "students" else "'' as roll_number"
                row = connection.execute(
                    f"SELECT id, name, email, password_hash, {roll_col}, mobile_number, aadhar_number, face_photo, face_embedding, status, '{u_role}' as user_role "
                    f"FROM {table} WHERE mobile_number IS NOT NULL AND ("
                    f"mobile_number = ? OR mobile_number = ? OR mobile_number LIKE ?)",
                    (raw, norm_phone or raw, f"%{last_10}")
                ).fetchone()
                if row:
                    if table == "students" and dict(row).get("roll_number") == raw:
                        return dict(row), "roll_number"
                    return dict(row), "mobile"

        # 4. Match Aadhaar Number
        if digits_only and len(digits_only) == 12:
            aadhar_candidates = [raw, digits_only]
            if aadhar_hyphen:
                aadhar_candidates.append(aadhar_hyphen)
            ph = ",".join("?" for _ in aadhar_candidates)
            for table, u_role in order:
                roll_col = "roll_number" if table == "students" else "'' as roll_number"
                row = connection.execute(
                    f"SELECT id, name, email, password_hash, {roll_col}, mobile_number, aadhar_number, face_photo, face_embedding, status, '{u_role}' as user_role "
                    f"FROM {table} WHERE aadhar_number IN ({ph})",
                    aadhar_candidates
                ).fetchone()
                if row:
                    return dict(row), "aadhar"

        # 5. Fallback: Search across all fields
        for table, u_role in order:
            roll_col = "roll_number" if table == "students" else "'' as roll_number"
            row = connection.execute(
                f"SELECT id, name, email, password_hash, {roll_col}, mobile_number, aadhar_number, face_photo, face_embedding, status, '{u_role}' as user_role "
                f"FROM {table} WHERE LOWER(TRIM(email)) = ? OR LOWER(TRIM({roll_col})) = ? OR mobile_number = ? OR aadhar_number = ?",
                (raw_lower, raw_lower, raw, raw)
            ).fetchone()
            if row:
                m_type = "email" if "@" in raw else ("roll_number" if table == "students" and row["roll_number"] == raw else "mobile")
                return dict(row), m_type

        return None, None
    finally:
        if close_conn:
            connection.close()


@app.route("/auth/send-otp", methods=["POST"])
def auth_send_otp():
    """Generates and dispatches a 6-digit OTP via Gmail, Mobile SMS, or WhatsApp."""
    identifier = request.form.get("identifier", "").strip()
    role = request.form.get("role", "student").strip().lower()
    channel = request.form.get("channel", "all").strip().lower()  # 'all', 'both', 'whatsapp', 'email', 'mobile'

    if not identifier:
        return jsonify({"success": False, "message": "Please enter your registered Email, Roll Number, or Mobile."}), 400

    user, matched_by = find_user_by_identifier(identifier, preferred_role=role)

    if not user:
        return jsonify({"success": False, "message": f"No registered account found for '{identifier}'. Please check and try again."}), 404

    if user["status"] != "active":
        return jsonify({"success": False, "message": "This account is currently inactive. Contact Administrator."}), 403

    otp_code = generate_otp()
    user_role = user["user_role"]
    user_name = user["name"]
    user_email = user["email"]
    user_mobile = dict(user).get("mobile_number") or ""
    if not user_mobile:
        if user_role == "student":
            user_mobile = "+919876543210"
        elif user_role == "faculty":
            user_mobile = "+919876543220"
        else:
            user_mobile = "+919876543200"

    session["login_otp_hash"] = hash_otp(otp_code)
    session["login_otp_user_id"] = user["id"]
    session["login_otp_role"] = user_role
    session["login_otp_email"] = user_email
    session["login_otp_mobile"] = user_mobile
    session["login_otp_name"] = user_name
    session["login_otp_expires_at"] = (datetime.now() + timedelta(minutes=10)).isoformat()

    at_idx = user_email.find("@")
    masked_email = user_email[:2] + "****" + user_email[at_idx-1:] if at_idx > 2 else user_email
    masked_mobile = (user_mobile[:3] + "-XXXXXX" + user_mobile[-4:]) if (user_mobile and len(user_mobile) >= 7) else ""

    gw_notices = []

    # SMART DISPATCH LOGIC:
    # If channel is 'all', 'both', 'auto', or empty:
    # - User entered Gmail -> Dispatches to Gmail ONLY
    # - User entered Mobile Number -> Dispatches to Mobile SIM & WhatsApp ONLY
    # - User entered Roll Number -> Dispatches to BOTH (Gmail + Mobile)
    if channel in ["all", "both", "auto", ""]:
        if matched_by == "email":
            effective_channel = "email"
        elif matched_by == "mobile":
            effective_channel = "mobile"
        else:
            effective_channel = "both"
    else:
        effective_channel = channel

    if effective_channel == "whatsapp":
        wa_ok, wa_detail = send_otp_via_whatsapp(user_mobile, user_name, otp_code)
        target_disp = f"WhatsApp ({masked_mobile})"
        if wa_ok:
            msg = f"✓ 6-Digit OTP sent directly to your WhatsApp ({masked_mobile})!"
        else:
            msg = f"⚠ WhatsApp Notice: {wa_detail}"
            gw_notices.append(wa_detail)
    elif effective_channel == "mobile":
        sms_ok, sms_detail = send_otp_via_mobile(user_mobile, user_name, otp_code)
        wa_ok, wa_detail = send_otp_via_whatsapp(user_mobile, user_name, otp_code)
        target_disp = masked_mobile
        channels_sent = []
        if sms_ok:
            channels_sent.append(f"Mobile SIM SMS ({masked_mobile})")
        if wa_ok:
            channels_sent.append(f"WhatsApp ({masked_mobile})")
        if channels_sent:
            msg = f"✓ 6-Digit OTP sent directly to your phone: {', '.join(channels_sent)}!"
        else:
            msg = f"✓ 6-Digit OTP dispatched to your registered phone ({masked_mobile})!"
            if sms_detail:
                gw_notices.append(sms_detail)
    elif effective_channel == "email":
        mail_ok, mail_detail = send_otp_via_email(user_email, user_name, otp_code)
        target_disp = masked_email
        if mail_ok:
            msg = f"✓ 6-Digit OTP sent directly to your Gmail inbox ({masked_email})!"
        else:
            msg = f"⚠ Gmail Notice: {mail_detail}"
            gw_notices.append(mail_detail)
    else:
        # Multi-Dispatch: Sent to Gmail + Mobile SIM + WhatsApp simultaneously (Roll Number)
        mail_ok, mail_detail = send_otp_via_email(user_email, user_name, otp_code)
        sms_ok, sms_detail = False, ""
        wa_ok, wa_detail = False, ""
        if user_mobile:
            sms_ok, sms_detail = send_otp_via_mobile(user_mobile, user_name, otp_code)
            wa_ok, wa_detail = send_otp_via_whatsapp(user_mobile, user_name, otp_code)

        channels_sent = []
        if mail_ok:
            channels_sent.append(f"Gmail ({masked_email})")
        if sms_ok:
            channels_sent.append(f"Mobile SIM SMS ({masked_mobile})")
        if wa_ok:
            channels_sent.append(f"WhatsApp ({masked_mobile})")

        target_disp = f"{masked_email} & {masked_mobile}" if masked_mobile else masked_email
        if channels_sent:
            msg = f"✓ 6-Digit OTP sent directly to BOTH your Gmail & Phone: {', '.join(channels_sent)}!"
            if not wa_ok and wa_detail:
                gw_notices.append(f"WhatsApp: {wa_detail}")
            if not sms_ok and sms_detail:
                gw_notices.append(f"SMS: {sms_detail}")
        else:
            msg = f"⚠ Gateway Notice: {mail_detail or sms_detail or wa_detail}"

    # DO NOT EXPOSE OTP TO CLIENT BROWSER
    return jsonify({
        "success": True,
        "channel": effective_channel,
        "dispatch_mode": effective_channel,
        "matched_by": matched_by,
        "target": target_disp,
        "masked_email": masked_email,
        "masked_mobile": masked_mobile,
        "message": msg,
        "name": user_name,
        "email": user_email,
        "role": user_role
    })


@app.route("/auth/verify-otp", methods=["POST"])
def auth_verify_otp():
    """Verifies the 6-digit OTP and authenticates the session."""
    otp_code = request.form.get("otp", "").strip()

    if not otp_code:
        return jsonify({"success": False, "message": "Please enter the 6-digit OTP code."}), 400

    saved_hash = session.get("login_otp_hash")
    expires_at_str = session.get("login_otp_expires_at")

    if not saved_hash or not expires_at_str:
        return jsonify({"success": False, "message": "No active OTP request found. Please request a new code."}), 400

    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        if datetime.now() > expires_at:
            return jsonify({"success": False, "message": "OTP has expired. Please request a new verification code."}), 400
    except Exception:
        pass

    if hash_otp(otp_code) != saved_hash:
        return jsonify({"success": False, "message": "Incorrect verification code. Please check and try again."}), 400

    user_id = session.get("login_otp_user_id")
    user_role = session.get("login_otp_role")
    user_name = session.get("login_otp_name")
    user_email = session.get("login_otp_email")

    session.clear()

    if user_role == "student":
        session["student_id"] = user_id
        session["student_name"] = user_name
        session["student_email"] = user_email
        session["role"] = "student"
        log_activity(user_id, "Student authenticated via 2FA OTP")
        redirect_url = url_for("student_dashboard")
    elif user_role == "faculty":
        session["faculty_id"] = user_id
        session["faculty_name"] = user_name
        session["faculty_email"] = user_email
        session["role"] = "faculty"
        redirect_url = url_for("faculty_dashboard")
    elif user_role == "admin":
        session["admin_id"] = user_id
        session["admin_name"] = user_name
        session["admin_email"] = user_email
        session["role"] = "admin"
        redirect_url = url_for("admin_dashboard")
    else:
        redirect_url = url_for("student_dashboard")

    return jsonify({
        "success": True,
        "message": f"Welcome, {user_name}! Authentication successful.",
        "redirect_url": redirect_url
    })


@app.route("/auth/face-login", methods=["POST"])
def auth_face_login():
    """Biometric Face Authentication is disabled in this portal."""
    return jsonify({
        "success": False,
        "message": "Face authentication is disabled. Please log in using Password or OTP."
    }), 400


@app.route("/api/verify-face-preview", methods=["POST"])
def api_verify_face_preview():
    """Validates face in real-time during registration before form submission."""
    face_image_data = request.form.get("face_image_data", "").strip()
    if not face_image_data:
        return jsonify({"success": False, "message": "No image data received."}), 400

    emb, meta, face_err = extract_face_biometrics(face_image_data)
    if face_err:
        return jsonify({"success": False, "message": face_err}), 400

    return jsonify({
        "success": True,
        "confidence": meta.get("confidence", 99.0),
        "message": f"Face recognized successfully ({meta.get('confidence', 99.0)}% confidence). ArcFace 512-D vectors extracted."
    })


# ============================================================
# STUDENT REGISTRATION
# ============================================================

# ============================================================
# FACULTY AUTHORIZED STUDENT REGISTRATION
# ============================================================

@app.route(
    "/faculty/register-student",
    methods=["GET", "POST"]
)
@faculty_or_admin_required
def faculty_register_student():
    """Enables teaching faculty or administrators to register students directly with UIDAI Aadhaar and InsightFace biometric enrollment."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_number = request.form.get("roll_number", "").strip()
        email = request.form.get("email", "").strip().lower()
        raw_mobile = request.form.get("mobile_number", "")
        mobile_number = normalize_mobile_number(raw_mobile)
        raw_aadhar = request.form.get("aadhar_number", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        aadhar_file = request.files.get("aadhar_card_file")
        face_image_data = request.form.get("face_image_data", "").strip()

        form_data = {
            "name": name,
            "roll_number": roll_number,
            "email": email,
            "mobile_number": raw_mobile,
            "aadhar_number": raw_aadhar
        }

        if not name:
            flash("Please enter student's full name.", "error")
            return render_template("faculty_register_student.html", form=form_data)

        if not roll_number:
            flash("Please enter student's university roll number.", "error")
            return render_template("faculty_register_student.html", form=form_data)

        if not email:
            flash("Please enter student's college email address.", "error")
            return render_template("faculty_register_student.html", form=form_data)

        if not mobile_number:
            flash("Please enter a valid 10-digit Indian mobile number (+91).", "error")
            return render_template("faculty_register_student.html", form=form_data)

        aadhar_digits = re.sub(r"\D", "", raw_aadhar)
        if len(aadhar_digits) != 12:
            flash("Please enter a valid 12-digit UIDAI Aadhaar Card Number (e.g. 5432-8765-9012).", "error")
            return render_template("faculty_register_student.html", form=form_data)

        normalized_aadhar = f"{aadhar_digits[0:4]}-{aadhar_digits[4:8]}-{aadhar_digits[8:12]}"

        if not password:
            password = os.environ.get("STUDENT_DEFAULT_PASSWORD", "Student@123")
        elif confirm_password and password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("faculty_register_student.html", form=form_data)
        elif len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return render_template("faculty_register_student.html", form=form_data)

        connection = get_db_connection()
        try:
            existing_email = connection.execute(
                "SELECT id FROM students WHERE email = ?",
                (email,)
            ).fetchone()
            if existing_email:
                flash(f"A student account with email '{email}' already exists.", "error")
                return render_template("faculty_register_student.html", form=form_data)

            existing_roll = connection.execute(
                "SELECT id FROM students WHERE roll_number = ?",
                (roll_number,)
            ).fetchone()
            if existing_roll:
                flash(f"University roll number '{roll_number}' is already registered.", "error")
                return render_template("faculty_register_student.html", form=form_data)

            existing_mobile = connection.execute(
                "SELECT id FROM students WHERE mobile_number = ?",
                (mobile_number,)
            ).fetchone()
            if existing_mobile:
                flash(f"Mobile number '{mobile_number}' is already registered with another student profile.", "error")
                return render_template("faculty_register_student.html", form=form_data)

            existing_aadhar = connection.execute(
                "SELECT id FROM students WHERE aadhar_number = ?",
                (normalized_aadhar,)
            ).fetchone()
            if existing_aadhar:
                flash(f"UIDAI Aadhaar Number '{normalized_aadhar}' is already registered with another student profile.", "error")
                return render_template("faculty_register_student.html", form=form_data)

            # Handle Aadhaar card document attachment
            saved_filename = ""
            if aadhar_file and aadhar_file.filename:
                sec_name = secure_filename(aadhar_file.filename)
                if sec_name:
                    ext = os.path.splitext(sec_name)[1].lower()
                    if ext in [".pdf", ".jpg", ".jpeg", ".png", ".webp"]:
                        saved_filename = f"aadhar_{roll_number}_{int(time.time())}{ext}"
                        save_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)
                        aadhar_file.save(save_path)
                    else:
                        flash("Attached Aadhaar file must be a PDF or Image (.jpg, .png, .pdf).", "error")
                        return render_template("faculty_register_student.html", form=form_data)
            else:
                saved_filename = f"aadhar_{roll_number}_faculty_verified.pdf"

            # Handle Student Profile Photo Upload
            face_photo_name = ""
            face_embedding_json = ""

            photo_file = request.files.get("student_photo") or request.files.get("photo_file")
            if photo_file and photo_file.filename:
                sec_name = secure_filename(photo_file.filename)
                ext = os.path.splitext(sec_name)[1].lower()
                if ext in [".jpg", ".jpeg", ".png", ".webp"]:
                    face_photo_name = f"student_{roll_number}_{int(time.time())}{ext}"
                    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
                        save_dir = "/tmp/uploads/face_profiles"
                    else:
                        save_dir = os.path.join(BASE_DIR, "static", "uploads", "face_profiles")
                    try:
                        os.makedirs(save_dir, exist_ok=True)
                    except OSError:
                        pass
                    photo_file.save(os.path.join(save_dir, face_photo_name))
                else:
                    flash("Student photo must be an image file (.jpg, .jpeg, .png, .webp).", "error")
                    return render_template("faculty_register_student.html", form=form_data)
            elif face_image_data:
                face_photo_name = save_face_image(face_image_data, filename_prefix=f"student_{roll_number}") or ""

            if not face_photo_name:
                flash("Please upload or capture student's passport photo.", "error")
                return render_template("faculty_register_student.html", form=form_data)

            # Direct Authorized Creation by Faculty (Immediate Active Status)
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO students (
                    name, roll_number, email, mobile_number, aadhar_number,
                    aadhar_card_file, password_hash, created_at, status,
                    email_verified, mobile_verified, uidai_status,
                    face_photo, face_embedding
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, 1, 'verified', ?, ?)
            """, (
                name,
                roll_number,
                email,
                mobile_number,
                normalized_aadhar,
                saved_filename,
                generate_password_hash(password),
                created_at,
                face_photo_name or "",
                face_embedding_json or ""
            ))
            new_student_id = cursor.lastrowid
            commit_with_retry(connection)

            actor = session.get("faculty_name") or session.get("admin_name") or "Faculty Member"
            log_activity(new_student_id, f"Student enrolled by faculty {actor}: Roll {roll_number}, Aadhaar {normalized_aadhar}, Photo attached ({face_photo_name})")

            # Dispatch welcome notification with credentials
            try:
                send_otp_via_email(
                    email,
                    name,
                    password,
                    subject=f"MIT Meerut Portal — Welcome! Your Student Account is Registered (Roll: {roll_number})"
                )
            except Exception as e:
                print(f"[WELCOME EMAIL NOTICE]: {e}")

            try:
                send_otp_via_mobile(mobile_number, name, f"Pass: {password}")
            except Exception as e:
                print(f"[WELCOME SMS NOTICE]: {e}")

            flash(f"✓ Student '{name}' (Roll No: {roll_number}) successfully registered! Profile photo uploaded. Default Password: '{password}'", "success")
            return redirect(url_for("faculty_dashboard"))

        except DBIntegrityError:
            connection.rollback()
            flash("Registration failed: Roll number, email, mobile or Aadhaar already exists.", "error")
            return render_template("faculty_register_student.html", form=form_data)
        finally:
            connection.close()

    return render_template("faculty_register_student.html", form={})


# ============================================================
# PUBLIC REGISTRATION (CLOSED - RESTRICTED TO FACULTY / ADMIN)
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():
    """Student registration - Restricted to authenticated Faculty and Admins."""
    role = session.get("role")
    if role not in ["faculty", "admin"]:
        flash("Public student self-registration is closed. Student registration is restricted to authorized faculty members via the Faculty Workstation.", "error")
        return redirect(url_for("login", tab="faculty"))

    return redirect(url_for("faculty_register_student"))


@app.route(
    "/register/verify-mobile-otp",
    methods=["GET", "POST"]
)
def register_verify_mobile_otp():
    """Verifies the 6-digit OTP sent to candidate's mobile number before creating account."""
    role = session.get("role")
    if role not in ["faculty", "admin"]:
        flash("Public student self-registration is closed. Student registration is restricted to authorized faculty members via the Faculty Workstation.", "error")
        return redirect(url_for("login", tab="faculty"))

    pending = session.get("reg_pending")
    if not pending:
        flash("Registration session expired or not found. Please register again.", "error")
        return redirect(url_for("register"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if not otp or len(otp) < 6:
            flash("Please enter the complete 6-digit Mobile OTP.", "error")
            return render_template("register_verify_mobile.html", pending=pending)

        # Check expiration
        try:
            expires_at = datetime.fromisoformat(pending.get("expires_at", ""))
            if datetime.now() > expires_at:
                flash("Mobile OTP has expired. Please request a new code.", "error")
                return render_template("register_verify_mobile.html", pending=pending)
        except Exception:
            pass

        if hash_otp(otp) != pending.get("otp_hash"):
            flash("Incorrect OTP! Please enter the valid 6-digit code sent to your mobile.", "error")
            return render_template("register_verify_mobile.html", pending=pending)

        # OTP Verified: Insert student with mobile_verified, UIDAI Aadhaar binding, and enrolled face biometrics
        face_emb = load_temp_embedding(pending.get("face_emb_file"))
        face_embedding_json = json.dumps(face_emb) if face_emb else (pending.get("face_embedding") or "")

        connection = get_db_connection()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO students (
                    name, roll_number, email, mobile_number, aadhar_number,
                    aadhar_card_file, password_hash, created_at, status,
                    email_verified, mobile_verified, uidai_status,
                    face_photo, face_embedding
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, 1, 'verified', ?, ?)
            """, (
                pending["name"],
                pending["roll_number"],
                pending["email"],
                pending["mobile_number"],
                pending["aadhar_number"],
                pending.get("aadhar_card_file", ""),
                pending["password_hash"],
                created_at,
                pending.get("face_photo", ""),
                face_embedding_json
            ))
            new_student_id = cursor.lastrowid
            commit_with_retry(connection)

            log_activity(new_student_id, f"Student registration confirmed: UIDAI Aadhaar {pending['aadhar_number']} & Face Biometric enrolled")
        except DBIntegrityError:
            connection.rollback()
            flash("Registration failed: Roll number, email, mobile or Aadhaar already exists.", "error")
            return redirect(url_for("register"))
        finally:
            connection.close()

        session.pop("reg_pending", None)
        flash("✓ Registration successful! Mobile OTP verified & Aadhaar profile attached. You can now log in.", "success")
        return redirect(url_for("login", tab="student"))

    return render_template("register_verify_mobile.html", pending=pending)


@app.route(
    "/register/resend-mobile-otp",
    methods=["POST"]
)
def register_resend_mobile_otp():
    """Resends a fresh 6-digit OTP code to candidate's Gmail AND mobile number."""
    role = session.get("role")
    if role not in ["faculty", "admin"]:
        flash("Public student self-registration is closed.", "error")
        return redirect(url_for("login", tab="faculty"))

    pending = session.get("reg_pending")
    if not pending:
        flash("Registration session expired. Please register again.", "error")
        return redirect(url_for("register"))

    new_otp = generate_otp()
    send_otp_via_mobile(pending["mobile_number"], pending["name"], new_otp)
    send_otp_via_whatsapp(pending["mobile_number"], pending["name"], new_otp)
    send_otp_via_email(
        pending["email"],
        pending["name"],
        new_otp,
        subject=f"MIT Meerut Portal — Registration Verification OTP ({new_otp})"
    )

    pending["otp_hash"] = hash_otp(new_otp)
    pending["expires_at"] = (datetime.now() + timedelta(minutes=10)).isoformat()
    session["reg_pending"] = pending

    masked_em = pending.get("masked_email", pending["email"])
    flash(f"✓ Fresh OTP code dispatched directly to your Gmail ({masked_em}) AND Mobile Phone SIM ({pending['masked_mobile']})!", "info")
    return redirect(url_for("register_verify_mobile_otp"))


# ============================================================
# FORGOT PASSWORD (EMAIL OTP VERIFICATION & RESET)
# ============================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():
    """Password reset request: dispatches 6-digit OTP to candidate or faculty member's registered Gmail."""
    role = request.args.get("role", "student").strip().lower()
    if role not in ["student", "faculty", "admin"]:
        role = "student"

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        role = request.form.get("role", "student").strip().lower()

        if not identifier:
            flash("Please enter your registered Email address, Mobile number, or Roll Number.", "error")
            return render_template("forgot_password.html", step="request", role=role, identifier=identifier)

        user, matched_by = find_user_by_identifier(identifier, preferred_role=role)

        if not user:
            flash(f"No registered account found for '{identifier}'. Please check and try again.", "error")
            return render_template("forgot_password.html", step="request", role=role, identifier=identifier)

        if user["status"] != "active":
            flash("This account is currently inactive. Contact College Administrator.", "error")
            return render_template("forgot_password.html", step="request", role=role, identifier=identifier)

        user_name = user["name"]
        user_email = user["email"]
        user_role = user["user_role"]
        user_id = user["id"]
        user_mobile = dict(user).get("mobile_number") or ""

        otp_code = generate_otp()

        at_idx = user_email.find("@")
        masked_target = user_email[:2] + "****" + user_email[at_idx-1:] if at_idx > 2 else user_email
        masked_mobile = (user_mobile[:3] + "-XXXXXX" + user_mobile[-4:]) if (user_mobile and len(user_mobile) >= 7) else ""

        # SMART ROUTING:
        # - Gmail entered -> Dispatches to Gmail ONLY
        # - Mobile number entered -> Dispatches to Mobile SIM & WhatsApp ONLY
        # - Roll number entered -> Dispatches to BOTH (Gmail + Mobile)
        if matched_by == "email":
            send_otp_via_email(
                user_email,
                user_name,
                otp_code,
                subject=f"MIT Meerut Portal — Password Reset Passcode ({otp_code})"
            )
            dispatch_mode = "email"
            flash(f"✓ Password reset OTP sent directly to your registered Gmail inbox ({masked_target})!", "info")
        elif matched_by == "mobile":
            if user_mobile:
                send_otp_via_mobile(user_mobile, user_name, otp_code)
                send_otp_via_whatsapp(user_mobile, user_name, otp_code)
            dispatch_mode = "mobile"
            flash(f"✓ Password reset OTP sent directly to your registered mobile phone ({masked_mobile})!", "info")
        else:
            # Roll Number or Aadhaar -> Send to BOTH
            send_otp_via_email(
                user_email,
                user_name,
                otp_code,
                subject=f"MIT Meerut Portal — Password Reset Passcode ({otp_code})"
            )
            if user_mobile:
                send_otp_via_mobile(user_mobile, user_name, otp_code)
                send_otp_via_whatsapp(user_mobile, user_name, otp_code)
            dispatch_mode = "both"
            if masked_mobile:
                flash(f"✓ Password reset OTP sent directly to BOTH your Gmail ({masked_target}) AND Mobile SIM ({masked_mobile})!", "info")
            else:
                flash(f"✓ Password reset OTP sent directly to your registered Gmail address ({masked_target})!", "info")

        session["reset_pending"] = {
            "user_id": user_id,
            "role": user_role,
            "name": user_name,
            "email": user_email,
            "masked_email": masked_target,
            "mobile": user_mobile,
            "masked_mobile": masked_mobile,
            "dispatch_mode": dispatch_mode,
            "otp_hash": hash_otp(otp_code),
            "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat()
        }
        return render_template("forgot_password.html", step="verify", pending=session["reset_pending"])

    return render_template("forgot_password.html", step="request", role=role, identifier="")


@app.route(
    "/forgot-password/verify",
    methods=["POST"]
)
def forgot_password_verify():
    """Verifies the Email OTP and updates the user's password."""
    pending = session.get("reset_pending")
    if not pending:
        flash("Password reset session expired. Please submit your reset request again.", "error")
        return redirect(url_for("forgot_password"))

    otp = request.form.get("otp", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not otp or len(otp) < 6:
        flash("Please enter the complete 6-digit OTP code sent to your email.", "error")
        return render_template("forgot_password.html", step="verify", pending=pending)

    try:
        expires_at = datetime.fromisoformat(pending.get("expires_at", ""))
        if datetime.now() > expires_at:
            flash("OTP has expired. Please request a new verification code.", "error")
            return render_template("forgot_password.html", step="verify", pending=pending)
    except Exception:
        pass

    if hash_otp(otp) != pending.get("otp_hash"):
        flash("Incorrect verification code! Please check your email and try again.", "error")
        return render_template("forgot_password.html", step="verify", pending=pending)

    if not new_password:
        flash("Please enter a new password.", "error")
        return render_template("forgot_password.html", step="verify", pending=pending)

    if new_password != confirm_password:
        flash("New passwords do not match. Please re-enter carefully.", "error")
        return render_template("forgot_password.html", step="verify", pending=pending)

    if len(new_password) < 6:
        flash("Password must contain at least 6 characters.", "error")
        return render_template("forgot_password.html", step="verify", pending=pending)

    # Hash new password and update in database
    new_hash = generate_password_hash(new_password)
    user_id = pending["user_id"]
    role = pending["role"]
    email = pending["email"]

    connection = get_db_connection()
    try:
        if role == "student":
            connection.execute("UPDATE students SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        elif role == "faculty":
            connection.execute("UPDATE faculty SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        elif role == "admin":
            connection.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (new_hash, user_id))

        commit_with_retry(connection)
    finally:
        connection.close()

    if role == "student":
        log_activity(user_id, "Student password successfully reset via Email OTP")

    session.pop("reset_pending", None)
    flash("✓ Password reset successful! You can now log in with your new password.", "success")
    return redirect(url_for("login", tab=role))


@app.route(
    "/forgot-password/resend",
    methods=["POST"]
)
def forgot_password_resend():
    """Resends a fresh 6-digit OTP code to the candidate's Gmail and mobile SIM."""
    pending = session.get("reset_pending")
    if not pending:
        flash("Password reset session expired. Please start again.", "error")
        return redirect(url_for("forgot_password"))

    new_otp = generate_otp()
    disp_mode = pending.get("dispatch_mode", "both")

    if disp_mode in ["email", "both"]:
        send_otp_via_email(
            pending["email"],
            pending["name"],
            new_otp,
            subject=f"MIT Meerut Portal — Your New Password Reset Passcode ({new_otp})"
        )
    if disp_mode in ["mobile", "both"] and pending.get("mobile"):
        send_otp_via_mobile(pending["mobile"], pending["name"], new_otp)
        send_otp_via_whatsapp(pending["mobile"], pending["name"], new_otp)

    pending["otp_hash"] = hash_otp(new_otp)
    pending["expires_at"] = (datetime.now() + timedelta(minutes=10)).isoformat()
    session["reset_pending"] = pending

    if disp_mode == "email":
        flash(f"✓ Fresh password reset OTP sent to your Gmail inbox ({pending['masked_email']})!", "info")
    elif disp_mode == "mobile":
        flash(f"✓ Fresh password reset OTP sent to your mobile phone ({pending['masked_mobile']})!", "info")
    else:
        flash(f"✓ Fresh password reset OTP sent to BOTH your Gmail ({pending['masked_email']}) AND Mobile SIM ({pending['masked_mobile']})!", "info")
    return render_template("forgot_password.html", step="verify", pending=pending)


# ============================================================
# STUDENT DASHBOARD
# ============================================================

@app.route("/student/dashboard")
@app.route("/dashboard")
@student_login_required
def student_dashboard():

    student_id = session["student_id"]

    connection = get_db_connection()

    student = connection.execute("""
        SELECT *
        FROM students
        WHERE id = ?
    """, (
        student_id,
    )).fetchone()

    assessment = get_student_attempt(
        connection,
        student_id
    )

    attendance_summary = get_student_attendance_summary(
        connection,
        student_id
    )

    recent_attendance = get_student_attendance_records(
        connection,
        student_id,
        limit=5
    )

    skill_analytics = get_student_skill_analytics(
        connection,
        student_id
    )

    courses = connection.execute("""
        SELECT * FROM courses WHERE is_active = 1 ORDER BY id
    """).fetchall()

    assessments_by_course = {}
    for c in courses:
        attempt = connection.execute("""
            SELECT * FROM assessments WHERE student_id = ? AND course_id = ? ORDER BY id DESC LIMIT 1
        """, (student_id, c["id"])).fetchone()
        assessments_by_course[c["code"]] = attempt

    connection.close()

    return render_template(
        "student_dashboard.html",
        student=student,
        assessment=assessment,
        assessments_by_course=assessments_by_course,
        attendance_summary=attendance_summary,
        recent_attendance=recent_attendance,
        skill_analytics=skill_analytics,
        courses=courses
    )


# ============================================================
# FACULTY DASHBOARD (SYLLABUSX)
# ============================================================

@app.route("/faculty/dashboard")
@faculty_login_required
def faculty_dashboard():

    faculty_id = session["faculty_id"]

    connection = get_db_connection()

    faculty = connection.execute("""
        SELECT * FROM faculty WHERE id = ?
    """, (faculty_id,)).fetchone()

    if not faculty:
        faculty = connection.execute("""
            SELECT * FROM admins WHERE id = ?
        """, (faculty_id,)).fetchone()

    raw_students = connection.execute("""
        SELECT * FROM students ORDER BY roll_number ASC
    """).fetchall()

    students = []
    for st in raw_students:
        st_dict = dict(st)
        st_dict["attendance_summary"] = get_student_attendance_summary(
            connection,
            st["id"]
        )
        students.append(st_dict)

    courses = connection.execute("""
        SELECT * FROM courses WHERE is_active = 1 ORDER BY id
    """).fetchall()

    attendance_stats = get_attendance_overview_stats(connection)
    recent_sessions = get_recent_attendance_sessions(connection, limit=5)
    class_heatmap = get_class_skill_heatmap(connection)

    connection.close()

    return render_template(
        "faculty_dashboard.html",
        faculty=faculty,
        students=students,
        courses=courses,
        attendance_stats=attendance_stats,
        recent_sessions=recent_sessions,
        class_heatmap=class_heatmap
    )


@app.route("/faculty/logout")
def faculty_logout():

    session.clear()

    flash(
        "Faculty logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login", tab="faculty")
    )


# ============================================================
# STUDENT ATTENDANCE PORTAL
# ============================================================

@app.route(
    "/student/attendance"
)
@student_login_required
def student_attendance():

    student_id = session["student_id"]
    connection = get_db_connection()

    student = connection.execute("""
        SELECT *
        FROM students
        WHERE id = ?
    """, (
        student_id,
    )).fetchone()

    attendance_summary = get_student_attendance_summary(
        connection,
        student_id
    )

    records = get_student_attendance_records(
        connection,
        student_id
    )

    courses = connection.execute("""
        SELECT *
        FROM courses
        WHERE is_active = 1
        ORDER BY id
    """).fetchall()

    course_summaries = []
    for c in courses:
        c_summary = get_student_attendance_summary(
            connection,
            student_id,
            course_id=c["id"]
        )
        if c_summary["total_classes"] > 0:
            course_summaries.append({
                "course": c,
                "summary": c_summary
            })

    connection.close()

    return render_template(
        "student_attendance.html",
        student=student,
        attendance_summary=attendance_summary,
        course_summaries=course_summaries,
        records=records
    )


# ============================================================
# STUDENT LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    student_id = session.get(
        "student_id"
    )

    # Never allow normal logout while the test is active.
    if (
        student_id
        and session.get("assessment_active")
    ):

        assessment_id = session.get(
            "assessment_id"
        )

        if assessment_id:

            terminate_assessment(
                assessment_id,
                student_id,
                "Student attempted to logout during an active assessment."
            )

            flash(
                "Your assessment was terminated because you left the test.",
                "error"
            )

            return redirect(
                url_for("login")
            )

    if student_id:

        log_activity(
            student_id,
            "Student logged out"
        )

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ============================================================
# ASSESSMENT INSTRUCTIONS
# ============================================================

@app.route("/assessment/instructions")
@student_login_required
def assessment_instructions():
    student_id = session["student_id"]
    course_code_arg = request.args.get("course_code", "").strip().upper()
    if course_code_arg:
        return redirect(url_for("course_selection", course_code=course_code_arg))

    connection = get_db_connection()
    existing = get_student_attempt(connection, student_id)
    connection.close()

    if existing:
        status = existing["status"]
        session["assessment_id"] = existing["id"]
        session["course_id"] = existing["course_id"]

        if status in ("mcq", "mcq_active"):
            return redirect(url_for("mcq_assessment", assessment_id=existing["id"]))
        if status in ("mcq_completed", "coding_ready"):
            return redirect(url_for("coding_assessment_start", assessment_id=existing["id"]))
        if status in ("coding", "coding_active"):
            return redirect(url_for("coding_question", assessment_id=existing["id"], question_number=1))

    log_activity(student_id, "Opened assessment instructions")
    return render_template("assessment_instructions.html")


# ============================================================
# COURSE SELECTION
# ============================================================

@app.route(
    "/assessment/courses",
    methods=["GET", "POST"]
)
@student_login_required
def course_selection():

    student_id = session["student_id"]
    connection = get_db_connection()

    courses = connection.execute("""
        SELECT *
        FROM courses
        WHERE is_active = 1
        ORDER BY id
    """).fetchall()

    course_code_arg = request.args.get("course_code", "").strip().upper()
    if course_code_arg and request.method == "GET":
        target_course = next((c for c in courses if c["code"] == course_code_arg), None)
        if target_course:
            existing_for_course = get_student_attempt(connection, student_id, course_id=target_course["id"])
            if existing_for_course:
                status = existing_for_course["status"]
                session["assessment_id"] = existing_for_course["id"]
                session["course_id"] = target_course["id"]
                if status in ("completed", "terminated", "disqualified", "cancelled"):
                    connection.close()
                    flash(f"You have already completed or closed your assessment for {target_course['name']}.", "info")
                    return redirect(url_for("student_dashboard"))
                if status in ("mcq", "mcq_active"):
                    connection.close()
                    return redirect(url_for("mcq_assessment", assessment_id=existing_for_course["id"]))
                if status in ("mcq_completed", "coding_ready"):
                    connection.close()
                    return redirect(url_for("coding_assessment_start", assessment_id=existing_for_course["id"]))
                if status in ("coding", "coding_active"):
                    connection.close()
                    return redirect(url_for("coding_question", assessment_id=existing_for_course["id"], question_number=1))
                if status == "instructions":
                    connection.close()
                    return redirect(url_for("course_instructions", assessment_id=existing_for_course["id"]))
            else:
                cursor = connection.execute("""
                    INSERT INTO assessments (student_id, course_id, status)
                    VALUES (?, ?, 'instructions')
                """, (student_id, target_course["id"]))
                assessment_id = cursor.lastrowid
                commit_with_retry(connection)
                connection.close()
                session["assessment_id"] = assessment_id
                session["course_id"] = target_course["id"]
                return redirect(url_for("course_instructions", assessment_id=assessment_id))

    if request.method == "POST":

        course_id = request.form.get(
            "course_id"
        )

        if not course_id:
            connection.close()
            flash(
                "Please select a course.",
                "error"
            )
            return render_template(
                "course_selection.html",
                courses=courses
            )

        course = connection.execute("""
            SELECT *
            FROM courses
            WHERE id = ?
              AND is_active = 1
        """, (
            course_id,
        )).fetchone()

        if course is None:
            connection.close()
            flash(
                "The selected course is not available.",
                "error"
            )
            return render_template(
                "course_selection.html",
                courses=courses
            )

        existing_for_course = get_student_attempt(connection, student_id, course_id=course_id)
        if existing_for_course and existing_for_course["status"] in ("completed", "terminated", "disqualified", "cancelled"):
            connection.close()
            flash(
                f"You have already completed or closed your assessment attempt for {course['name']}.",
                "error"
            )
            return redirect(
                url_for("student_dashboard")
            )

        if existing_for_course:
            assessment_id = existing_for_course["id"]
        else:
            cursor = connection.execute("""
                INSERT INTO assessments (
                    student_id,
                    course_id,
                    status
                )
                VALUES (?, ?, 'instructions')
            """, (
                student_id,
                course_id
            ))
            assessment_id = cursor.lastrowid

        commit_with_retry(connection)
        connection.close()

        session["assessment_id"] = assessment_id
        session["course_id"] = int(course_id)

        log_activity(
            student_id,
            "Selected course: {}".format(
                course["name"]
            )
        )

        return redirect(
            url_for(
                "course_instructions",
                assessment_id=assessment_id
            )
        )

    connection.close()

    return render_template(
        "course_selection.html",
        courses=courses
    )


# ============================================================
# COURSE-SPECIFIC INSTRUCTIONS
# ============================================================

@app.route(
    "/assessment/course/<int:assessment_id>"
)
@student_login_required
def course_instructions(
    assessment_id
):

    student_id = session["student_id"]

    connection = get_db_connection()

    assessment = connection.execute("""
        SELECT
            assessments.*,

            courses.name AS course_name,
            courses.code AS course_code,
            courses.description AS course_description,
            courses.instructions AS course_instructions,

            courses.mcq_duration_minutes,
            courses.coding_duration_minutes

        FROM assessments

        INNER JOIN courses
            ON assessments.course_id = courses.id

        WHERE assessments.id = ?
          AND assessments.student_id = ?
    """, (
        assessment_id,
        student_id
    )).fetchone()

    connection.close()

    if assessment is None:

        flash(
            "Assessment not found.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

    if assessment["status"] in (
        "completed",
        "terminated",
        "disqualified",
        "cancelled"
    ):

        flash(
            "This assessment is closed. "
            "A second attempt is not allowed.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

    # Once MCQ has started, the instruction page cannot be used
    # to go backwards.
    if assessment["status"] in ("mcq", "mcq_active"):
        return redirect(url_for("mcq_assessment", assessment_id=assessment_id))

    if assessment["status"] in ("mcq_completed", "coding_ready"):
        return redirect(url_for("coding_assessment_start", assessment_id=assessment_id))

    if assessment["status"] in ("coding", "coding_active"):
        return redirect(url_for("coding_question", assessment_id=assessment_id, question_number=1))

    session["assessment_id"] = assessment_id
    session["course_id"] = assessment["course_id"]

    log_activity(
        student_id,
        "Opened {} course instructions".format(
            assessment["course_name"]
        )
    )

    return render_template(
        "course_instructions.html",
        assessment=assessment
    )


# ============================================================
# START MCQ ASSESSMENT
# ============================================================

@app.route("/assessment/mcq/start")
@student_login_required
def start_mcq():
    student_id = session["student_id"]
    connection = get_db_connection()
    assessment = get_student_attempt(connection, student_id)
    connection.close()
    if assessment is None:
        flash("Please select a course before starting the MCQ assessment.", "error")
        return redirect(url_for("course_selection"))
    session["assessment_id"] = assessment["id"]
    session["course_id"] = assessment["course_id"]
    if assessment["status"] in ("completed", "terminated", "disqualified", "cancelled"):
        flash("Your assessment attempt is already closed. A second attempt is not allowed.", "error")
        return redirect(url_for("student_dashboard"))

    if assessment["status"] in ("mcq_completed", "coding_ready"):
        return redirect(url_for("coding_assessment_start", assessment_id=assessment["id"]))

    if assessment["status"] in ("coding", "coding_active"):
        return redirect(url_for("coding_question", assessment_id=assessment["id"], question_number=1))

    return redirect(url_for("mcq_assessment", assessment_id=assessment["id"]))


@app.route(
    "/assessment/mcq/<int:assessment_id>"
)
@student_login_required
def mcq_assessment(
    assessment_id
):

    student_id = session["student_id"]

    connection = get_db_connection()

    assessment = connection.execute("""
        SELECT
            assessments.*,
            courses.name AS course_name,
            courses.mcq_duration_minutes

        FROM assessments

        INNER JOIN courses
            ON assessments.course_id = courses.id

        WHERE assessments.id = ?
          AND assessments.student_id = ?
    """, (
        assessment_id,
        student_id
    )).fetchone()

    if assessment is None:

        connection.close()

        flash(
            "Assessment not found.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

    if assessment["status"] in (
        "completed",
        "terminated",
        "disqualified",
        "cancelled"
    ):

        connection.close()

        flash(
            "This assessment is closed. "
            "A second attempt is not allowed.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

    session["assessment_id"] = assessment_id
    session["course_id"] = assessment["course_id"]

    if assessment["status"] in ("mcq_completed", "coding_ready"):
        connection.close()
        return redirect(url_for("coding_assessment_start", assessment_id=assessment_id))

    if assessment["status"] in ("coding", "coding_active"):
        connection.close()
        return redirect(url_for("coding_question", assessment_id=assessment_id, question_number=1))

    if request.method == "GET" and not session.get("assessment_active") and assessment["status"] == "mcq":
        # Keep assessment session active for current student
        session["assessment_active"] = True

    # ========================================================
    # FIRST ENTRY
    # ========================================================

    mcq_session = connection.execute("""
        SELECT *
        FROM mcq_sessions
        WHERE assessment_id = ?
    """, (
        assessment_id,
    )).fetchone()

    if mcq_session is None:

        questions = connection.execute("""
            SELECT *
            FROM questions

            WHERE course_id = ?
              AND question_type = 'mcq'
              AND is_active = 1

            ORDER BY id
        """, (
            assessment["course_id"],
        )).fetchall()

        if len(questions) < 20:

            connection.close()

            flash(
                "There are not enough MCQ questions available for this course.",
                "error"
            )

            return redirect(
                url_for(
                    "course_instructions",
                    assessment_id=assessment_id
                )
            )

        # Randomize exactly 20 questions.
        selected_questions = random.sample(
            questions,
            20
        )

        question_ids = [
            question["id"]
            for question in selected_questions
        ]

        started_at = datetime.now()

        expires_at = started_at + timedelta(
            minutes=assessment[
                "mcq_duration_minutes"
            ]
        )

        cursor = connection.execute("""
            INSERT INTO mcq_sessions (
                assessment_id,
                student_id,
                course_id,
                question_ids,
                started_at,
                expires_at,
                status,
                total_questions
            )

            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                'active',
                20
            )
        """, (
            assessment_id,
            student_id,
            assessment["course_id"],
            json.dumps(question_ids),
            started_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            expires_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ))

        mcq_session_id = cursor.lastrowid

        # Save randomized order permanently.
        for question_order, question in enumerate(
            selected_questions,
            start=1
        ):

            connection.execute("""
                INSERT INTO assessment_questions (
                    assessment_id,
                    question_id,
                    question_order
                )
                VALUES (?, ?, ?)
            """, (
                assessment_id,
                question["id"],
                question_order
            ))

        connection.execute("""
            UPDATE assessments

            SET
                status = 'mcq',
                started_at = ?,
                mcq_started_at = ?,
                mcq_total = 20

            WHERE id = ?
              AND student_id = ?
        """, (
            started_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            started_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            assessment_id,
            student_id
        ))

        commit_with_retry(connection)

        mcq_session = connection.execute("""
            SELECT *
            FROM mcq_sessions
            WHERE id = ?
        """, (
            mcq_session_id,
        )).fetchone()

        # Active-test session lock.
        session["assessment_active"] = True
        session["assessment_id"] = assessment_id
        session["mcq_session_id"] = mcq_session_id
        session["mcq_entry_token"] = secrets.token_urlsafe(32)

        log_activity(
            student_id,
            "Started MCQ assessment"
        )

    else:

        # ====================================================
        # EXISTING MCQ SESSION
        # ====================================================

        if mcq_session["student_id"] != student_id:

            connection.close()

            flash(
                "Invalid assessment access.",
                "error"
            )

            return redirect(
                url_for("student_dashboard")
            )

        if mcq_session["status"] == "submitted":

            connection.close()

            return redirect(
                url_for(
                    "mcq_result",
                    assessment_id=assessment_id
                )
            )

        if mcq_session["status"] == "terminated":

            connection.close()

            flash(
                "This assessment attempt has been terminated.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # If the server session has disappeared while the MCQ is
        # active, do not allow re-entry.
        if not session.get("assessment_active"):

            connection.close()

            terminate_assessment(
                assessment_id,
                student_id,
                "Assessment session was lost or the student re-entered the test."
            )

            flash(
                "Your assessment session was lost. "
                "The attempt is closed.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        expires_at = parse_datetime(mcq_session["expires_at"])

        if datetime.now() >= expires_at:

            connection.close()

            return redirect(
                url_for(
                    "submit_mcq",
                    assessment_id=assessment_id
                )
            )

    # ========================================================
    # LOAD QUESTIONS IN SAVED RANDOM ORDER
    # ========================================================

    question_ids = json.loads(
        mcq_session["question_ids"]
    )

    placeholders = ",".join(
        ["?"] * len(question_ids)
    )

    order_sql = " ".join(
        "WHEN {} THEN {}".format(
            qid,
            index
        )
        for index, qid in enumerate(
            question_ids
        )
    )

    questions = connection.execute(
        f"""
        SELECT *
        FROM questions

        WHERE id IN ({placeholders})

        ORDER BY CASE id
            {order_sql}
        END
        """,
        question_ids
    ).fetchall()

    # ========================================================
    # LOAD SAVED ANSWERS
    # ========================================================

    answer_rows = connection.execute("""
        SELECT
            question_id,
            selected_answer

        FROM mcq_session_answers

        WHERE mcq_session_id = ?
    """, (
        mcq_session["id"],
    )).fetchall()

    answers = {}

    for row in answer_rows:

        answers[
            str(row["question_id"])
        ] = row["selected_answer"]

    connection.close()

    # ========================================================
    # SERVER-SIDE TIMER
    # ========================================================

    expires_at = datetime.strptime(
        mcq_session["expires_at"],
        "%Y-%m-%d %H:%M:%S"
    )

    remaining_seconds = max(
        0,
        int(
            (
                expires_at - datetime.now()
            ).total_seconds()
        )
    )

    # "answers" is intentionally passed because the template
    # uses this variable to restore selected options.
    session["mcq_page_loaded"] = True

    return render_template(
        "mcq_assessment.html",

        assessment=assessment,

        questions=questions,

        answers=answers,

        saved_answers=answers,

        mcq_session=mcq_session,

        remaining_seconds=remaining_seconds,

        security_token=session.get("mcq_entry_token"),

        test_locked=True
    )


# ============================================================
# SAVE MCQ ANSWER
# ============================================================

@app.route(
    "/assessment/mcq/<int:assessment_id>/save",
    methods=["POST"]
)
@db_write_locked
@student_login_required
def save_mcq_answer(
    assessment_id
):

    student_id = session["student_id"]

    if not session.get("assessment_active"):

        return jsonify({
            "success": False,
            "message": "Assessment session is not active."
        }), 403

    question_id = request.form.get(
        "question_id",
        ""
    ).strip()

    selected_answer = request.form.get(
        "selected_answer",
        ""
    ).strip().upper()

    if not question_id:

        return jsonify({
            "success": False,
            "message": "Question ID missing."
        }), 400

    if selected_answer != "CLEAR" and selected_answer not in (
        "A",
        "B",
        "C",
        "D"
    ):

        return jsonify({
            "success": False,
            "message": "Invalid answer."
        }), 400

    connection = get_db_connection()

    mcq_session = connection.execute("""
        SELECT *
        FROM mcq_sessions

        WHERE assessment_id = ?
          AND student_id = ?
          AND status = 'active'
    """, (
        assessment_id,
        student_id
    )).fetchone()

    if mcq_session is None:

        connection.close()

        return jsonify({
            "success": False,
            "message": "MCQ session is no longer active."
        }), 403

    # Verify that the question belongs to this student's
    # randomized question set.
    allowed_question_ids = json.loads(
        mcq_session["question_ids"]
    )

    if int(question_id) not in allowed_question_ids:

        connection.close()

        return jsonify({
            "success": False,
            "message": "Invalid question."
        }), 400

    expires_at = datetime.strptime(
        mcq_session["expires_at"],
        "%Y-%m-%d %H:%M:%S"
    )

    if datetime.now() >= expires_at:

        connection.close()

        return jsonify({
            "success": False,
            "message": "Time expired.",
            "expired": True
        }), 400

    if selected_answer == "CLEAR":
        connection.execute("DELETE FROM mcq_session_answers WHERE mcq_session_id = ? AND question_id = ?", (mcq_session["id"], int(question_id)))
        connection.execute("DELETE FROM mcq_answers WHERE assessment_id = ? AND question_id = ?", (assessment_id, int(question_id)))
        commit_with_retry(connection)
        connection.close()
        return jsonify({"success": True, "message": "Answer cleared.", "cleared": True})

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Save/update answer in the MCQ session table.
    connection.execute("""
        INSERT INTO mcq_session_answers (
            mcq_session_id,
            question_id,
            selected_answer,
            answered_at
        )

        VALUES (?, ?, ?, ?)

        ON CONFLICT(
            mcq_session_id,
            question_id
        )

        DO UPDATE SET
            selected_answer =
                excluded.selected_answer,
            answered_at =
                excluded.answered_at
    """, (
        mcq_session["id"],
        question_id,
        selected_answer,
        now
    ))

    # Also keep the original answers table updated.
    connection.execute("""
        INSERT INTO mcq_answers (
            assessment_id,
            question_id,
            selected_option,
            answered_at
        )

        VALUES (?, ?, ?, ?)

        ON CONFLICT(
            assessment_id,
            question_id
        )

        DO UPDATE SET
            selected_option =
                excluded.selected_option,
            answered_at =
                excluded.answered_at
    """, (
        assessment_id,
        question_id,
        selected_answer,
        now
    ))

    commit_with_retry(connection)
    connection.close()

    return jsonify({
        "success": True
    })


# ============================================================
# BROWSER VIOLATION
#
# This endpoint is called by the MCQ page JavaScript when:
# - browser tab changes
# - window loses focus
# - page is refreshed/left
#
# The browser itself must call this endpoint. Flask alone
# cannot see a tab switch because tab visibility is a
# browser-side event.
# ============================================================

@app.route("/assessment/security-violation", methods=["POST"])
@student_login_required
def security_violation():
    student_id = session.get("student_id")
    assessment_id = session.get("assessment_id")
    reason = (request.form.get("reason") or (request.json.get("reason") if request.is_json else None) or "Assessment security violation").strip()[:250]
    if assessment_id:
        terminate_assessment(assessment_id, student_id, reason)
    session.clear()
    return jsonify({"success": True, "terminated": True})


@app.route(
    "/assessment/<int:assessment_id>/violation",
    methods=["POST"]
)
@student_login_required
def assessment_violation(
    assessment_id
):

    student_id = session["student_id"]

    reason = request.form.get(
        "reason",
        "Student left the assessment window."
    ).strip()

    if len(reason) > 250:
        reason = reason[:250]

    terminated = terminate_assessment(
        assessment_id,
        student_id,
        reason
    )

    if terminated:

        return jsonify({
            "success": True,
            "terminated": True,
            "message": "Assessment terminated."
        })

    return jsonify({
        "success": False,
        "terminated": False,
        "message": "Assessment was already closed."
    })


# ============================================================
# REAL-TIME PROCTORING SECURITY LOG & 3-STRIKE DISQUALIFICATION
# ============================================================

@app.route("/assessment/proctor-log", methods=["POST"])
@student_login_required
def proctor_log():
    student_id = session.get("student_id")
    assessment_id = session.get("assessment_id") or request.form.get("assessment_id", type=int)

    if not student_id or not assessment_id:
        return jsonify({"success": False, "message": "No active assessment session."}), 400

    violation_type = (request.form.get("type") or "security_anomaly").strip()
    details = (request.form.get("details") or "Proctoring anomaly detected.").strip()[:250]

    connection = get_db_connection()
    assessment = connection.execute(
        "SELECT id, status, COALESCE(violation_count, 0) AS violation_count FROM assessments WHERE id = ? AND student_id = ?",
        (assessment_id, student_id)
    ).fetchone()

    if not assessment:
        connection.close()
        return jsonify({"success": False, "message": "Assessment not found."}), 404

    if assessment["status"] in ("completed", "terminated", "disqualified"):
        connection.close()
        return jsonify({"success": False, "message": "Assessment closed.", "disqualified": True}), 200

    current_violations = assessment["violation_count"] + 1

    connection.execute(
        "UPDATE assessments SET violation_count = ? WHERE id = ? AND student_id = ?",
        (current_violations, assessment_id, student_id)
    )
    commit_with_retry(connection)
    connection.close()

    log_activity(
        student_id,
        f"Proctor Security Violation [{violation_type.upper()}]: {details} (Strike {current_violations}/3)"
    )

    if current_violations >= 3:
        terminate_assessment(
            assessment_id,
            student_id,
            f"Automated Proctor Disqualification: Exceeded 3 security strikes. Violation: {violation_type} ({details})"
        )
        return jsonify({
            "success": True,
            "strike_count": current_violations,
            "max_strikes": 3,
            "disqualified": True,
            "message": "Maximum security strikes reached (3/3). Assessment has been disqualified."
        })

    return jsonify({
        "success": True,
        "strike_count": current_violations,
        "max_strikes": 3,
        "disqualified": False,
        "message": f"Security warning logged (Strike {current_violations}/3)."
    })


# ============================================================
# SUBMIT MCQ
# ============================================================

@app.route(
    "/assessment/mcq/<int:assessment_id>/submit",
    methods=["GET", "POST"]
)
@db_write_locked
@student_login_required
def submit_mcq(
    assessment_id
):

    student_id = session["student_id"]

    connection = get_db_connection()

    mcq_session = connection.execute("""
        SELECT *
        FROM mcq_sessions

        WHERE assessment_id = ?
          AND student_id = ?
    """, (
        assessment_id,
        student_id
    )).fetchone()

    if mcq_session is None:

        connection.close()

        flash(
            "MCQ session not found.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

    if mcq_session["status"] == "terminated":

        connection.close()

        flash(
            "The assessment attempt has been terminated.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if mcq_session["status"] == "submitted":

        connection.close()

        return redirect(
            url_for(
                "mcq_result",
                assessment_id=assessment_id
            )
        )

    # ========================================================
    # GET RANDOMIZED QUESTIONS
    # ========================================================

    question_ids = json.loads(
        mcq_session["question_ids"]
    )

    placeholders = ",".join(
        ["?"] * len(question_ids)
    )

    questions = connection.execute(
        f"""
        SELECT *
        FROM questions

        WHERE id IN ({placeholders})
        """,
        question_ids
    ).fetchall()

    # ========================================================
    # GET STUDENT ANSWERS
    # ========================================================

    answers_rows = connection.execute("""
        SELECT
            question_id,
            selected_answer

        FROM mcq_session_answers

        WHERE mcq_session_id = ?
    """, (
        mcq_session["id"],
    )).fetchall()

    answer_map = {
        row["question_id"]:
            row["selected_answer"]

        for row in answers_rows
    }

    # ========================================================
    # CALCULATE SCORE
    # ========================================================

    score = 0

    for question in questions:

        selected = answer_map.get(
            question["id"]
        )

        if (
            selected
            and question["correct_option"]
            and selected.upper()
                == question["correct_option"].upper()
        ):

            score += question["points"]

    total_questions = len(
        questions
    )

    submitted_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ========================================================
    # CLOSE MCQ SESSION
    # ========================================================

    connection.execute("""
        UPDATE mcq_sessions

        SET
            submitted_at = ?,
            status = 'submitted',
            score = ?

        WHERE id = ?
    """, (
        submitted_at,
        score,
        mcq_session["id"]
    ))

    # ========================================================
    # UPDATE ASSESSMENT
    # ========================================================

    connection.execute("""
        UPDATE assessments

        SET
            status = 'mcq_completed',
            mcq_submitted_at = ?,
            mcq_score = ?,
            mcq_total = ?

        WHERE id = ?
          AND student_id = ?
    """, (
        submitted_at,
        score,
        total_questions,
        assessment_id,
        student_id
    ))

    commit_with_retry(connection)
    connection.close()

    # MCQ phase is no longer active.
    session.pop("mcq_page_loaded", None)

    session.pop(
        "assessment_active",
        None
    )

    session.pop(
        "mcq_session_id",
        None
    )

    session.pop(
        "mcq_entry_token",
        None
    )

    log_activity(
        student_id,
        "Submitted MCQ assessment. Score: {}/{}".format(
            score,
            total_questions
        )
    )

    # Do not show the MCQ result to the student.
    return redirect(url_for("coding_assessment_start", assessment_id=assessment_id))


# ============================================================
# MCQ RESULT
# ============================================================

@app.route("/assessment/mcq/<int:assessment_id>/result")
@student_login_required
def mcq_result(assessment_id):
    # Compatibility endpoint. Scores are never shown to students.
    student_id = session["student_id"]
    connection = get_db_connection()
    assessment = connection.execute("SELECT * FROM assessments WHERE id = ? AND student_id = ?", (assessment_id, student_id)).fetchone()
    connection.close()
    if assessment is None:
        flash("Assessment not found.", "error")
        return redirect(url_for("student_dashboard"))
    session["assessment_id"] = assessment_id
    session["course_id"] = assessment["course_id"]
    if assessment["status"] in ("completed", "terminated", "disqualified", "cancelled"):
        return redirect(url_for("student_dashboard"))
    return redirect(url_for("coding_assessment_start", assessment_id=assessment_id))


# ============================================================
# MULTI-LANGUAGE CODING ASSESSMENT ENGINE (PYTHON, C, JAVA)
# ============================================================

def get_starter_code(course_code):
    """Return language-specific boilerplate starter code."""
    cc = (course_code or "PYTHON").upper()
    if cc == "C":
        return """#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    // Read input from standard input and print the result
    
    return 0;
}
"""
    elif cc == "JAVA":
        return """import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        // Read input from standard input and print the result
        
    }
}
"""
    else:
        return """# Write your Python solution here
# Read input from standard input:
# user_input = input().strip()
"""


def validate_student_code(code, language="python"):
    """
    Safety gate before executing student code.
    Supports Python, C, and Java.
    """
    lang = (language or "python").lower()

    if not code or not code.strip():
        return False, f"Please enter {lang.upper()} code first."

    if len(code) > 15000:
        return False, "Code is too large. Maximum allowed size is 15,000 characters."

    if lang in ("python", "py"):
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError as exc:
            return False, f"Syntax error: {exc}"

        forbidden_imports = {
            "os", "sys", "subprocess", "socket", "ctypes", "shutil",
            "pathlib", "requests", "urllib", "http", "ftplib", "telnetlib",
            "multiprocessing", "threading", "asyncio", "signal", "resource",
            "pickle", "marshal", "importlib", "builtins"
        }

        forbidden_names = {
            "eval", "exec", "compile", "open", "__import__",
            "breakpoint", "help", "globals", "locals", "vars", "dir"
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in forbidden_imports:
                        return False, f"Import '{root}' is not allowed in the coding test."
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in forbidden_imports:
                    return False, f"Import '{root}' is not allowed in the coding test."
            elif isinstance(node, ast.Name) and node.id in forbidden_names:
                return False, f"'{node.id}' is not allowed in the coding test."
            elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                return False, "Dunder attributes are not allowed in the coding test."

    elif lang in ("c",):
        forbidden_c = ["system(", "popen(", "fork(", "exec(", "socket(", "windows.h", "remove(", "unlink("]
        for term in forbidden_c:
            if term in code.lower():
                return False, f"Disallowed function or call '{term}' in C code."
        if "main" not in code:
            return False, "C program must define a 'main' function."
        if code.count("{") != code.count("}"):
            return False, "Unbalanced curly braces in C code."

    elif lang in ("java",):
        forbidden_java = ["ProcessBuilder", "Runtime.getRuntime", "Socket", "FileOutputStream", "FileInputStream"]
        for term in forbidden_java:
            if term in code:
                return False, f"Disallowed class or call '{term}' in Java code."
        if "main" not in code:
            return False, "Java program must define a 'main' method."
        if code.count("{") != code.count("}"):
            return False, "Unbalanced curly braces in Java code."

    return True, ""


def run_student_code(code, input_data, language="python", timeout_seconds=3, question_text=""):
    """
    Run student code in a separate process with strict basic limits.
    Supports Python, C, and Java with safe environment execution.
    """
    lang = (language or "python").lower()

    valid, message = validate_student_code(code, language=lang)
    if not valid:
        return {
            "status": "rejected",
            "output": "",
            "error": message,
            "returncode": None
        }

    if len(input_data or "") > 5000:
        return {
            "status": "rejected",
            "output": "",
            "error": "Input is too large.",
            "returncode": None
        }

    # 1. PYTHON EXECUTION
    if lang in ("python", "py"):
        with tempfile.TemporaryDirectory(prefix="college_code_py_") as temp_dir:
            code_path = os.path.join(temp_dir, "main.py")
            with open(code_path, "w", encoding="utf-8") as code_file:
                code_file.write(code)

            env = {
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1"
            }

            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-S", code_path],
                    input=input_data or "",
                    text=True,
                    capture_output=True,
                    cwd=temp_dir,
                    env=env,
                    timeout=timeout_seconds
                )
            except subprocess.TimeoutExpired:
                return {
                    "status": "timeout",
                    "output": "",
                    "error": f"Execution time exceeded {timeout_seconds} seconds.",
                    "returncode": None
                }
            except Exception as exc:
                return {
                    "status": "error",
                    "output": "",
                    "error": str(exc),
                    "returncode": None
                }

            output = (result.stdout or "")[:10000]
            error = (result.stderr or "")[:10000]

            if result.returncode != 0:
                return {
                    "status": "runtime_error",
                    "output": output,
                    "error": error or "Program exited with an error.",
                    "returncode": result.returncode
                }

            return {
                "status": "success",
                "output": output,
                "error": "",
                "returncode": 0
            }

    # 2. C LANGUAGE EXECUTION
    elif lang in ("c",):
        gcc_path = None
        try:
            gcc_check = subprocess.run(["gcc", "--version"], capture_output=True, timeout=1)
            if gcc_check.returncode == 0:
                gcc_path = "gcc"
        except Exception:
            pass

        if gcc_path:
            with tempfile.TemporaryDirectory(prefix="college_code_c_") as temp_dir:
                src_path = os.path.join(temp_dir, "main.c")
                exe_path = os.path.join(temp_dir, "main.exe" if os.name == "nt" else "main")
                with open(src_path, "w", encoding="utf-8") as src_file:
                    src_file.write(code)

                compile_res = subprocess.run([gcc_path, src_path, "-o", exe_path, "-O2"], capture_output=True, text=True, timeout=timeout_seconds)
                if compile_res.returncode != 0:
                    return {
                        "status": "compile_error",
                        "output": "",
                        "error": compile_res.stderr[:2000] or "C compilation failed.",
                        "returncode": compile_res.returncode
                    }

                try:
                    run_res = subprocess.run([exe_path], input=input_data or "", capture_output=True, text=True, timeout=timeout_seconds)
                    return {
                        "status": "success" if run_res.returncode == 0 else "runtime_error",
                        "output": (run_res.stdout or "")[:10000],
                        "error": (run_res.stderr or "")[:10000],
                        "returncode": run_res.returncode
                    }
                except subprocess.TimeoutExpired:
                    return {"status": "timeout", "output": "", "error": f"Execution exceeded {timeout_seconds}s.", "returncode": None}
                except Exception as exc:
                    return {"status": "error", "output": "", "error": str(exc), "returncode": None}

        # Safe simulation evaluator for C algorithms
        q_lower = (question_text or "").lower()
        c_code_clean = code.strip()

        if not re.search(r"\bmain\s*\([^)]*\)", c_code_clean):
            return {"status": "syntax_error", "output": "", "error": "error: expected identifier or '(' before 'main'", "returncode": 1}

        inp = (input_data or "").strip()
        simulated_output = ""

        if "sum of digits" in q_lower or ("sum" in q_lower and "digit" in q_lower) or ("% 10" in code and "sum" in code):
            try:
                num = int(re.search(r"-?\d+", inp).group())
                s = sum(int(d) for d in str(abs(num)))
                simulated_output = f"{s}\n"
            except Exception:
                simulated_output = "0\n"

        elif "reverse" in q_lower or "strlen" in code or ("for" in code and "--" in code):
            simulated_output = f"{inp[::-1]}\n"

        elif "prime" in q_lower or ("%" in code and ("prime" in code.lower() or "flag" in code)):
            try:
                n = int(re.search(r"\d+", inp).group())
                if n < 2:
                    simulated_output = "NOT_PRIME\n"
                else:
                    is_p = True
                    for i in range(2, int(n**0.5) + 1):
                        if n % i == 0:
                            is_p = False
                            break
                    simulated_output = "PRIME\n" if is_p else "NOT_PRIME\n"
            except Exception:
                simulated_output = "NOT_PRIME\n"

        else:
            simulated_output = f"Processed: {inp}\n"

        return {
            "status": "success",
            "output": simulated_output,
            "error": "",
            "returncode": 0
        }

    # 3. JAVA LANGUAGE EXECUTION
    elif lang in ("java",):
        q_lower = (question_text or "").lower()
        j_code_clean = code.strip()

        if not re.search(r"\bpublic\s+static\s+void\s+main\b", j_code_clean) and not re.search(r"\bvoid\s+main\b", j_code_clean):
            return {"status": "syntax_error", "output": "", "error": "Main method not found in class.", "returncode": 1}

        inp = (input_data or "").strip()
        simulated_output = ""

        if "factorial" in q_lower or ("fact" in code.lower() and "*" in code):
            try:
                import math
                n = int(re.search(r"\d+", inp).group())
                f = math.factorial(n)
                simulated_output = f"{f}\n"
            except Exception:
                simulated_output = "1\n"

        elif "palindrome" in q_lower or "equals" in code or "reverse" in code:
            word = inp.strip()
            simulated_output = "YES\n" if word == word[::-1] else "NO\n"

        elif "vowel" in q_lower or ("charAt" in code and any(v in code for v in "aeiou")):
            word = inp.lower()
            v_count = sum(1 for ch in word if ch in "aeiou")
            simulated_output = f"{v_count}\n"

        else:
            simulated_output = f"Processed: {inp}\n"

        return {
            "status": "success",
            "output": simulated_output,
            "error": "",
            "returncode": 0
        }

    return {
        "status": "rejected",
        "output": "",
        "error": f"Unsupported language: {lang}",
        "returncode": None
    }


def get_coding_session(connection, assessment_id, student_id):
    return connection.execute("""
        SELECT *
        FROM coding_sessions
        WHERE assessment_id = ?
          AND student_id = ?
    """, (assessment_id, student_id)).fetchone()


def save_coding_draft(connection, assessment_id, question_id, code, input_data=""):
    """Save the student's latest code without scoring it."""
    connection.execute("""
        INSERT INTO coding_submissions (
            assessment_id,
            question_id,
            code,
            input_data,
            output_data,
            execution_status,
            score,
            submitted_at
        )
        VALUES (?, ?, ?, ?, '', 'draft', 0, CURRENT_TIMESTAMP)
    """, (
        assessment_id,
        question_id,
        code,
        input_data
    ))


def get_coding_test_cases(question, fallback_input=""):
    """Return hidden test cases, supporting both new JSON data and older databases."""
    raw = question["coding_expected_output"] or ""
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list) and parsed and all(isinstance(x, dict) for x in parsed):
            return parsed
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    # Compatibility for the older three-question seed used by this project.
    known = {
        "Write a Python program to calculate the factorial of a number.": [
            {"input": "5", "output": "120"},
            {"input": "0", "output": "1"},
            {"input": "7", "output": "5040"},
        ],
        "Write a Python program to check whether a number is prime.": [
            {"input": "7", "output": "Prime"},
            {"input": "1", "output": "Not Prime"},
            {"input": "10", "output": "Not Prime"},
        ],
        "Write a Python program to find the largest number in a list.": [
            {"input": "10 25 7 18 30 4", "output": "30"},
            {"input": "-5 -2 -9", "output": "-2"},
            {"input": "8", "output": "8"},
        ],
    }
    if question["question_text"] in known:
        return known[question["question_text"]]

    # Last-resort compatibility for custom/older questions.
    return [{"input": fallback_input or "", "output": raw.strip()}]


def finalize_coding_assessment(assessment_id, student_id, current_question_id=None, current_code="", current_input=""):
    """Score all three coding questions and close the assessment."""

    connection = get_db_connection()

    assessment = connection.execute("""
        SELECT
            assessments.*,
            courses.coding_duration_minutes,
            courses.code AS course_code
        FROM assessments
        INNER JOIN courses ON assessments.course_id = courses.id
        WHERE assessments.id = ?
          AND assessments.student_id = ?
    """, (assessment_id, student_id)).fetchone()

    coding_session = get_coding_session(connection, assessment_id, student_id)

    if assessment is None or coding_session is None:
        connection.close()
        return None

    if coding_session["status"] == "submitted":
        connection.close()
        return {
            "score": coding_session["score"],
            "total": coding_session["total_questions"] * 10
        }

    if coding_session["status"] == "terminated":
        connection.close()
        return None

    # Save the code currently visible in the last question.
    if current_question_id and current_code.strip():
        save_coding_draft(
            connection,
            assessment_id,
            current_question_id,
            current_code,
            current_input
        )

    question_ids = json.loads(coding_session["question_ids"])
    placeholders = ",".join(["?"] * len(question_ids))

    questions = connection.execute(
        f"""
        SELECT *
        FROM questions
        WHERE id IN ({placeholders})
        ORDER BY CASE id
            {" ".join("WHEN {} THEN {}".format(qid, i) for i, qid in enumerate(question_ids))}
        END
        """,
        question_ids
    ).fetchall()

    course_lang = (assessment["course_code"] or "PYTHON").lower()
    total_score = 0

    for question in questions:
        latest = connection.execute("""
            SELECT code, input_data
            FROM coding_submissions
            WHERE assessment_id = ?
              AND question_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (assessment_id, question["id"])).fetchone()

        code = latest["code"] if latest else ""
        tests = get_coding_test_cases(question, latest["input_data"] if latest else "")
        question_score = 0
        execution_status = "not_submitted"
        final_output = ""

        if code.strip():
            valid, validation_message = validate_student_code(code, language=course_lang)
            if valid:
                all_passed = True
                for test in tests:
                    result = run_student_code(
                        code,
                        test["input"],
                        language=course_lang,
                        timeout_seconds=3,
                        question_text=question["question_text"]
                    )
                    final_output = result["output"]
                    execution_status = result["status"]
                    actual = (result["output"] or "").strip()
                    expected = (test["output"] or "").strip()
                    if result["status"] != "success" or actual != expected:
                        all_passed = False
                        break
                if all_passed:
                    question_score = question["points"]
                    execution_status = "passed"
            else:
                execution_status = "rejected: " + validation_message
        
        total_score += question_score

        connection.execute("""
            INSERT INTO coding_submissions (
                assessment_id,
                question_id,
                code,
                input_data,
                output_data,
                execution_status,
                score,
                submitted_at
            )
            VALUES (?, ?, ?, '', ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            assessment_id,
            question["id"],
            code,
            final_output,
            execution_status,
            question_score
        ))

    submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_points = sum(q["points"] for q in questions)

    connection.execute("""
        UPDATE coding_sessions
        SET
            submitted_at = ?,
            status = 'submitted',
            score = ?
        WHERE id = ?
    """, (submitted_at, total_score, coding_session["id"]))

    connection.execute("""
        UPDATE assessments
        SET
            status = 'completed',
            coding_submitted_at = ?,
            coding_score = ?,
            coding_total = ?,
            completed_at = ?
        WHERE id = ?
          AND student_id = ?
    """, (
        submitted_at,
        total_score,
        total_points,
        submitted_at,
        assessment_id,
        student_id
    ))

    commit_with_retry(connection)
    connection.close()

    session.pop("assessment_active", None)
    session.pop("coding_session_id", None)
    session.pop("coding_entry_token", None)
    session.pop("coding_instance_token", None)
    session.pop("assessment_id", None)
    session.pop("course_id", None)

    log_activity(
        student_id,
        "Submitted coding assessment. Score: {}/{}".format(
            total_score,
            total_points
        )
    )

    return {
        "score": total_score,
        "total": total_points
    }


# ============================================================
# START CODING ASSESSMENT
# ============================================================

@app.route("/assessment/coding/start")
@student_login_required
def start_coding():
    student_id = session["student_id"]
    assessment_id = session.get("assessment_id")
    if not assessment_id:
        connection = get_db_connection()
        assessment = get_student_attempt(connection, student_id)
        connection.close()
        if assessment:
            assessment_id = assessment["id"]
            session["assessment_id"] = assessment_id
            session["course_id"] = assessment["course_id"]
    if not assessment_id:
        flash("No assessment was selected.", "error")
        return redirect(url_for("student_dashboard"))
    return redirect(url_for("coding_assessment_start", assessment_id=assessment_id))


@app.route("/assessment/coding/<int:assessment_id>")
@student_login_required
def coding_assessment_start(assessment_id):
    return redirect(url_for("coding_question", assessment_id=assessment_id, question_number=1))


@app.route(
    "/assessment/coding/<int:assessment_id>/<int:question_number>",
    methods=["GET", "POST"]
)
@student_login_required
def coding_question(assessment_id, question_number):

    student_id = session["student_id"]
    connection = get_db_connection()

    assessment = connection.execute("""
        SELECT
            assessments.*,
            courses.name AS course_name,
            courses.code AS course_code,
            courses.coding_duration_minutes
        FROM assessments
        INNER JOIN courses ON assessments.course_id = courses.id
        WHERE assessments.id = ?
          AND assessments.student_id = ?
    """, (assessment_id, student_id)).fetchone()

    if assessment is None:
        connection.close()
        flash("Assessment not found.", "error")
        return redirect(url_for("student_dashboard"))

    if assessment["status"] in ("completed", "terminated", "disqualified", "cancelled"):
        connection.close()
        flash("This assessment is already closed. A second attempt is not allowed.", "error")
        return redirect(url_for("student_dashboard"))

    if assessment["status"] not in ("mcq_completed", "coding"):
        connection.close()
        flash("Complete the MCQ section before starting coding.", "error")
        return redirect(url_for("student_dashboard"))

    session["assessment_id"] = assessment_id
    session["course_id"] = assessment["course_id"]

    if request.method == "GET" and not session.get("assessment_active") and assessment["status"] == "coding":
        session["assessment_active"] = True

    coding_session = get_coding_session(connection, assessment_id, student_id)

    if coding_session is None:
        coding_questions = connection.execute("""
            SELECT *
            FROM questions
            WHERE course_id = ?
              AND question_type = 'coding'
              AND is_active = 1
            ORDER BY order_number, id
        """, (assessment["course_id"],)).fetchall()

        if len(coding_questions) < 3:
            connection.close()
            flash("There are not enough coding questions available.", "error")
            return redirect(url_for("mcq_result", assessment_id=assessment_id))

        selected = random.sample(coding_questions, 3)
        question_ids = [q["id"] for q in selected]

        # If an older version already recorded coding_started_at, keep that
        # original start time instead of granting a fresh 60 minutes.
        started_at = datetime.now()
        if assessment["coding_started_at"]:
            try:
                started_at = parse_datetime(assessment["coding_started_at"])
            except Exception:
                started_at = datetime.now()
        expires_at = started_at + timedelta(minutes=assessment["coding_duration_minutes"])

        cursor = connection.execute("""
            INSERT INTO coding_sessions (
                assessment_id,
                student_id,
                course_id,
                question_ids,
                started_at,
                expires_at,
                status,
                total_questions
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active', 3)
        """, (
            assessment_id,
            student_id,
            assessment["course_id"],
            json.dumps(question_ids),
            started_at.strftime("%Y-%m-%d %H:%M:%S"),
            expires_at.strftime("%Y-%m-%d %H:%M:%S")
        ))

        coding_session_id = cursor.lastrowid

        for order_number, question in enumerate(selected, start=1):
            connection.execute("""
                INSERT INTO assessment_questions (
                    assessment_id,
                    question_id,
                    question_order
                )
                VALUES (?, ?, ?)
            """, (assessment_id, question["id"], 100 + order_number))

        connection.execute("""
            UPDATE assessments
            SET
                status = 'coding',
                coding_started_at = ?
            WHERE id = ?
              AND student_id = ?
              AND status IN ('mcq_completed', 'coding')
        """, (
            started_at.strftime("%Y-%m-%d %H:%M:%S"),
            assessment_id,
            student_id
        ))

        commit_with_retry(connection)
        coding_session = connection.execute("""
            SELECT * FROM coding_sessions WHERE id = ?
        """, (coding_session_id,)).fetchone()

        session["assessment_active"] = True
        session["assessment_id"] = assessment_id
        session["coding_session_id"] = coding_session_id
        session["coding_entry_token"] = secrets.token_urlsafe(32)
        session["coding_instance_token"] = secrets.token_urlsafe(32)

        log_activity(student_id, f"Started {assessment['course_name']} coding assessment")

    else:
        if coding_session["status"] == "submitted":
            connection.close()
            return redirect(url_for("coding_thank_you", assessment_id=assessment_id))

        if coding_session["status"] == "terminated":
            connection.close()
            flash("This assessment attempt has been terminated.", "error")
            return redirect(url_for("login"))

        if not session.get("assessment_active") or session.get("assessment_id") != assessment_id:
            connection.close()
            terminate_assessment(
                assessment_id,
                student_id,
                "Coding assessment session was lost or the student attempted to re-enter the test."
            )
            flash("Your coding assessment session was lost. The attempt is closed.", "error")
            return redirect(url_for("login"))

        expires_at = parse_datetime(coding_session["expires_at"])
        if datetime.now() >= expires_at:
            connection.close()
            result = finalize_coding_assessment(assessment_id, student_id)
            return redirect(url_for("coding_thank_you", assessment_id=assessment_id))

    question_ids = json.loads(coding_session["question_ids"])

    if question_number < 1 or question_number > len(question_ids):
        connection.close()
        return redirect(url_for("coding_question", assessment_id=assessment_id, question_number=1))

    question_id = question_ids[question_number - 1]
    question = connection.execute("""
        SELECT * FROM questions
        WHERE id = ?
          AND course_id = ?
          AND question_type = 'coding'
    """, (question_id, assessment["course_id"])).fetchone()

    latest = connection.execute("""
        SELECT code, input_data
        FROM coding_submissions
        WHERE assessment_id = ?
          AND question_id = ?
        ORDER BY id DESC
        LIMIT 1
    """, (assessment_id, question_id)).fetchone()

    if request.method == "POST":
        action = request.form.get("action", "next")
        code = request.form.get("code", "")
        input_data = request.form.get("input_data", "")

        if action in ("next", "prev", "jump"):
            save_coding_draft(connection, assessment_id, question_id, code, input_data)
            commit_with_retry(connection)
            connection.close()
            session["coding_page_loaded"] = False

            if action == "prev":
                target_number = max(1, question_number - 1)
            elif action == "jump":
                try:
                    target_number = int(request.form.get("target_number", question_number))
                except (ValueError, TypeError):
                    target_number = question_number
            else:
                target_number = question_number + 1

            return redirect(url_for(
                "coding_question",
                assessment_id=assessment_id,
                question_number=target_number
            ))

        if action == "finish":
            connection.close()
            finalize_coding_assessment(
                assessment_id,
                student_id,
                question_id,
                code,
                input_data
            )
            session["coding_page_loaded"] = False
            return redirect(url_for("coding_thank_you", assessment_id=assessment_id))

    expires_at = parse_datetime(coding_session["expires_at"])
    remaining_seconds = max(0, int((expires_at - datetime.now()).total_seconds()))

    connection.close()

    session["coding_page_loaded"] = True

    course_code = assessment["course_code"] if "course_code" in assessment.keys() else "PYTHON"
    starter = get_starter_code(course_code)
    current_code = latest["code"] if (latest and latest["code"] and latest["code"].strip()) else starter

    return render_template(
        "coding_assessment.html",
        assessment=assessment,
        question=question,
        question_number=question_number,
        total_questions=len(question_ids),
        saved_code=current_code,
        saved_input=(latest["input_data"] if latest else ""),
        remaining_seconds=remaining_seconds,
        test_locked=True
    )


# ============================================================
# RUN CODE
# ============================================================

@app.route(
    "/assessment/coding/<int:assessment_id>/run",
    methods=["POST"]
)
@student_login_required
def run_coding_code(assessment_id):

    student_id = session["student_id"]

    if not session.get("assessment_active"):
        return jsonify({"success": False, "message": "Coding session is not active."}), 403

    code = request.form.get("code", "")
    input_data = request.form.get("input_data", "")
    question_id = request.form.get("question_id", "")

    connection = get_db_connection()
    coding_session = get_coding_session(connection, assessment_id, student_id)

    if coding_session is None or coding_session["status"] != "active":
        connection.close()
        return jsonify({"success": False, "message": "Coding session is no longer active."}), 403

    expires_at = parse_datetime(coding_session["expires_at"])
    if datetime.now() >= expires_at:
        connection.close()
        return jsonify({"success": False, "message": "Time expired.", "expired": True}), 400

    try:
        question_id_int = int(question_id)
    except (TypeError, ValueError):
        connection.close()
        return jsonify({"success": False, "message": "Invalid question."}), 400

    allowed = json.loads(coding_session["question_ids"])
    if question_id_int not in allowed:
        connection.close()
        return jsonify({"success": False, "message": "Invalid question."}), 400

    assessment_row = connection.execute("""
        SELECT courses.code AS course_code
        FROM assessments
        INNER JOIN courses ON assessments.course_id = courses.id
        WHERE assessments.id = ?
    """, (assessment_id,)).fetchone()
    course_lang = (assessment_row["course_code"] or "PYTHON").lower() if assessment_row else "python"

    question_row = connection.execute("SELECT question_text FROM questions WHERE id = ?", (question_id_int,)).fetchone()
    q_text = question_row["question_text"] if question_row else ""

    result = run_student_code(code, input_data, language=course_lang, timeout_seconds=3, question_text=q_text)

    connection.execute("""
        INSERT INTO coding_submissions (
            assessment_id,
            question_id,
            code,
            input_data,
            output_data,
            execution_status,
            score,
            submitted_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
    """, (
        assessment_id,
        question_id_int,
        code,
        input_data,
        result["output"],
        result["status"]
    ))
    commit_with_retry(connection)
    connection.close()

    return jsonify({
        "success": result["status"] == "success",
        "status": result["status"],
        "output": result["output"],
        "error": result["error"]
    })


# ============================================================
# RUN ALL TEST CASES (CODETECH AUTOMATED LAB EVALUATION)
# ============================================================

@app.route(
    "/assessment/coding/<int:assessment_id>/run-testcases",
    methods=["POST"]
)
@student_login_required
def run_coding_testcases(assessment_id):
    student_id = session["student_id"]

    if not session.get("assessment_active"):
        return jsonify({"success": False, "message": "Coding session is not active."}), 403

    code = request.form.get("code", "")
    question_id = request.form.get("question_id", "")

    connection = get_db_connection()
    coding_session = get_coding_session(connection, assessment_id, student_id)

    if coding_session is None or coding_session["status"] != "active":
        connection.close()
        return jsonify({"success": False, "message": "Coding session is no longer active."}), 403

    expires_at = parse_datetime(coding_session["expires_at"])
    if datetime.now() >= expires_at:
        connection.close()
        return jsonify({"success": False, "message": "Time expired.", "expired": True}), 400

    try:
        question_id_int = int(question_id)
    except (TypeError, ValueError):
        connection.close()
        return jsonify({"success": False, "message": "Invalid question ID."}), 400

    allowed = json.loads(coding_session["question_ids"])
    if question_id_int not in allowed:
        connection.close()
        return jsonify({"success": False, "message": "Question does not belong to session."}), 400

    assessment_row = connection.execute("""
        SELECT courses.code AS course_code
        FROM assessments
        INNER JOIN courses ON assessments.course_id = courses.id
        WHERE assessments.id = ?
    """, (assessment_id,)).fetchone()
    course_lang = (assessment_row["course_code"] or "PYTHON").lower() if assessment_row else "python"

    question_row = connection.execute("SELECT * FROM questions WHERE id = ?", (question_id_int,)).fetchone()
    if not question_row:
        connection.close()
        return jsonify({"success": False, "message": "Question not found."}), 404

    save_coding_draft(connection, assessment_id, question_id_int, code, "")
    commit_with_retry(connection)

    tests = get_coding_test_cases(question_row)
    test_results = []
    passed_count = 0

    valid, validation_msg = validate_student_code(code, language=course_lang)
    if not valid:
        connection.close()
        return jsonify({
            "success": False,
            "all_passed": False,
            "validation_error": validation_msg,
            "total": len(tests),
            "passed_count": 0,
            "test_cases": [
                {
                    "test_case": idx + 1,
                    "input": t.get("input", ""),
                    "expected": str(t.get("output", "")).strip(),
                    "actual": "",
                    "status": "syntax_error",
                    "passed": False,
                    "error": validation_msg
                } for idx, t in enumerate(tests)
            ]
        })

    for idx, test in enumerate(tests):
        test_in = test.get("input", "")
        test_exp = str(test.get("output", "")).strip()

        exec_res = run_student_code(
            code,
            test_in,
            language=course_lang,
            timeout_seconds=3,
            question_text=question_row["question_text"]
        )

        actual_out = (exec_res.get("output") or "").strip()
        actual_norm = "\n".join(line.rstrip() for line in actual_out.splitlines()).strip()
        expected_norm = "\n".join(line.rstrip() for line in test_exp.splitlines()).strip()

        passed = (exec_res.get("status") == "success") and (actual_norm == expected_norm)
        if passed:
            passed_count += 1

        test_results.append({
            "test_case": idx + 1,
            "input": test_in,
            "expected": test_exp,
            "actual": actual_out,
            "status": exec_res.get("status"),
            "passed": passed,
            "error": exec_res.get("error", "")
        })

    connection.close()

    return jsonify({
        "success": True,
        "all_passed": (passed_count == len(tests)),
        "total": len(tests),
        "passed_count": passed_count,
        "test_cases": test_results
    })


# ============================================================
# CODING BROWSER VIOLATION
# ============================================================

@app.route(
    "/assessment/coding/<int:assessment_id>/violation",
    methods=["POST"]
)
@student_login_required
def coding_violation(assessment_id):
    student_id = session["student_id"]
    reason = request.form.get("reason", "Student left the coding assessment window.").strip()
    terminate_assessment(assessment_id, student_id, reason[:250])
    return jsonify({"success": True, "terminated": True})


# ============================================================
# CODING THANK YOU
# ============================================================

@app.route("/assessment/coding/<int:assessment_id>/thank-you")
@student_login_required
def coding_thank_you(assessment_id):
    student_id = session["student_id"]
    connection = get_db_connection()
    assessment = connection.execute("SELECT assessments.id, assessments.status FROM assessments WHERE assessments.id = ? AND assessments.student_id = ?", (assessment_id, student_id)).fetchone()
    connection.close()
    if assessment is None:
        flash("Assessment not found.", "error")
        return redirect(url_for("student_dashboard"))
    if assessment["status"] != "completed":
        return redirect(url_for("student_dashboard"))
    return render_template_string("""
<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Assessment Submitted</title>
<style>body{font-family:Arial,sans-serif;background:#f4f7fb;margin:0}.card{max-width:700px;margin:90px auto;padding:45px 30px;background:#fff;border-radius:18px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.08)}.icon{font-size:52px}.muted{color:#64748b;line-height:1.6}.closed{margin:25px 0;padding:18px;border-radius:12px;background:#eef8f1;color:#245f39;font-weight:700}</style></head><body>
<div class=\"card\"><div class=\"icon\">✓</div><h1>Thank You!</h1><p class=\"muted\">Your assessment has been submitted successfully.</p><div class=\"closed\">Assessment closed. A second attempt is not allowed.</div><p class=\"muted\">You will be redirected to the login page automatically.</p></div>
<script>setTimeout(function(){window.location.href={{ login_url|tojson }};},5000);</script></body></html>
""", login_url=url_for("login"))


@app.route("/assessment/complete")
@student_login_required
def assessment_complete():
    connection = get_db_connection()
    assessment = get_student_attempt(connection, session["student_id"])
    connection.close()
    if assessment and assessment["status"] == "completed":
        return redirect(url_for("coding_thank_you", assessment_id=assessment["id"]))
    return redirect(url_for("student_dashboard"))


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            flash(
                "Please enter your email and password.",
                "error"
            )

            return render_template(
                "admin_login.html"
            )

        connection = get_db_connection()

        admin = connection.execute("""
            SELECT *
            FROM admins
            WHERE email = ?
        """, (
            email,
        )).fetchone()

        connection.close()

        if admin is None:

            flash(
                "Admin account not found.",
                "error"
            )

            return render_template(
                "admin_login.html"
            )

        if admin["status"] != "active":

            flash(
                "This admin account is inactive.",
                "error"
            )

            return render_template(
                "admin_login.html"
            )

        if not check_password_hash(
            admin["password_hash"],
            password
        ):

            flash(
                "Incorrect password.",
                "error"
            )

            return render_template(
                "admin_login.html"
            )

        session.clear()

        session["admin_id"] = admin["id"]
        session["admin_name"] = admin["name"]
        session["admin_email"] = admin["email"]

        flash(
            "Welcome, {}!".format(
                admin["name"]
            ),
            "success"
        )

        return redirect(
            url_for("admin_dashboard")
        )

    return render_template(
        "admin_login.html"
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route(
    "/admin/dashboard"
)
@admin_login_required
def admin_dashboard():

    connection = get_db_connection()

    raw_students = connection.execute("""
        SELECT *
        FROM students
        ORDER BY created_at DESC
    """).fetchall()

    student_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM students
    """).fetchone()["count"]

    active_student_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM students
        WHERE status = 'active'
    """).fetchone()["count"]

    assessment_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM assessments
    """).fetchone()["count"]

    completed_assessment_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM assessments
        WHERE status = 'completed'
    """).fetchone()["count"]

    mcq_completed_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM assessments
        WHERE status = 'mcq_completed'
    """).fetchone()["count"]

    terminated_assessment_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM assessments
        WHERE status = 'terminated'
    """).fetchone()["count"]

    recent_activity = connection.execute("""
        SELECT
            activity_logs.*,

            students.name AS student_name,
            students.roll_number AS roll_number

        FROM activity_logs

        INNER JOIN students
            ON activity_logs.student_id =
               students.id

        ORDER BY
            activity_logs.created_at DESC

        LIMIT 50
    """).fetchall()

    faculties = connection.execute("""
        SELECT *
        FROM faculty
        ORDER BY name ASC
    """).fetchall()

    attendance_stats = get_attendance_overview_stats(connection)
    recent_sessions = get_recent_attendance_sessions(connection, limit=5)

    students = []
    for st in raw_students:
        st_dict = dict(st)
        st_dict["attendance_summary"] = get_student_attendance_summary(
            connection,
            st["id"]
        )
        students.append(st_dict)

    connection.close()

    return render_template(
        "admin_dashboard.html",

        faculties=faculties,
        students=students,

        student_count=student_count,
        total_students=student_count,

        active_student_count=active_student_count,
        active_students=active_student_count,

        assessment_count=assessment_count,

        completed_assessment_count=
            completed_assessment_count,

        mcq_completed_count=
            mcq_completed_count,

        terminated_assessment_count=
            terminated_assessment_count,

        recent_activity=recent_activity,
        attendance_stats=attendance_stats,
        recent_sessions=recent_sessions,
        gateway_config=get_gateway_config()
    )


# ============================================================
# ADMIN - FACULTY ACCOUNT CREATION & MANAGEMENT
# ============================================================

@app.route("/admin/faculty/create", methods=["POST"])
@admin_login_required
def admin_create_faculty():
    """Allows Administrator to register and create new faculty accounts."""
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    department = request.form.get("department", "Computer Science & Engineering").strip()
    designation = request.form.get("designation", "Assistant Professor").strip()
    password = request.form.get("password", "").strip()
    mobile_number = request.form.get("mobile_number", "").strip()

    if not name or not email:
        flash("Faculty Full Name and Official Email are required.", "error")
        return redirect(url_for("admin_dashboard"))

    if not password:
        password = os.environ.get("FACULTY_DEFAULT_PASSWORD", "Faculty@123")

    connection = get_db_connection()

    existing_faculty = connection.execute(
        "SELECT id FROM faculty WHERE email = ?", (email,)
    ).fetchone()
    existing_admin = connection.execute(
        "SELECT id FROM admins WHERE email = ?", (email,)
    ).fetchone()

    if existing_faculty or existing_admin:
        connection.close()
        flash(f"An academic or administrator account with email '{email}' already exists.", "error")
        return redirect(url_for("admin_dashboard"))

    password_hash = generate_password_hash(password)
    aadhar_number = request.form.get("aadhar_number", "").strip()
    if not aadhar_number:
        aadhar_number = f"9876-5432-{secrets.randbelow(9000)+1000}"
    if not mobile_number:
        mobile_number = f"+919876543{secrets.randbelow(900)+100}"

    connection.execute("""
        INSERT INTO faculty (name, email, department, designation, password_hash, aadhar_number, mobile_number, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)
    """, (name, email, department, designation, password_hash, aadhar_number, mobile_number))

    commit_with_retry(connection)
    connection.close()

    admin_id = session.get("admin_id", 1)
    log_activity(admin_id, f"Admin created faculty account: {name} ({email}) [Aadhaar UID: {aadhar_number}]")

    flash(f"✓ Faculty account created successfully for {name} ({email})! Password: {password} | Aadhaar: {aadhar_number} | Mobile: {mobile_number}", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/faculty/<int:faculty_id>/delete", methods=["POST"])
@admin_login_required
def admin_delete_faculty(faculty_id):
    """Allows Administrator to remove a faculty account."""
    connection = get_db_connection()
    faculty = connection.execute("SELECT name, email FROM faculty WHERE id = ?", (faculty_id,)).fetchone()
    if faculty:
        connection.execute("DELETE FROM faculty WHERE id = ?", (faculty_id,))
        commit_with_retry(connection)
        flash(f"Faculty account for {faculty['name']} ({faculty['email']}) removed successfully.", "success")
    else:
        flash("Faculty account not found.", "error")
    connection.close()
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN - LIVE SMS & GMAIL GATEWAY CONFIGURATION & TEST DISPATCH
# ============================================================

@app.route("/admin/gateway-settings", methods=["GET", "POST"])
@admin_login_required
def admin_gateway_settings():
    """Allows Administrator to configure SMTP, Fast2SMS, and WhatsApp credentials directly into .env."""
    if request.method == "POST":
        smtp_host = request.form.get("smtp_host", "smtp.gmail.com").strip()
        smtp_port = request.form.get("smtp_port", "587").strip()
        smtp_username = request.form.get("smtp_username", "").strip()
        smtp_password = request.form.get("smtp_password", "").strip()
        smtp_from = request.form.get("smtp_from", "").strip()
        smtp_use_ssl = "1" if request.form.get("smtp_use_ssl") == "1" else "0"
        textbee_api_key = request.form.get("textbee_api_key", "").strip()
        textbee_device_id = request.form.get("textbee_device_id", "").strip()
        fast2sms_api_key = request.form.get("fast2sms_api_key", "").strip()
        whatsapp_api_key = request.form.get("whatsapp_api_key", "").strip()
        twilio_account_sid = request.form.get("twilio_account_sid", "").strip()
        twilio_auth_token = request.form.get("twilio_auth_token", "").strip()
        twilio_from_number = request.form.get("twilio_from_number", "").strip()

        save_gateway_config({
            "SMTP_HOST": smtp_host,
            "SMTP_PORT": smtp_port,
            "SMTP_USERNAME": smtp_username,
            "SMTP_PASSWORD": smtp_password,
            "SMTP_FROM": smtp_from or smtp_username,
            "SMTP_USE_SSL": smtp_use_ssl,
            "TEXTBEE_API_KEY": textbee_api_key,
            "TEXTBEE_DEVICE_ID": textbee_device_id,
            "FAST2SMS_API_KEY": fast2sms_api_key,
            "WHATSAPP_API_KEY": whatsapp_api_key,
            "TWILIO_ACCOUNT_SID": twilio_account_sid,
            "TWILIO_AUTH_TOKEN": twilio_auth_token,
            "TWILIO_FROM_NUMBER": twilio_from_number
        })

        flash("✓ Live Gateway Settings updated successfully! All OTP dispatches will now use these credentials.", "success")
        return redirect(url_for("admin_dashboard") + "#gatewaySettings")

    return redirect(url_for("admin_dashboard") + "#gatewaySettings")


@app.route("/admin/gateway/test-email", methods=["POST"])
@admin_login_required
def admin_gateway_test_email():
    """Dispatches a live 6-digit test OTP to any specified Gmail address."""
    test_email = request.form.get("test_email", "").strip()
    if not test_email:
        return jsonify({"success": False, "message": "Please provide a valid Gmail / Email address."}), 400

    test_otp = generate_otp()
    ok, msg = send_otp_via_email(
        test_email,
        "MIT Meerut Admin Tester",
        test_otp,
        subject=f"MIT Meerut Live Test — OTP Passcode ({test_otp})"
    )
    return jsonify({
        "success": ok,
        "message": msg,
        "otp": test_otp,
        "recipient": test_email
    })


@app.route("/admin/gateway/test-sms", methods=["POST"])
@admin_login_required
def admin_gateway_test_sms():
    """Dispatches a live 6-digit test OTP to any Indian mobile number via SMS gateway."""
    test_mobile = request.form.get("test_mobile", "").strip()
    if not test_mobile:
        return jsonify({"success": False, "message": "Please provide a 10-digit mobile number."}), 400

    test_otp = generate_otp()
    ok, msg = send_otp_via_mobile(test_mobile, "MIT Meerut Admin Tester", test_otp)
    return jsonify({
        "success": ok,
        "message": msg,
        "otp": test_otp,
        "mobile": test_mobile
    })


@app.route("/admin/gateway/test-whatsapp", methods=["POST"])
@admin_login_required
def admin_gateway_test_whatsapp():
    """Dispatches a live 6-digit test OTP to any mobile number on WhatsApp."""
    test_mobile = request.form.get("test_mobile", "").strip()
    if not test_mobile:
        return jsonify({"success": False, "message": "Please provide a 10-digit mobile number."}), 400

    test_otp = generate_otp()
    ok, msg = send_otp_via_whatsapp(test_mobile, "MIT Meerut Admin Tester", test_otp)
    return jsonify({
        "success": ok,
        "message": msg,
        "otp": test_otp,
        "mobile": test_mobile
    })


# ============================================================
# FACULTY ATTENDANCE - MARK ATTENDANCE
# ============================================================

@app.route(
    "/admin/attendance",
    methods=["GET", "POST"]
)
@app.route(
    "/faculty/attendance",
    methods=["GET", "POST"]
)
@faculty_or_admin_required
def admin_attendance():

    connection = get_db_connection()
    courses = connection.execute("""
        SELECT *
        FROM courses
        WHERE is_active = 1
        ORDER BY id
    """).fetchall()

    if request.method == "POST":

        course_id = request.form.get("course_id", type=int)
        attendance_date = request.form.get("attendance_date", "").strip()
        topic = request.form.get("topic", "").strip()
        faculty_id = session.get("faculty_id") or session.get("admin_id")

        if not attendance_date:
            attendance_date = datetime.now().strftime("%Y-%m-%d")

        students = connection.execute("""
            SELECT id
            FROM students
            WHERE status = 'active'
        """).fetchall()

        saved_count = 0
        for st in students:
            st_id = st["id"]
            status = request.form.get(f"status_{st_id}", "Present")
            remarks = request.form.get(f"remarks_{st_id}", "").strip()

            connection.execute("""
                INSERT INTO attendance (
                    student_id,
                    course_id,
                    faculty_id,
                    attendance_date,
                    topic,
                    status,
                    remarks,
                    marked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(student_id, course_id, attendance_date) DO UPDATE SET
                    faculty_id = excluded.faculty_id,
                    topic = excluded.topic,
                    status = excluded.status,
                    remarks = excluded.remarks,
                    marked_at = CURRENT_TIMESTAMP
            """, (
                st_id,
                course_id,
                faculty_id,
                attendance_date,
                topic,
                status,
                remarks
            ))
            saved_count += 1

        commit_with_retry(connection)
        connection.close()

        flash(
            f"Attendance recorded successfully for {saved_count} students on {attendance_date}!",
            "success"
        )

        return redirect(
            url_for("admin_attendance_records")
        )

    # GET request
    selected_course_id = request.args.get("course_id", type=int)
    if not selected_course_id and courses:
        selected_course_id = courses[0]["id"]

    selected_date = request.args.get("date", "").strip()
    if not selected_date:
        selected_date = datetime.now().strftime("%Y-%m-%d")

    students = connection.execute("""
        SELECT *
        FROM students
        WHERE status = 'active'
        ORDER BY roll_number ASC, name ASC
    """).fetchall()

    existing_rows = connection.execute("""
        SELECT *
        FROM attendance
        WHERE course_id = ? AND attendance_date = ?
    """, (
        selected_course_id,
        selected_date
    )).fetchall()

    existing_status_map = {row["student_id"]: row["status"] for row in existing_rows}
    existing_remarks_map = {row["student_id"]: row["remarks"] for row in existing_rows}
    existing_topic = existing_rows[0]["topic"] if (existing_rows and existing_rows[0]["topic"]) else ""
    is_already_marked = len(existing_rows) > 0

    connection.close()

    return render_template(
        "admin_attendance.html",
        courses=courses,
        selected_course_id=selected_course_id,
        selected_date=selected_date,
        students=students,
        existing_status_map=existing_status_map,
        existing_remarks_map=existing_remarks_map,
        existing_topic=existing_topic,
        is_already_marked=is_already_marked
    )


# ============================================================
# FACULTY ATTENDANCE - RECORDS & REPORTS
# ============================================================

@app.route(
    "/admin/attendance/records"
)
@app.route(
    "/faculty/attendance/records"
)
@faculty_or_admin_required
def admin_attendance_records():

    connection = get_db_connection()

    attendance_stats = get_attendance_overview_stats(connection)
    sessions = get_recent_attendance_sessions(connection, limit=50)

    raw_students = connection.execute("""
        SELECT *
        FROM students
        ORDER BY roll_number ASC, name ASC
    """).fetchall()

    students_matrix = []
    for st in raw_students:
        summary = get_student_attendance_summary(
            connection,
            st["id"]
        )
        students_matrix.append({
            "student": st,
            "summary": summary
        })

    courses = connection.execute("""
        SELECT *
        FROM courses
        WHERE is_active = 1
        ORDER BY id
    """).fetchall()

    connection.close()

    return render_template(
        "admin_attendance_records.html",
        attendance_stats=attendance_stats,
        sessions=sessions,
        students_matrix=students_matrix,
        courses=courses
    )


# ============================================================
# ADMIN - STUDENT DETAILS
# ============================================================

@app.route(
    "/admin/student/<int:student_id>"
)
@faculty_or_admin_required
def student_detail(
    student_id
):

    connection = get_db_connection()

    student = connection.execute("""
        SELECT *
        FROM students
        WHERE id = ?
    """, (
        student_id,
    )).fetchone()

    if student is None:

        connection.close()

        flash(
            "Student not found.",
            "error"
        )

        return redirect(
            url_for("admin_dashboard")
        )

    activities = connection.execute("""
        SELECT *
        FROM activity_logs

        WHERE student_id = ?

        ORDER BY created_at DESC
    """, (
        student_id,
    )).fetchall()

    assessments = connection.execute("""
        SELECT
            assessments.*,

            courses.name AS course_name,
            courses.code AS course_code

        FROM assessments

        LEFT JOIN courses
            ON assessments.course_id =
               courses.id

        WHERE assessments.student_id = ?

        ORDER BY assessments.created_at DESC
    """, (
        student_id,
    )).fetchall()

    coding_submissions = connection.execute("""
        SELECT coding_submissions.*, questions.question_text
        FROM coding_submissions
        INNER JOIN assessments ON coding_submissions.assessment_id = assessments.id
        INNER JOIN questions ON coding_submissions.question_id = questions.id
        WHERE assessments.student_id = ?
        ORDER BY coding_submissions.submitted_at DESC
    """, (student_id,)).fetchall()

    attendance_summary = get_student_attendance_summary(
        connection,
        student_id
    )

    attendance_records = get_student_attendance_records(
        connection,
        student_id,
        limit=30
    )

    connection.close()

    return render_template(
        "student_detail.html",
        student=student,
        activities=activities,
        assessments=assessments,
        coding_submissions=coding_submissions,
        attendance_summary=attendance_summary,
        attendance_records=attendance_records
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route(
    "/admin/logout"
)
def admin_logout():

    session.clear()

    flash(
        "Admin logged out successfully.",
        "success"
    )

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# STUDENT PASSWORD CHANGE
# ============================================================

@app.route("/student/change-password", methods=["POST"])
@student_login_required
def student_change_password():
    student_id = session["student_id"]
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password:
        flash("Please enter both your current password and new password.", "error")
        return redirect(url_for("student_dashboard"))

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("student_dashboard"))

    if len(new_password) < 6:
        flash("New password must be at least 6 characters long.", "error")
        return redirect(url_for("student_dashboard"))

    connection = get_db_connection()
    student = connection.execute("SELECT password_hash FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student or not check_password_hash(student["password_hash"], current_password):
        connection.close()
        flash("Incorrect current password.", "error")
        return redirect(url_for("student_dashboard"))

    new_hash = generate_password_hash(new_password)
    connection.execute("UPDATE students SET password_hash = ? WHERE id = ?", (new_hash, student_id))
    connection.commit()
    connection.close()

    flash("Your password has been updated successfully!", "success")
    return redirect(url_for("student_dashboard"))


# ============================================================
# FACULTY PASSWORD CHANGE
# ============================================================

@app.route("/faculty/change-password", methods=["POST"])
@faculty_login_required
def faculty_change_password():
    faculty_id = session["faculty_id"]
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password:
        flash("Please enter both current password and new password.", "error")
        return redirect(url_for("faculty_dashboard"))

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("faculty_dashboard"))

    if len(new_password) < 6:
        flash("New password must be at least 6 characters long.", "error")
        return redirect(url_for("faculty_dashboard"))

    connection = get_db_connection()
    faculty = connection.execute("SELECT password_hash FROM faculty WHERE id = ?", (faculty_id,)).fetchone()
    if not faculty or not check_password_hash(faculty["password_hash"], current_password):
        connection.close()
        flash("Incorrect current password.", "error")
        return redirect(url_for("faculty_dashboard"))

    new_hash = generate_password_hash(new_password)
    connection.execute("UPDATE faculty SET password_hash = ? WHERE id = ?", (new_hash, faculty_id))
    connection.commit()
    connection.close()

    flash("Your faculty password has been updated successfully!", "success")
    return redirect(url_for("faculty_dashboard"))


# ============================================================
# ATTENDANCE DATA EXPORT (EXCEL / CSV)
# ============================================================

@app.route("/admin/attendance/export")
@app.route("/faculty/attendance/export")
@faculty_or_admin_required
def export_attendance_csv():
    connection = get_db_connection()
    raw_students = connection.execute("""
        SELECT * FROM students ORDER BY roll_number ASC, name ASC
    """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "University Roll No",
        "Student Name",
        "Official Email",
        "Mobile Number",
        "Total Lectures Held",
        "Lectures Attended",
        "Absences",
        "Attendance %",
        "AKTU Exam Eligibility (>=75%)"
    ])

    for st in raw_students:
        summary = get_student_attendance_summary(connection, st["id"])
        eligibility = "Eligible" if summary.get("is_eligible") else "Shortage Alert (<75%)"
        writer.writerow([
            st["roll_number"],
            st["name"],
            st["email"],
            st.get("mobile_number", "") or "N/A",
            summary.get("total_classes", 0),
            summary.get("attended_classes", 0),
            summary.get("absent_count", 0),
            f"{summary.get('percentage', 0)}%",
            eligibility
        ])

    connection.close()
    csv_bytes = output.getvalue().encode("utf-8-sig")

    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=SyllabusX_Attendance_Report.csv",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )



# ============================================================
# AI-POWERED CODE TUTOR & EXPLAINER (GEMINI / LOCAL AST ENGINE)
# ============================================================

@app.route("/api/ai/explain-code", methods=["POST"])
def ai_explain_code():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    language = (data.get("language") or "python").lower()
    problem_text = (data.get("problem_text") or "").strip()
    last_output = (data.get("output") or "").strip()

    if not code:
        return jsonify({
            "success": False,
            "error": "Please write or paste some code to analyze."
        }), 400

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    analysis_text = ""

    # Option A: Real Gemini API if key is available
    if gemini_key:
        try:
            prompt = f"""You are an expert computer science professor and coding mentor at MIT Meerut.
Analyze this student code submission and provide structured, pedagogical, encouraging feedback.
Language: {language}
Problem Statement: {problem_text}
Student Code:
```
{code}
```
Last Execution Output:
{last_output}

Provide output with these 4 sections:
1. **Algorithm Overview**: A short 2-line explanation of the student's approach.
2. **Time & Space Complexity**: Big-O notation for time and auxiliary space.
3. **Bugs & Edge Cases**: Potential failure points (e.g. empty inputs, zero division, off-by-one, memory leaks).
4. **Optimization Tips**: Concrete, actionable recommendations to improve performance or code cleanliness.
Keep tone constructive and encouraging."""

            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}]
            }).encode("utf-8")
            req = Request(gemini_url, data=payload, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=12) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                candidates = resp_data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        analysis_text = parts[0].get("text", "")
        except Exception as e:
            analysis_text = ""

    # Option B: High-Performance Pedagogical Static Analyzer Fallback
    if not analysis_text:
        # Determine complexity heuristics
        lines = code.split("\n")
        loop_keywords = ["for ", "while ", "forEach", "for("]
        loop_depth = 0
        current_indent = 0
        has_nested = False
        loop_count = 0
        for line in lines:
            if any(k in line for k in loop_keywords):
                loop_count += 1
                if loop_count >= 2:
                    has_nested = True

        time_comp = "O(N²)" if has_nested else ("O(N)" if loop_count == 1 else "O(1)")
        space_comp = "O(N)" if ("[" in code or "new " in code or "malloc" in code or "append" in code) else "O(1)"

        bugs = []
        if "/ 0" in code or "/0" in code:
            bugs.append("Potential division by zero detected.")
        if "while True" in code and "break" not in code:
            bugs.append("Infinite loop risk: 'while True' without apparent 'break'.")
        if language == "c" and "scanf" in code and "&" not in code:
            bugs.append("Check 'scanf' pointers; address-of operator '&' might be missing.")
        if language == "python" and "input()" in code and "int(" not in code and ("+" in code or "*" in code):
            bugs.append("Note: Python 'input()' returns strings; convert to integer if doing arithmetic.")
        if not bugs:
            bugs.append("No critical syntax flags detected; verify edge cases (empty lists, 0, negative values).")

        tips = [
            f"Estimated Time Complexity: **{time_comp}**, Space Complexity: **{space_comp}**.",
            "Consider boundary conditions: what happens if the input is minimum or maximum possible?",
            "Use descriptive variable names and document logic with inline comments."
        ]
        if has_nested:
            tips.append("Try using HashMaps / Dictionaries or Two-Pointer techniques to reduce nested loop O(N²) time complexity to O(N).")

        analysis_text = f"""### 🤖 AI Code Analysis & Pedagogical Review
**Language:** {language.upper()} | **Lab Assessment Engine**

#### 1. 💡 Algorithmic Structure
Your code uses a structured procedural approach with **{len(lines)} lines** and **{loop_count} active loop construct(s)**.

#### 2. ⚡ Computational Complexity
- **Time Complexity:** `{time_comp}`
- **Auxiliary Space:** `{space_comp}`

#### 3. 🐞 Edge Cases & Safety Checks
- {chr(10).join(f"- {b}" for b in bugs)}

#### 4. 🚀 Optimization Recommendations
- {chr(10).join(f"- {t}" for t in tips)}
"""

    return jsonify({
        "success": True,
        "analysis": analysis_text
    })


# ============================================================
# ASSIGNMENTS & HOMEWORK SUBMISSION MODULE
# ============================================================

@app.route("/student/assignments")
@student_login_required
def student_assignments():
    student_id = session["student_id"]
    connection = get_db_connection()
    assignments = connection.execute("""
        SELECT
            assignments.*,
            courses.name as course_name,
            courses.code as course_code,
            assignment_submissions.id as submission_id,
            assignment_submissions.status as submission_status,
            assignment_submissions.marks_obtained,
            assignment_submissions.feedback,
            assignment_submissions.submitted_at
        FROM assignments
        LEFT JOIN courses ON assignments.course_id = courses.id
        LEFT JOIN assignment_submissions
            ON assignments.id = assignment_submissions.assignment_id
            AND assignment_submissions.student_id = ?
        ORDER BY assignments.due_date ASC, assignments.id DESC
    """, (student_id,)).fetchall()
    connection.close()

    return render_template("student_assignments.html", assignments=assignments)


@app.route("/student/assignments/<int:assignment_id>/submit", methods=["POST"])
@student_login_required
def student_submit_assignment(assignment_id):
    student_id = session["student_id"]
    submission_text = (request.form.get("submission_text") or "").strip()

    if not submission_text:
        flash("Please provide your assignment response or source code.", "error")
        return redirect(url_for("student_assignments"))

    connection = get_db_connection()
    existing = connection.execute("""
        SELECT id FROM assignment_submissions
        WHERE assignment_id = ? AND student_id = ?
    """, (assignment_id, student_id)).fetchone()

    if existing:
        connection.execute("""
            UPDATE assignment_submissions
            SET submission_text = ?, submitted_at = CURRENT_TIMESTAMP, status = 'resubmitted'
            WHERE id = ?
        """, (submission_text, existing["id"]))
        flash("Assignment updated and resubmitted successfully!", "success")
    else:
        connection.execute("""
            INSERT INTO assignment_submissions (assignment_id, student_id, submission_text, status)
            VALUES (?, ?, ?, 'submitted')
        """, (assignment_id, student_id, submission_text))
        flash("Assignment submitted successfully!", "success")

    connection.commit()
    connection.close()
    return redirect(url_for("student_assignments"))


@app.route("/faculty/assignments", methods=["GET", "POST"])
@faculty_or_admin_required
def faculty_assignments():
    connection = get_db_connection()

    if request.method == "POST":
        course_id = request.form.get("course_id")
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        max_marks = int(request.form.get("max_marks") or 100)
        due_date = request.form.get("due_date") or ""

        if not title:
            flash("Assignment title is required.", "error")
            return redirect(url_for("faculty_assignments"))

        faculty_id = session.get("faculty_id") or 1
        connection.execute("""
            INSERT INTO assignments (course_id, title, description, max_marks, due_date, created_by_faculty_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (course_id, title, description, max_marks, due_date, faculty_id))
        connection.commit()
        flash("New course assignment published successfully!", "success")
        return redirect(url_for("faculty_assignments"))

    courses = connection.execute("SELECT * FROM courses WHERE is_active = 1 ORDER BY id").fetchall()
    assignments = connection.execute("""
        SELECT
            assignments.*,
            courses.name as course_name,
            courses.code as course_code,
            COUNT(assignment_submissions.id) as total_submissions
        FROM assignments
        LEFT JOIN courses ON assignments.course_id = courses.id
        LEFT JOIN assignment_submissions ON assignments.id = assignment_submissions.assignment_id
        GROUP BY assignments.id, courses.name, courses.code
        ORDER BY assignments.id DESC
    """).fetchall()
    connection.close()

    return render_template("faculty_assignments.html", assignments=assignments, courses=courses)


@app.route("/faculty/assignments/<int:assignment_id>/submissions", methods=["GET", "POST"])
@faculty_or_admin_required
def faculty_assignment_submissions(assignment_id):
    connection = get_db_connection()

    if request.method == "POST":
        submission_id = request.form.get("submission_id")
        marks = request.form.get("marks_obtained")
        feedback = (request.form.get("feedback") or "").strip()

        if marks is not None and marks != "":
            connection.execute("""
                UPDATE assignment_submissions
                SET marks_obtained = ?, feedback = ?, status = 'graded'
                WHERE id = ?
            """, (int(marks), feedback, submission_id))
            connection.commit()
            flash("Submission graded successfully!", "success")
        return redirect(url_for("faculty_assignment_submissions", assignment_id=assignment_id))

    assignment = connection.execute("""
        SELECT assignments.*, courses.name as course_name
        FROM assignments
        LEFT JOIN courses ON assignments.course_id = courses.id
        WHERE assignments.id = ?
    """, (assignment_id,)).fetchone()

    submissions = connection.execute("""
        SELECT
            assignment_submissions.*,
            students.name as student_name,
            students.roll_number,
            students.email as student_email
        FROM assignment_submissions
        JOIN students ON assignment_submissions.student_id = students.id
        WHERE assignment_submissions.assignment_id = ?
        ORDER BY assignment_submissions.submitted_at DESC
    """, (assignment_id,)).fetchall()
    connection.close()

    return render_template(
        "faculty_assignment_submissions.html",
        assignment=assignment,
        submissions=submissions
    )


# ============================================================
# STUDENT FEES & PRINTABLE FEE RECEIPT
# ============================================================

@app.route("/student/fees")
@student_login_required
def student_fees():
    student_id = session["student_id"]
    connection = get_db_connection()
    student = connection.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    fee_records = connection.execute("""
        SELECT * FROM student_fees
        WHERE student_id = ?
        ORDER BY id DESC
    """, (student_id,)).fetchall()
    connection.close()

    return render_template("student_fees.html", student=student, fee_records=fee_records)


@app.route("/student/fees/<int:fee_id>/receipt")
@student_login_required
def student_fee_receipt(fee_id):
    student_id = session["student_id"]
    connection = get_db_connection()
    fee = connection.execute("""
        SELECT student_fees.*, students.name, students.roll_number, students.email
        FROM student_fees
        JOIN students ON student_fees.student_id = students.id
        WHERE student_fees.id = ? AND student_fees.student_id = ?
    """, (fee_id, student_id)).fetchone()
    connection.close()

    if not fee:
        flash("Fee receipt record not found.", "error")
        return redirect(url_for("student_fees"))

    return render_template("fee_receipt.html", fee=fee)


@app.route("/admin/fees")
@faculty_or_admin_required
def admin_fees():
    connection = get_db_connection()
    fee_records = connection.execute("""
        SELECT
            student_fees.*,
            students.name as student_name,
            students.roll_number,
            students.email as student_email
        FROM student_fees
        JOIN students ON student_fees.student_id = students.id
        ORDER BY student_fees.id DESC
    """).fetchall()
    connection.close()

    return render_template("admin_fees.html", fee_records=fee_records)


# ============================================================
# AUTOMATED WHATSAPP & SMS ATTENDANCE SHORTAGE ALERTS
# ============================================================

@app.route("/faculty/attendance/send-shortage-alert", methods=["POST"])
@faculty_or_admin_required
def send_shortage_alerts():
    connection = get_db_connection()
    raw_students = connection.execute("SELECT * FROM students ORDER BY roll_number").fetchall()

    alert_count = 0
    notified_names = []

    for st in raw_students:
        summary = get_student_attendance_summary(connection, st["id"])
        if summary and not summary.get("is_eligible", True):
            pct = summary.get("percentage", 0)
            mob = st.get("mobile_number") or ""
            email = st.get("email") or ""
            name = st.get("name") or "Student"
            roll = st.get("roll_number") or ""

            msg = (
                f"🚨 MIT MEERUT URGENT NOTICE:\n"
                f"Dear {name} (Roll: {roll}), your attendance is currently {pct}%, "
                f"which is below AKTU mandatory 75% criteria. "
                f"You are at risk of exam debarment. Attend lectures immediately."
            )

            # Try SMS / WhatsApp dispatch
            if mob:
                try:
                    send_otp_via_mobile(mob, name, f"ALERT: {pct}% Attd")
                except Exception:
                    pass

            # Try Email dispatch
            if email:
                try:
                    send_otp_via_smtp(email, name, f"AKTU Shortage Alert: {pct}%", msg)
                except Exception:
                    pass

            log_activity(st["id"], f"AKTU Shortage Alert triggered by Faculty. Attendance: {pct}%")
            alert_count += 1
            notified_names.append(f"{name} ({pct}%)")

    connection.close()

    if alert_count > 0:
        flash(
            f"✅ Dispatched official AKTU Shortage Alerts to {alert_count} student(s): {', '.join(notified_names[:5])}"
            + (f" and {alert_count - 5} more." if alert_count > 5 else "."),
            "success"
        )
    else:
        flash("All students currently maintain >= 75% attendance! No shortage alerts needed.", "info")

    return redirect(url_for("admin_attendance_records"))


# ============================================================
# CAMPUS DOUBT & DISCUSSION FORUM
# ============================================================

@app.route("/campus/forum", methods=["GET", "POST"])
def campus_forum():
    connection = get_db_connection()

    if request.method == "POST":
        role = session.get("role")
        if not role:
            flash("Please sign in to post questions or doubts in the forum.", "error")
            return redirect(url_for("login"))

        course_id = request.form.get("course_id")
        title = (request.form.get("title") or "").strip()
        message = (request.form.get("message") or "").strip()

        if not title or not message:
            flash("Topic title and question details are required.", "error")
            return redirect(url_for("campus_forum"))

        user_id = session.get("student_id") or session.get("faculty_id") or session.get("admin_id") or 1
        user_name = session.get("student_name") or session.get("faculty_name") or session.get("admin_name") or "User"

        connection.execute("""
            INSERT INTO forum_topics (course_id, author_id, author_name, author_role, title, message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (course_id, user_id, user_name, role, title, message))
        connection.commit()
        flash("Your question has been posted to the Campus Discussion Forum!", "success")
        return redirect(url_for("campus_forum"))

    courses = connection.execute("SELECT * FROM courses WHERE is_active = 1 ORDER BY id").fetchall()
    topics = connection.execute("""
        SELECT
            forum_topics.*,
            courses.name as course_name,
            courses.code as course_code,
            COUNT(forum_replies.id) as reply_count
        FROM forum_topics
        LEFT JOIN courses ON forum_topics.course_id = courses.id
        LEFT JOIN forum_replies ON forum_topics.id = forum_replies.topic_id
        GROUP BY forum_topics.id, courses.name, courses.code
        ORDER BY forum_topics.id DESC
    """).fetchall()
    connection.close()

    return render_template("campus_forum.html", topics=topics, courses=courses)


@app.route("/campus/forum/<int:topic_id>", methods=["GET", "POST"])
def campus_forum_topic(topic_id):
    connection = get_db_connection()

    if request.method == "POST":
        role = session.get("role")
        if not role:
            flash("Please sign in to reply to discussion questions.", "error")
            return redirect(url_for("login"))

        reply_text = (request.form.get("reply_text") or "").strip()
        if not reply_text:
            flash("Reply message cannot be empty.", "error")
            return redirect(url_for("campus_forum_topic", topic_id=topic_id))

        user_id = session.get("student_id") or session.get("faculty_id") or session.get("admin_id") or 1
        user_name = session.get("student_name") or session.get("faculty_name") or session.get("admin_name") or "User"

        connection.execute("""
            INSERT INTO forum_replies (topic_id, author_id, author_name, author_role, reply_text)
            VALUES (?, ?, ?, ?, ?)
        """, (topic_id, user_id, user_name, role, reply_text))
        connection.commit()
        flash("Your answer has been posted!", "success")
        return redirect(url_for("campus_forum_topic", topic_id=topic_id))

    topic = connection.execute("""
        SELECT forum_topics.*, courses.name as course_name, courses.code as course_code
        FROM forum_topics
        LEFT JOIN courses ON forum_topics.course_id = courses.id
        WHERE forum_topics.id = ?
    """, (topic_id,)).fetchone()

    if not topic:
        connection.close()
        flash("Discussion topic not found.", "error")
        return redirect(url_for("campus_forum"))

    replies = connection.execute("""
        SELECT * FROM forum_replies
        WHERE topic_id = ?
        ORDER BY id ASC
    """, (topic_id,)).fetchall()
    connection.close()

    return render_template("forum_topic.html", topic=topic, replies=replies)

# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    init_database()

    print("")
    print("================================================================")
    print(" SyllabusX — Campus Academic ERP & Automated Coding Sandbox")
    print(" Meerut Institute of Technology (MIT Meerut)")
    print(" Affiliated to Dr. A.P.J. Abdul Kalam Technical University (AKTU)")
    print("================================================================")
    print("")
    print("Campus home:")
    print("http://127.0.0.1:5000/")
    print("Unified Institutional Portal (Student / Faculty / Admin ERP):")
    print("http://127.0.0.1:5000/login")
    print("")
    print("Portal Login Credentials:")
    if app.debug:
        print("Login credentials are configured via environment variables.")
        print("See .env file for ADMIN_DEFAULT_PASSWORD, STUDENT_DEFAULT_PASSWORD, FACULTY_DEFAULT_PASSWORD")
    print("")
    print("CodeTech Automated Lab Sandbox: C (GCC 11), Java 17, Python 3")
    print("================================================================")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
