from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
import json
import random
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import subprocess
import sys
import tempfile
import ast

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)
app.secret_key = "college-assessment-secret-key-change-later"

# ============================================================
# DATABASE
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "assessment.db")


def get_db_connection():
    os.makedirs(DATABASE_DIR, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


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
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return any(row["name"] == column_name for row in rows)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():

    connection = get_db_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # STUDENTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    # ADMINS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    """)

    # --------------------------------------------------------
    # ACTIVITY LOGS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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

    # --------------------------------------------------------
    # CODING SUBMISSIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS coding_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    admin_password = "Admin@123"

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
        print("Password: Admin@123")

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

    connection.commit()
    connection.close()


# ============================================================
# LOGIN REQUIRED DECORATORS
# ============================================================

def student_login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "student_id" not in session:

            flash(
                "Please login as a student first.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


def admin_login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "admin_id" not in session:

            flash(
                "Please login as admin/teacher first.",
                "error"
            )

            return redirect(
                url_for("admin_login")
            )

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

    connection.commit()
    connection.close()


# ============================================================
# TERMINATE ASSESSMENT
# ============================================================

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

    connection.commit()
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
    student_id
):

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
# HOME
# ============================================================

@app.route("/")
def index():

    if "student_id" in session:

        return redirect(
            url_for("student_dashboard")
        )

    if "admin_id" in session:

        return redirect(
            url_for("admin_dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# STUDENT LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

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
                "login.html"
            )

        connection = get_db_connection()

        student = connection.execute("""
            SELECT *
            FROM students
            WHERE email = ?
        """, (
            email,
        )).fetchone()

        if student is None:

            connection.close()

            flash(
                "No student account found with this email. Please register.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if student["status"] != "active":

            connection.close()

            flash(
                "Your student account is currently inactive.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            student["password_hash"],
            password
        ):

            connection.close()

            flash(
                "Incorrect password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        connection.execute("""
            UPDATE students
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            student["id"],
        ))

        connection.commit()
        connection.close()

        session.clear()

        session["student_id"] = student["id"]
        session["student_name"] = student["name"]
        session["student_email"] = student["email"]

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

    return render_template(
        "login.html"
    )


# ============================================================
# STUDENT REGISTRATION
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        roll_number = request.form.get(
            "roll_number",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not name:

            flash(
                "Please enter your name.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if not roll_number:

            flash(
                "Please enter your roll number.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if not email:

            flash(
                "Please enter your college email.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if not password:

            flash(
                "Please enter a password.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )

        connection = get_db_connection()

        existing_email = connection.execute("""
            SELECT id
            FROM students
            WHERE email = ?
        """, (
            email,
        )).fetchone()

        if existing_email:

            connection.close()

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )

        existing_roll = connection.execute("""
            SELECT id
            FROM students
            WHERE roll_number = ?
        """, (
            roll_number,
        )).fetchone()

        if existing_roll:

            connection.close()

            flash(
                "This roll number is already registered.",
                "error"
            )

            return render_template(
                "register.html"
            )

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            connection.execute("""
                INSERT INTO students (
                    name, roll_number, email, password_hash, created_at, status
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                name, roll_number, email, generate_password_hash(password),
                created_at, "active"
            ))
        except sqlite3.IntegrityError:
            connection.rollback()
            connection.close()
            flash("Registration failed. The email or roll number may already exist.", "error")
            return render_template("register.html")

        connection.commit()
        connection.close()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# STUDENT DASHBOARD
# ============================================================

@app.route(
    "/student/dashboard"
)
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

    connection.close()

    return render_template(
        "student_dashboard.html",
        student=student,
        assessment=assessment
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
    connection = get_db_connection()
    existing = get_student_attempt(connection, student_id)
    connection.close()

    if existing:
        status = existing["status"]
        # IMPORTANT: restore the assessment context before the Start button is used.
        session["assessment_id"] = existing["id"]
        session["course_id"] = existing["course_id"]

        if status in ("completed", "terminated", "disqualified", "cancelled"):
            flash("Your assessment attempt is already closed. A second attempt is not allowed.", "error")
            return redirect(url_for("student_dashboard"))
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
        ORDER BY name
    """).fetchall()

    existing = get_student_attempt(
        connection,
        student_id
    )

    # Once the MCQ/coding test starts or closes,
    # course changing is not allowed.
    if existing and existing["status"] in (
        "mcq", "mcq_active", "mcq_completed", "coding", "coding_active",
        "completed", "terminated", "disqualified", "cancelled"
    ):

        connection.close()

        flash(
            "Your assessment has already started or closed. "
            "You cannot select another course.",
            "error"
        )

        return redirect(
            url_for("student_dashboard")
        )

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

        # Reuse the same attempt before MCQ starts.
        if existing:

            assessment_id = existing["id"]

            connection.execute("""
                UPDATE assessments

                SET course_id = ?

                WHERE id = ?
                  AND student_id = ?
                  AND status = 'instructions'
            """, (
                course_id,
                assessment_id,
                student_id
            ))

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

        connection.commit()
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

    if request.method == "GET" and session.get("mcq_page_loaded"):
        connection.close()
        terminate_assessment(assessment_id, student_id, "MCQ page refresh, back navigation, or duplicate entry detected.")
        session.clear()
        flash("Assessment terminated because the MCQ test page was refreshed or left.", "error")
        return redirect(url_for("login"))

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

        connection.commit()

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

    if selected_answer not in (
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

    connection.commit()
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
# SUBMIT MCQ
# ============================================================

@app.route(
    "/assessment/mcq/<int:assessment_id>/submit",
    methods=["GET", "POST"]
)
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

    connection.commit()
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
# CODING CODE SAFETY CHECK
# ============================================================

def validate_student_code(code):
    """
    Basic safety gate before running student code.

    Student code is NEVER executed with exec() or eval().
    It is run as a separate Python subprocess with a short timeout.
    """

    if not code or not code.strip():
        return False, "Please enter Python code first."

    if len(code) > 15000:
        return False, "Code is too large. Maximum allowed size is 15,000 characters."

    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        return False, "Syntax error: {}".format(exc)

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
                    return False, "Import '{}' is not allowed in the coding test.".format(root)

        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in forbidden_imports:
                return False, "Import '{}' is not allowed in the coding test.".format(root)

        elif isinstance(node, ast.Name) and node.id in forbidden_names:
            return False, "'{}' is not allowed in the coding test.".format(node.id)

        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            return False, "Dunder attributes are not allowed in the coding test."

    return True, ""


def run_student_code(code, input_data, timeout_seconds=3):
    """Run student code in a separate process with strict basic limits."""

    valid, message = validate_student_code(code)
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

    with tempfile.TemporaryDirectory(prefix="college_code_") as temp_dir:
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
                "error": "Execution time exceeded 3 seconds.",
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
            courses.coding_duration_minutes
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
            valid, validation_message = validate_student_code(code)
            if valid:
                all_passed = True
                for test in tests:
                    result = run_student_code(code, test["input"], timeout_seconds=3)
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

    connection.commit()
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

    if request.method == "GET" and session.get("coding_page_loaded"):
        connection.close()
        terminate_assessment(assessment_id, student_id, "Coding page refresh, back navigation, or duplicate entry detected.")
        session.clear()
        flash("Assessment terminated because the coding test page was refreshed or left.", "error")
        return redirect(url_for("login"))

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

        connection.commit()
        coding_session = connection.execute("""
            SELECT * FROM coding_sessions WHERE id = ?
        """, (coding_session_id,)).fetchone()

        session["assessment_active"] = True
        session["assessment_id"] = assessment_id
        session["coding_session_id"] = coding_session_id
        session["coding_entry_token"] = secrets.token_urlsafe(32)
        session["coding_instance_token"] = secrets.token_urlsafe(32)

        log_activity(student_id, "Started Python coding assessment")

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

        if action == "next":
            save_coding_draft(connection, assessment_id, question_id, code, input_data)
            connection.commit()
            connection.close()
            session["coding_page_loaded"] = False

            next_number = question_number + 1
            return redirect(url_for(
                "coding_question",
                assessment_id=assessment_id,
                question_number=next_number
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

    return render_template(
        "coding_assessment.html",
        assessment=assessment,
        question=question,
        question_number=question_number,
        total_questions=len(question_ids),
        saved_code=(latest["code"] if latest else ""),
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

    result = run_student_code(code, input_data, timeout_seconds=3)

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
    connection.commit()
    connection.close()

    return jsonify({
        "success": result["status"] == "success",
        "status": result["status"],
        "output": result["output"],
        "error": result["error"]
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

    students = connection.execute("""
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

    connection.close()

    return render_template(
        "admin_dashboard.html",

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

        recent_activity=recent_activity
    )


# ============================================================
# ADMIN - STUDENT DETAILS
# ============================================================

@app.route(
    "/admin/student/<int:student_id>"
)
@admin_login_required
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

    connection.close()

    return render_template(
        "student_detail.html",
        student=student,
        activities=activities,
        assessments=assessments,
        coding_submissions=coding_submissions
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
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    init_database()

    print("")
    print("==============================================")
    print(" College Assessment Website")
    print("==============================================")
    print("")

    print("Student Login:")
    print("http://127.0.0.1:5000/login")
    print("")

    print("Student Registration:")
    print("http://127.0.0.1:5000/register")
    print("")

    print("Admin Login:")
    print("http://127.0.0.1:5000/admin/login")
    print("")

    print("Demo Admin:")
    print("Email: admin@college.edu")
    print("Password: Admin@123")
    print("")

    print("==============================================")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
