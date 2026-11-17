import os
import re
import secrets
import hmac
import logging
from datetime import timedelta

import psycopg2
from psycopg2 import errors as pg_errors
from flask import (
    Flask, request, redirect, url_for,
    session, render_template, abort, jsonify, flash, get_flashed_messages
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Set SECRET_KEY and DATABASE_URL in Vercel Environment Variables.
ON_VERCEL = os.environ.get("VERCEL") == "1"

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if ON_VERCEL:
        raise RuntimeError("SECRET_KEY environment variable is not set.")
    SECRET_KEY = "local-development-only-change-me"

DATABASE_URL = os.environ.get("DATABASE_URL")

app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,
    MAX_CONTENT_LENGTH=64 * 1024,
)

logging.basicConfig(level=logging.INFO)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MIN_PASSWORD = 8
MAX_PASSWORD = 128

DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


# ---------------- DATABASE (Neon) ----------------

def run_query(sql, params=(), one=False):
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")

    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                if cur.description:
                    return cur.fetchone() if one else cur.fetchall()
                return None
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(30) NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
    ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS feedback (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name       VARCHAR(100) NOT NULL,
    phone      VARCHAR(30)  NOT NULL,
    message    TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
"""

_schema_ready = False


@app.before_request
def ensure_schema():
    global _schema_ready
    if not _schema_ready:
        run_query(SCHEMA)
        _schema_ready = True


@app.errorhandler(psycopg2.Error)
def handle_db_error(error):
    app.logger.exception("Database error: %s", error)
    return "Service temporarily unavailable. Please try again.", 503


# ---------------- SECURITY ----------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf():
    submitted = request.form.get("csrf_token", "")
    stored = session.get("csrf_token", "")

    if not stored or not hmac.compare_digest(submitted, stored):
        abort(400, description="Invalid form security token.")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# ---------------- ROUTES ----------------

def login_user(user_id, username):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username


def consume_auth_messages():
    """Return one-time success messages for the shared login/signup page."""
    return get_flashed_messages(with_categories=True)


@app.route("/")
def home():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    return render_template(
        "main.html",
        username=session.get("username"),
        csrf_token=get_csrf_token()
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("home"))

    error = None
    username = ""

    if request.method == "POST":
        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not USERNAME_RE.match(username):
            error = ("Username must be 3-30 characters: letters, "
                     "numbers and underscore only.")
        elif len(password) < MIN_PASSWORD:
            error = "Password must be at least 8 characters."
        elif len(password) > MAX_PASSWORD:
            error = "Password is too long."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                run_query(
                    "INSERT INTO users (username, password_hash) "
                    "VALUES (%s, %s)",
                    (username, generate_password_hash(password))
                )
                # Do not sign the new user in here. They must authenticate
                # through the login form after successful registration.
                flash("Registration successful! Please log in with your new account.", "success")
                return redirect(url_for("login"))
            except pg_errors.UniqueViolation:
                error = "That username is already taken. Try another."

    return render_template(
        "auth.html",
        mode="signup",
        error=error,
        username=username,
        csrf_token=get_csrf_token(),
        messages=consume_auth_messages()
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    error = None
    username = ""

    if request.method == "POST":
        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = run_query(
            "SELECT id, username, password_hash FROM users "
            "WHERE LOWER(username) = LOWER(%s)",
            (username,),
            one=True
        )

        if row:
            valid = check_password_hash(row[2], password)
        else:
            check_password_hash(DUMMY_HASH, password)
            valid = False

        if valid:
            login_user(row[0], row[1])
            return redirect(url_for("home"))

        error = "Invalid username or password. Please try again."

    return render_template(
        "auth.html",
        mode="login",
        error=error,
        username=username,
        csrf_token=get_csrf_token(),
        messages=consume_auth_messages()
    )


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/feedback", methods=["POST"])
def feedback():
    if not session.get("user_id"):
        return jsonify(error="Please log in again."), 401

    check_csrf()

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    message = request.form.get("message", "").strip()

    if not name or not phone or not message:
        return jsonify(error="Please fill in all fields."), 400

    if len(name) > 100 or len(phone) > 30 or len(message) > 2000:
        return jsonify(error="One of the fields is too long."), 400

    run_query(
        "INSERT INTO feedback (user_id, name, phone, message) "
        "VALUES (%s, %s, %s, %s)",
        (session["user_id"], name, phone, message)
    )

    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=True)
