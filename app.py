import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, flash, g, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; env vars can still be set another way

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CTF_DATABASE", BASE_DIR / "ctf.db"))
UPLOADS_DIR = BASE_DIR / "uploads"
FLAG_IDOR = os.environ.get("FLAG_IDOR", "flag{1d0r_1s_n3v3r_tru5t_th3_cl13nt}")
FLAG_DIRLIST = os.environ.get("FLAG_DIRLIST", "flag{d1r3ct0ry_l1st1ng_l34ks_s3cr3ts}")
FLAG_XSS = os.environ.get("FLAG_XSS", "flag{st0r3d_xss_runs_in_someone_elses_browser}")
FLAG_OSINT = os.environ.get("FLAG_OSINT", "flag{kushal}")
ORGANIZER_KEY = os.environ.get("CTF_ORGANIZER_KEY", "alokishrestha123")

CHALLENGES = {
    "idor": {"name": "Profile Pivot", "points": 100, "flag": FLAG_IDOR},
    "dirlisting": {"name": "Quiet Directories", "points": 100, "flag": FLAG_DIRLIST},
    "xss": {"name": "Shared Scribbles", "points": 100, "flag": FLAG_XSS},
    "osint": {"name": "Secretary Search", "points": 100, "flag": FLAG_OSINT},
}

app = Flask(__name__)
app.secret_key = os.environ.get("CTF_SECRET_KEY", secrets.token_hex(32))
app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
NEPAL_TIMEZONE = timezone(timedelta(hours=5, minutes=45), name="NPT")


def get_db():
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'player',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS solves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            challenge_key TEXT NOT NULL REFERENCES challenges(key),
            submitted_at TEXT NOT NULL,
            UNIQUE(user_id, challenge_key)
        );
        CREATE TABLE IF NOT EXISTS first_bloods (
            challenge_key TEXT PRIMARY KEY REFERENCES challenges(key),
            user_id INTEGER NOT NULL REFERENCES users(id),
            solve_id INTEGER NOT NULL UNIQUE REFERENCES solves(id),
            claimed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id),
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS challenges (
            key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            points INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_solves_user_id ON solves(user_id);
        CREATE INDEX IF NOT EXISTS idx_solves_challenge_time ON solves(challenge_key, submitted_at, id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at, id);
    """)
    for key, challenge in CHALLENGES.items():
        db.execute("INSERT OR IGNORE INTO challenges(key, name, points) VALUES (?, ?, ?)", (key, challenge["name"], challenge["points"]))
    if db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None:
        now = datetime.now(NEPAL_TIMEZONE).isoformat(timespec="seconds")
        db.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, 'organizer', ?)", ("organizer", generate_password_hash(secrets.token_urlsafe(24)), now))
    db.commit()
    db.close()
    UPLOADS_DIR.joinpath("profile").mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.joinpath("secrets").mkdir(parents=True, exist_ok=True)
    default_image = UPLOADS_DIR / "profile" / "default.svg"
    if not default_image.exists():
        default_image.write_text("<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><rect width='160' height='160' fill='#16383a'/><circle cx='80' cy='63' r='28' fill='#72e0bf'/><path d='M28 145c9-42 95-42 104 0' fill='#72e0bf'/></svg>", encoding="ascii")
    flag_file = UPLOADS_DIR / "secrets" / "flag.txt"
    if not flag_file.exists():
        flag_file.write_text(FLAG_DIRLIST, encoding="ascii")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def organizer_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "organizer":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def nepal_now():
    return datetime.now(NEPAL_TIMEZONE).isoformat(timespec="seconds")


def record_audit(event_type, details, actor_user_id=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs(actor_user_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
        (actor_user_id, event_type, details, nepal_now()),
    )


def record_solve(user_id, challenge_key):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        submitted_at = nepal_now()
        solve = db.execute(
            "INSERT INTO solves(user_id, challenge_key, submitted_at) VALUES (?, ?, ?) RETURNING id",
            (user_id, challenge_key, submitted_at),
        ).fetchone()
        db.execute(
            "INSERT OR IGNORE INTO first_bloods(challenge_key, user_id, solve_id, claimed_at) VALUES (?, ?, ?, ?)",
            (challenge_key, user_id, solve["id"], submitted_at),
        )
        record_audit("solve", f"{CHALLENGES[challenge_key]['name']} accepted", user_id)
        db.commit()
        first_blood = db.execute(
            "SELECT solve_id FROM first_bloods WHERE challenge_key = ?", (challenge_key,)
        ).fetchone()["solve_id"] == solve["id"]
        return True, first_blood
    except sqlite3.IntegrityError:
        db.rollback()
        return False, False


def solve_state(user_id):
    rows = get_db().execute("SELECT challenge_key FROM solves WHERE user_id = ?", (user_id,)).fetchall()
    return {row["challenge_key"] for row in rows}


@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 32 or not username.replace("_", "").isalnum():
            flash("Use 3-32 letters, numbers, or underscores.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            try:
                cursor = get_db().execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, 'player', ?)", (username, generate_password_hash(password), nepal_now()))
                record_audit("account_created", f"Player account created: {username}", cursor.lastrowid)
                get_db().commit()
                flash("Account created. Log in to enter the arena.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                get_db().rollback()
                flash("That handle is already taken.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"])
            return redirect(url_for("dashboard"))
        flash("Invalid handle or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for("dashboard_for_user", requested_id=session["user_id"]))


@app.route("/dashboard/<int:requested_id>")
@login_required
def dashboard_for_user(requested_id):
    try:
        requested_id = int(requested_id)
    except (TypeError, ValueError):
        abort(404)
    target = get_db().execute("SELECT id, username, role FROM users WHERE id = ?", (requested_id,)).fetchone()
    if target is None:
        abort(404)
    if target["role"] == "organizer":
        return render_template("admin_dashboard.html", target=target, flag=FLAG_IDOR)
    return render_template("dashboard.html", target=target, is_self=requested_id == session["user_id"])


@app.route("/api/xss-flag")
@login_required
def api_xss_flag():
    # Deliberately NOT embedded anywhere in dashboard.html's markup or inline
    # scripts. A player must get their own injected payload to execute in an
    # authenticated browser to reach this page - viewing page source or
    # curling /dashboard gives them nothing. Plain text (not JSON) so the
    # simplest possible payload is just a page redirect, no fetch needed.
    return Response(FLAG_XSS, mimetype="text/plain")


@app.route("/hint")
@login_required
def hint():
    return render_template("hint.html")


@app.route("/notes")
@login_required
def notes_page():
    # Private to the logged-in user only - each player has their own list,
    # so a payload one player writes only ever renders in their own browser.
    # This keeps the XSS challenge fully self-contained and stops it from
    # leaking into the IDOR challenge via a shared /dashboard/<id> feed.
    notes = get_db().execute(
        "SELECT id, content, user_id, created_at FROM notes WHERE user_id = ? ORDER BY id DESC LIMIT 50",
        (session["user_id"],),
    ).fetchall()
    return render_template("notes.html", notes=notes)


@app.route("/notes", methods=["POST"])
@login_required
def create_note():
    content = request.form.get("content", "").strip()
    if not content or len(content) > 2000:
        flash("A note must contain 1-2000 characters.", "error")
    else:
        db = get_db()
        cursor = db.execute("INSERT INTO notes(user_id, content, created_at) VALUES (?, ?, ?)", (session["user_id"], content, nepal_now()))
        record_audit("note_created", f"Note #{cursor.lastrowid} created", session["user_id"])
        db.commit()
        flash("Note saved.", "success")
    return redirect(url_for("notes_page"))


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    note = db.execute("SELECT id, user_id FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)
    if note["user_id"] != session["user_id"]:
        abort(403)
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    record_audit("note_deleted", f"Note #{note_id} deleted", session["user_id"])
    db.commit()
    flash("Note deleted.", "success")
    return redirect(url_for("notes_page"))


@app.route("/files/")
@app.route("/files/<path:subpath>")
@login_required
def files(subpath=""):
    requested = (UPLOADS_DIR / subpath).resolve()
    if UPLOADS_DIR.resolve() not in requested.parents and requested != UPLOADS_DIR.resolve():
        abort(403)
    if requested.is_dir():
        relative = requested.relative_to(UPLOADS_DIR).as_posix()
        entries = []
        for item in sorted(requested.iterdir()):
            entries.append({"name": item.name + ("/" if item.is_dir() else ""), "size": "-" if item.is_dir() else f"{item.stat().st_size} B"})
        parent = str(Path(relative).parent).replace(".", "") or None
        return render_template("directory_listing.html", path=f"/files/{relative}" if relative else "/files/", entries=entries, parent=parent)
    if requested.is_file():
        return send_from_directory(requested.parent, requested.name)
    abort(404)


@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    if request.method == "POST":
        submitted = request.form.get("flag", "").strip()
        challenge_key = next((key for key, item in CHALLENGES.items() if item["flag"] == submitted), None)
        if challenge_key:
            accepted, first_blood = record_solve(session["user_id"], challenge_key)
            if accepted:
                flash(f"Accepted: {CHALLENGES[challenge_key]['name']}.", "success")
                if first_blood:
                    flash("First blood! You are first on this challenge.", "success")
            else:
                flash("Already solved. Your original time remains on the board.", "success")
        else:
            flash("That flag is not accepted.", "error")
        return redirect(url_for("submit"))
    return render_template("submit.html", challenges=CHALLENGES, solved=solve_state(session["user_id"]))


@app.route("/leaderboard")
def leaderboard():
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    page_size = 50
    total_players = get_db().execute("SELECT COUNT(*) FROM users WHERE role = 'player'").fetchone()[0]
    total_pages = max(1, (total_players + page_size - 1) // page_size)
    page = min(page, total_pages)
    rows = get_db().execute("""
            SELECT u.id AS user_id, u.username, COUNT(s.id) AS solved, COALESCE(SUM(c.points), 0) AS score,
             MIN(s.submitted_at) AS first_solve,
             MAX(CASE WHEN s.challenge_key = 'idor' THEN s.submitted_at END) AS idor_solved_at,
             MAX(CASE WHEN s.challenge_key = 'dirlisting' THEN s.submitted_at END) AS dirlisting_solved_at,
             MAX(CASE WHEN s.challenge_key = 'xss' THEN s.submitted_at END) AS xss_solved_at,
             MAX(CASE WHEN s.challenge_key = 'osint' THEN s.submitted_at END) AS osint_solved_at
        FROM users u LEFT JOIN solves s ON s.user_id = u.id
        LEFT JOIN challenges c ON c.key = s.challenge_key
        WHERE u.role = 'player' GROUP BY u.id ORDER BY score DESC, first_solve ASC, u.username ASC
        LIMIT ? OFFSET ?
    """, (page_size, (page - 1) * page_size)).fetchall()
    first_blood = get_db().execute("SELECT user_id FROM solves ORDER BY id LIMIT 1").fetchone()
    first_blood_user_id = first_blood["user_id"] if first_blood else None
    return render_template("leaderboard.html", rows=rows, challenges=CHALLENGES, first_blood_user_id=first_blood_user_id, page=page, total_pages=total_pages)


@app.route("/control", methods=["GET", "POST"])
def control():
    if request.method == "POST":
        if secrets.compare_digest(request.form.get("organizer_key", ""), ORGANIZER_KEY):
            session.update(role="organizer", username="organizer")
            user = get_db().execute("SELECT id FROM users WHERE username='organizer'").fetchone()
            session["user_id"] = user["id"]
            return redirect(url_for("control"))
        flash("Organizer key rejected.", "error")
    if session.get("role") != "organizer":
        return render_template("control_login.html")
    stats = get_db().execute("SELECT c.name, c.points, COUNT(s.id) AS solves FROM challenges c LEFT JOIN solves s ON s.challenge_key=c.key GROUP BY c.key").fetchall()
    recent = get_db().execute("SELECT u.username, c.name, s.submitted_at FROM solves s JOIN users u ON u.id=s.user_id JOIN challenges c ON c.key=s.challenge_key ORDER BY s.id DESC LIMIT 25").fetchall()
    logs = get_db().execute("SELECT a.event_type, a.details, a.created_at, COALESCE(u.username, 'system') AS actor FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT 100").fetchall()
    return render_template("control.html", stats=stats, recent=recent, logs=logs)


@app.context_processor
def inject_event():
    return {"event_name": os.environ.get("CTF_EVENT_NAME", "Nimbus Notes // Beginner Arena")}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
