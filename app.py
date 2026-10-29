"""
MEDIQ Hospital ERP: Smart Hospital Management and Online Appointment Booking
============================================================================
EDUCATIONAL DEMONSTRATION. Not for real patient data without a full security,
privacy and regulatory review.

How the file is organised (read it top to bottom):
  1. Setup & database helpers
  2. Security helpers (CSRF, login, roles)
  3. Validation helpers
  4. Appointment / slot logic
  5. Public & authentication routes
  6. Patient routes
  7. Doctor routes
  8. Shared appointment actions (cancel, status)
  9. Administrator routes
"""
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config, DEFAULT_SECRET, DEMO_REGISTRY

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# =============================================================================
# 1. SETUP & DATABASE HELPERS
# =============================================================================
app = Flask(__name__)
app.config.from_object(Config)

SLOT_STATUSES_SQL = "('Booked','Confirmed','Completed')"   # statuses that occupy a slot
VERIFICATION_STATUSES = ("Pending", "Verified", "Requires Review", "Rejected")
GENDERS = ("Female", "Male", "Other", "Prefer not to say")
DATE_FMT = "%Y-%m-%d"
DT_FMT = "%Y-%m-%d %H:%M"


def connect(path):
    """Open an SQLite connection with foreign keys ON.
    isolation_level=None lets us control transactions ourselves (BEGIN/COMMIT)."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row            # access columns by name
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignores foreign keys unless asked
    return conn


def init_db(path):
    """Create all tables (safe to run many times: uses IF NOT EXISTS)."""
    conn = connect(path)
    with open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.close()


def get_db():
    """One database connection per request, stored in Flask's `g`."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def transaction(db):
    """All-or-nothing database changes.
    BEGIN IMMEDIATE locks the database for writing straight away, so two people
    booking the same slot at the same moment are handled one after the other."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def audit(db, action, entity_type, entity_id=None, user_id=None):
    """Write an audit-log entry (who did what)."""
    if user_id is None and g.get("user") is not None:
        user_id = g.user["id"]
    db.execute(
        "INSERT INTO audit_logs (user_id, action, entity_type, entity_id) VALUES (?, ?, ?, ?)",
        (user_id, action, entity_type, entity_id),
    )


def notify(db, user_id, message, ntype, appointment_id=None):
    """Create an in-app notification.
    EXTENSION POINT: to add email/SMS later, call your provider inside
    deliver_external(). No real email or SMS is sent in this prototype."""
    db.execute(
        "INSERT INTO notifications (user_id, appointment_id, message, notification_type) VALUES (?, ?, ?, ?)",
        (user_id, appointment_id, message, ntype),
    )
    deliver_external(user_id, message, ntype)


def deliver_external(user_id, message, ntype):
    """Placeholder for email / SMS delivery. Intentionally does nothing."""
    return None


if app.config["MEDIQ_ENV"] == "production" and app.config["SECRET_KEY"] == DEFAULT_SECRET:
    raise RuntimeError("Set a strong SECRET_KEY environment variable before running in production.")
init_db(app.config["DATABASE"])


# =============================================================================
# 2. SECURITY HELPERS: CSRF, sessions, role-based access
# =============================================================================
def csrf_token():
    """A random token stored in the session and placed in every form."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token   # usable in every template and macro


@app.before_request
def load_user_and_check_csrf():
    if request.endpoint == "static":
        return
    # 1) Who is logged in? (re-checked on every request so deactivated users are locked out)
    g.user = None
    uid = session.get("user_id")
    if uid:
        row = get_db().execute(
            "SELECT id, full_name, email, role FROM users WHERE id = ? AND is_active = 1", (uid,)
        ).fetchone()
        if row:
            g.user = row
        else:
            session.clear()
    # 2) CSRF protection for every state-changing request
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Your form expired or was invalid. Please go back, refresh the page and try again.")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"   # don't cache private pages
    return response


@app.context_processor
def inject_globals():
    """Variables available in every template."""
    unread = 0
    if g.get("user") is not None:
        unread = get_db().execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (g.user["id"],)
        ).fetchone()[0]
    return {"user": g.get("user"), "unread_count": unread, "csrf_token": csrf_token,
            "demo_mode": current_app.config["SHOW_DEMO_CREDENTIALS"],
            "cancel_hours": current_app.config["CANCELLATION_NOTICE_HOURS"]}


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def role_required(*roles):
    """Allow only the listed roles; everybody else gets an 'Access denied' page."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def safe_next(target, fallback):
    """Only follow redirects that stay on this website (prevents open redirects)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return fallback


def start_session(user_id):
    session.clear()                 # new session = protection against session fixation
    session["user_id"] = user_id
    session.permanent = True


DUMMY_HASH = generate_password_hash("not-a-real-password")


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_error(error):
    code = getattr(error, "code", 500) or 500
    titles = {400: "Bad request", 403: "Access denied", 404: "Page not found",
              405: "Method not allowed", 500: "Something went wrong"}
    messages = {403: "You do not have permission to open this page.",
                404: "We could not find the page you asked for.",
                405: "That action is not allowed here.",
                500: "An unexpected error occurred. Please try again later."}
    message = messages.get(code) or getattr(error, "description", "") or "Please try again."
    return render_template("error.html", code=code, title=titles.get(code, "Error"), message=message), code


# =============================================================================
# 3. VALIDATION HELPERS
# =============================================================================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")
NAME_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ .'\-]){1,99}$")
IDENT_RE = re.compile(r"^[A-Z]{2}-[0-9]{6}$")          # e.g. MQ-100001
POLICY_RE = re.compile(r"^[A-Z0-9\-]{6,20}$")           # e.g. DC-2024-0001
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def valid_password(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters long."
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        return "Password must contain at least one letter and one number."
    return None


def parse_date(text):
    try:
        return datetime.strptime(text, DATE_FMT).date()
    except (ValueError, TypeError):
        return None


def normalize_phone(raw):
    return re.sub(r"[\s\-()]", "", raw or "")


def check_insurance(provider, policy, errors):
    """Insurance is optional, but provider and policy reference go together."""
    if provider and not policy:
        errors.append("Insurance policy reference is required when an insurance provider is given.")
    elif policy and not provider:
        errors.append("Insurance provider is required when a policy reference is given.")
    elif policy and not POLICY_RE.match(policy):
        errors.append("Insurance policy reference must be 6-20 letters, digits or hyphens (e.g. DC-2024-0001).")
    if len(provider) > 100:
        errors.append("Insurance provider name is too long.")


def clean_patient_form(form, registering=True):
    """Return (cleaned_values, errors) for the patient registration / profile forms."""
    get = lambda k: " ".join(form.get(k, "").split()) if k not in ("medical_history", "registration_symptoms", "address") else form.get(k, "").strip()
    f = {
        "full_name": get("full_name"), "email": get("email").lower(),
        "date_of_birth": get("date_of_birth"), "gender": get("gender"),
        "phone": normalize_phone(form.get("phone", "")), "address": get("address"),
        "patient_identifier": get("patient_identifier").upper(),
        "insurance_provider": get("insurance_provider"),
        "insurance_policy_reference": get("insurance_policy_reference").upper(),
        "registration_symptoms": get("registration_symptoms"), "medical_history": get("medical_history"),
    }
    errors = []
    if registering:
        if not f["full_name"]:
            errors.append("Full name is required.")
        elif not NAME_RE.match(f["full_name"]):
            errors.append("Full name may contain only letters, spaces, dots, hyphens and apostrophes.")
        if not f["email"]:
            errors.append("Email address is required.")
        elif not EMAIL_RE.match(f["email"]):
            errors.append("Please enter a valid email address (for example name@example.com).")
        dob = parse_date(f["date_of_birth"])
        if not f["date_of_birth"]:
            errors.append("Date of birth is required.")
        elif dob is None:
            errors.append("Date of birth is not a valid date.")
        elif dob > date.today():
            errors.append("Date of birth cannot be in the future.")
        elif (date.today() - dob).days > 120 * 365:
            errors.append("Date of birth is not realistic (over 120 years ago).")
        if f["patient_identifier"] and not IDENT_RE.match(f["patient_identifier"]):
            errors.append("Patient identifier must look like MQ-100001 (2 letters, hyphen, 6 digits).")
    if not f["phone"]:
        errors.append("Phone number is required.")
    elif not PHONE_RE.match(f["phone"]):
        errors.append("Phone number must contain 7-15 digits (a leading + is allowed).")
    if f["gender"] and f["gender"] not in GENDERS:
        errors.append("Please choose a gender from the list, or leave it blank.")
    if len(f["address"]) > 300:
        errors.append("Address is too long (maximum 300 characters).")
    for key, label in (("registration_symptoms", "Symptoms"), ("medical_history", "Medical history")):
        if len(f[key]) > 2000:
            errors.append(f"{label} is too long (maximum 2000 characters).")
    check_insurance(f["insurance_provider"], f["insurance_policy_reference"], errors)
    return f, errors


def run_demo_verification(f):
    """SIMULATED verification using local demo data only.
    It never contacts a government, insurer or hospital system.
    Insurance is NEVER auto-approved: it always goes to human review."""
    ident = f["patient_identifier"]
    has_insurance = bool(f["insurance_provider"])
    if ident:
        record = DEMO_REGISTRY.get(ident)
        if record is None:
            return "Requires Review", "Identifier was not found in the demonstration registry. Staff review needed."
        same_name = " ".join(record[0].split()).casefold() == f["full_name"].casefold()
        if not (same_name and record[1] == f["date_of_birth"]):
            return "Requires Review", "Name or date of birth does not match the demonstration registry record."
        if has_insurance:
            return "Requires Review", ("Identity matched the demonstration registry. Insurance cannot be "
                                       "verified automatically and needs human review.")
        return "Verified", "Name, date of birth and identifier matched the demonstration registry (simulated check)."
    if has_insurance:
        return "Requires Review", "No patient identifier given; insurance details need human review."
    return "Pending", "No patient identifier given; waiting for staff review."


# =============================================================================
# 4. APPOINTMENT / SLOT LOGIC
# =============================================================================
class BookingError(Exception):
    """Raised when a booking rule is broken (message is shown to the user)."""


@app.template_filter("pretty_date")
def pretty_date(value):
    d = parse_date(value)
    return d.strftime("%a %d %b %Y") if d else value


@app.template_filter("age")
def age_filter(value):
    d = parse_date(value)
    if not d:
        return ""
    today = date.today()
    return today.year - d.year - ((today.month, today.day) < (d.month, d.day))


def parse_dt(d, t):
    return datetime.strptime(f"{d} {t}", DT_FMT)


def build_slots(start, end, minutes):
    """Cut a time window into consultation slots, e.g. 09:00-10:00 / 30 -> 09:00, 09:30."""
    cur = datetime.strptime(start, "%H:%M")
    stop = datetime.strptime(end, "%H:%M")
    step = timedelta(minutes=minutes)
    slots = []
    while cur + step <= stop:
        slots.append((cur.strftime("%H:%M"), (cur + step).strftime("%H:%M")))
        cur += step
    return slots


def free_slots_range(db, doctor_id, minutes, d0, d1):
    """Return {date: [{'start','end'}, ...]} of still-free future slots between two dates."""
    windows = db.execute(
        "SELECT available_date, start_time, end_time FROM doctor_availability "
        "WHERE doctor_id = ? AND is_available = 1 AND available_date BETWEEN ? AND ? "
        "ORDER BY available_date, start_time", (doctor_id, d0, d1)).fetchall()
    busy = {}
    for r in db.execute(
            f"SELECT appointment_date, start_time, end_time FROM appointments "
            f"WHERE doctor_id = ? AND status IN {SLOT_STATUSES_SQL} AND appointment_date BETWEEN ? AND ?",
            (doctor_id, d0, d1)):
        busy.setdefault(r["appointment_date"], []).append((r["start_time"], r["end_time"]))
    now = datetime.now()
    result = {}
    for w in windows:
        day = w["available_date"]
        for s, e in build_slots(w["start_time"], w["end_time"], minutes):
            if parse_dt(day, s) <= now:
                continue                                    # slot already started
            if any(s < be and e > bs for bs, be in busy.get(day, [])):
                continue                                    # overlaps another appointment
            result.setdefault(day, []).append({"start": s, "end": e})
    return result


def validate_slot(db, doctor, day, start, ignore_appointment_id=None):
    """BACKEND check that a slot can really be booked. Returns the slot's end time.
    Must be called inside a transaction so the answer cannot change before we insert."""
    if not doctor or not doctor["is_active"] or not doctor["department_active"]:
        raise BookingError("This doctor is not currently accepting appointments.")
    d = parse_date(day)
    if d is None or not TIME_RE.match(start or ""):
        raise BookingError("Invalid date or time.")
    windows = db.execute(
        "SELECT start_time, end_time FROM doctor_availability "
        "WHERE doctor_id = ? AND available_date = ? AND is_available = 1", (doctor["id"], day)).fetchall()
    end = None
    for w in windows:
        for s, e in build_slots(w["start_time"], w["end_time"], doctor["consultation_duration"]):
            if s == start:
                end = e
    if end is None:
        raise BookingError("That time is not an available slot for this doctor.")
    if parse_dt(day, start) <= datetime.now():
        raise BookingError("That time has already passed.")
    clash = db.execute(
        f"SELECT 1 FROM appointments WHERE doctor_id = ? AND appointment_date = ? "
        f"AND status IN {SLOT_STATUSES_SQL} AND start_time < ? AND end_time > ? AND id != ?",
        (doctor["id"], day, end, start, ignore_appointment_id or -1)).fetchone()
    if clash:
        raise BookingError("Sorry, that slot has just been taken. Please choose another time.")
    return end


def check_patient_free(db, patient_id, day, start, end, ignore_appointment_id=None):
    clash = db.execute(
        "SELECT 1 FROM appointments WHERE patient_id = ? AND appointment_date = ? "
        "AND status IN ('Booked','Confirmed') AND start_time < ? AND end_time > ? AND id != ?",
        (patient_id, day, end, start, ignore_appointment_id or -1)).fetchone()
    if clash:
        raise BookingError("You already have another appointment at that time.")


APPT_SELECT = """
    SELECT a.*, pu.full_name AS patient_name, pu.id AS patient_user_id,
           du.full_name AS doctor_name, du.id AS doctor_user_id,
           dep.department_name, d.specialty
    FROM appointments a
    JOIN patients p     ON p.id = a.patient_id
    JOIN users pu       ON pu.id = p.user_id
    JOIN doctors d      ON d.id = a.doctor_id
    JOIN users du       ON du.id = d.user_id
    JOIN departments dep ON dep.id = d.department_id
"""


def can_cancel(appt, role):
    """Cancellation rules: only Booked/Confirmed appointments can be cancelled.
    Patients must cancel at least CANCELLATION_NOTICE_HOURS before the start time."""
    if appt["status"] not in ("Booked", "Confirmed"):
        return False
    if role == "patient":
        notice = timedelta(hours=current_app.config["CANCELLATION_NOTICE_HOURS"])
        return parse_dt(appt["appointment_date"], appt["start_time"]) - datetime.now() >= notice
    return True


def decorate(rows, role):
    out = []
    now = datetime.now()
    for r in rows:
        a = dict(r)
        a["started"] = parse_dt(a["appointment_date"], a["start_time"]) <= now
        a["can_cancel"] = can_cancel(a, role)
        a["can_reschedule"] = role == "patient" and a["can_cancel"]
        out.append(a)
    return out


def patient_for(db, user_id):
    return db.execute("SELECT * FROM patients WHERE user_id = ?", (user_id,)).fetchone()


def doctor_for(db, user_id):
    return db.execute(
        "SELECT d.*, dep.department_name, dep.is_active AS department_active "
        "FROM doctors d JOIN departments dep ON dep.id = d.department_id WHERE d.user_id = ?",
        (user_id,)).fetchone()


def get_doctor(db, doctor_id):
    return db.execute(
        "SELECT d.*, u.full_name, dep.department_name, dep.is_active AS department_active "
        "FROM doctors d JOIN users u ON u.id = d.user_id "
        "JOIN departments dep ON dep.id = d.department_id WHERE d.id = ?", (doctor_id,)).fetchone()


def booking_allowed(patient):
    status = patient["verification_status"]
    if status == "Verified":
        return True
    return current_app.config["ALLOW_UNVERIFIED_BOOKING"] and status != "Rejected"


# =============================================================================
# 5. PUBLIC & AUTHENTICATION ROUTES
# =============================================================================
@app.route("/")
def index():
    db = get_db()
    departments = db.execute(
        "SELECT dep.id, dep.department_name, dep.description, COUNT(d.id) AS doctor_count "
        "FROM departments dep LEFT JOIN doctors d ON d.department_id = dep.id AND d.is_active = 1 "
        "WHERE dep.is_active = 1 GROUP BY dep.id ORDER BY dep.department_name").fetchall()
    doctor_total = db.execute("SELECT COUNT(*) FROM doctors WHERE is_active = 1").fetchone()[0]
    return render_template("index.html", departments=departments, doctor_total=doctor_total)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        # Always run a hash check so the response time does not reveal if the email exists
        password_ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)
        if row and row["is_active"] and password_ok:
            target = safe_next(request.args.get("next"), url_for("dashboard"))
            start_session(row["id"])
            audit(db, "login", "user", row["id"], user_id=row["id"])
            flash(f"Welcome back, {row['full_name']}!", "success")
            return redirect(target)
        flash("Invalid email or password.", "danger")      # same message for every failure
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        audit(get_db(), "logout", "user", g.user["id"])
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for({"patient": "patient_dashboard", "doctor": "doctor_dashboard",
                             "admin": "admin_dashboard"}[g.user["role"]]))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    form, errors = {}, []
    if request.method == "POST":
        db = get_db()
        form, errors = clean_patient_form(request.form, registering=True)
        password, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")
        pw_error = valid_password(password)
        if pw_error:
            errors.append(pw_error)
        elif password != confirm:
            errors.append("The two passwords do not match.")
        if not errors:   # duplicate checks
            if db.execute("SELECT 1 FROM users WHERE email = ?", (form["email"],)).fetchone():
                errors.append("An account with this email already exists. Please log in instead.")
            if form["patient_identifier"] and db.execute(
                    "SELECT 1 FROM patients WHERE patient_identifier = ?", (form["patient_identifier"],)).fetchone():
                errors.append("This patient identifier is already registered.")
            if db.execute(
                    "SELECT 1 FROM patients p JOIN users u ON u.id = p.user_id "
                    "WHERE lower(u.full_name) = lower(?) AND p.date_of_birth = ?",
                    (form["full_name"], form["date_of_birth"])).fetchone():
                errors.append("A patient with the same name and date of birth is already registered. "
                              "Please contact the hospital front desk.")
        if not errors:
            status, note = run_demo_verification(form)
            try:
                with transaction(db):
                    uid = db.execute(
                        "INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'patient')",
                        (form["full_name"], form["email"], generate_password_hash(password))).lastrowid
                    pid = db.execute(
                        "INSERT INTO patients (user_id, date_of_birth, gender, phone, address, patient_identifier, "
                        "insurance_provider, insurance_policy_reference, medical_history, registration_symptoms, "
                        "verification_status, verification_note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (uid, form["date_of_birth"], form["gender"] or None, form["phone"], form["address"] or None,
                         form["patient_identifier"] or None, form["insurance_provider"] or None,
                         form["insurance_policy_reference"] or None, form["medical_history"] or None,
                         form["registration_symptoms"] or None, status, note)).lastrowid
                    notify(db, uid, "Welcome to MEDIQ! Your registration was received.", "registration")
                    notify(db, uid, f"Your verification status is: {status}. {note}", "verification")
                    audit(db, "patient_registered", "patient", pid, user_id=uid)
                start_session(uid)
                flash(f"Registration successful. Verification status: {status}.", "success")
                return redirect(url_for("patient_dashboard"))
            except sqlite3.IntegrityError:
                errors.append("This email, patient identifier or patient record is already registered.")
    return render_template("register.html", f=form, errors=errors, genders=GENDERS, registry=DEMO_REGISTRY)


@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    db = get_db()
    if request.method == "POST":
        db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (g.user["id"],))
        return redirect(url_for("notifications"))
    items = db.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100",
                       (g.user["id"],)).fetchall()
    return render_template("notifications.html", items=items)


@app.route("/doctors")
def doctor_availability():
    """Public doctor directory with live availability, search and filters."""
    db = get_db()
    q = request.args.get("q", "").strip()
    dept = request.args.get("department", "").strip()
    specialty = request.args.get("specialty", "").strip()
    day = request.args.get("date", "").strip()
    avail = request.args.get("availability", "").strip()
    sql = ("SELECT d.*, u.full_name, dep.department_name FROM doctors d JOIN users u ON u.id = d.user_id "
           "JOIN departments dep ON dep.id = d.department_id "
           "WHERE d.is_active = 1 AND u.is_active = 1 AND dep.is_active = 1")
    params = []
    if q:
        sql += " AND u.full_name LIKE ?"
        params.append(f"%{q}%")
    if dept.isdigit():
        sql += " AND d.department_id = ?"
        params.append(int(dept))
    if specialty:
        sql += " AND d.specialty = ?"
        params.append(specialty)
    doctors = db.execute(sql + " ORDER BY u.full_name", params).fetchall()

    today = date.today()
    if day and parse_date(day):
        d0 = d1 = day
    else:
        day = ""
        d0, d1 = today.strftime(DATE_FMT), (today + timedelta(days=current_app.config["BOOKING_WINDOW_DAYS"])).strftime(DATE_FMT)
    cards = []
    for doc in doctors:
        slots = free_slots_range(db, doc["id"], doc["consultation_duration"], d0, d1)
        has_slots = bool(slots)
        if avail == "available" and not has_slots or avail == "unavailable" and has_slots:
            continue
        cards.append({"doc": doc, "slots": slots, "available": has_slots})
    departments = db.execute("SELECT id, department_name FROM departments WHERE is_active = 1 ORDER BY department_name").fetchall()
    specialties = [r[0] for r in db.execute("SELECT DISTINCT specialty FROM doctors WHERE is_active = 1 ORDER BY specialty")]
    return render_template("doctor_availability.html", cards=cards, departments=departments, specialties=specialties,
                           filters={"q": q, "department": dept, "specialty": specialty, "date": day, "availability": avail},
                           today=today.strftime(DATE_FMT))


# =============================================================================
# 6. PATIENT ROUTES
# =============================================================================
@app.route("/patient/dashboard")
@role_required("patient")
def patient_dashboard():
    db = get_db()
    patient = patient_for(db, g.user["id"])
    today = date.today().strftime(DATE_FMT)
    upcoming = decorate(db.execute(
        APPT_SELECT + " WHERE a.patient_id = ? AND a.status IN ('Booked','Confirmed') AND a.appointment_date >= ? "
        "ORDER BY a.appointment_date, a.start_time LIMIT 5", (patient["id"], today)).fetchall(), "patient")
    recent = db.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 5", (g.user["id"],)).fetchall()
    return render_template("patient_dashboard.html", patient=patient, upcoming=upcoming, recent=recent,
                           can_book=booking_allowed(patient))


@app.route("/patient/profile", methods=["GET", "POST"])
@role_required("patient")
def patient_profile():
    db = get_db()
    patient = patient_for(db, g.user["id"])
    errors = []
    if request.method == "POST":
        f, errors = clean_patient_form(request.form, registering=False)
        if not errors:
            old = (patient["insurance_provider"] or "", patient["insurance_policy_reference"] or "")
            new = (f["insurance_provider"], f["insurance_policy_reference"])
            status, note = patient["verification_status"], patient["verification_note"]
            insurance_changed = old != new and f["insurance_provider"]
            if insurance_changed:       # insurance is never auto-approved
                status, note = "Requires Review", "Insurance details were changed and need human review."
            with transaction(db):
                db.execute(
                    "UPDATE patients SET gender=?, phone=?, address=?, insurance_provider=?, "
                    "insurance_policy_reference=?, medical_history=?, registration_symptoms=?, "
                    "verification_status=?, verification_note=?, updated_at=datetime('now') WHERE id=?",
                    (f["gender"] or None, f["phone"], f["address"] or None, f["insurance_provider"] or None,
                     f["insurance_policy_reference"] or None, f["medical_history"] or None,
                     f["registration_symptoms"] or None, status, note, patient["id"]))
                audit(db, "patient_profile_updated", "patient", patient["id"])
                if insurance_changed:
                    notify(db, g.user["id"], "Your insurance details changed, so your profile is now 'Requires Review'.", "verification")
                    audit(db, "verification_changed", "patient", patient["id"])
            flash("Profile updated.", "success")
            return redirect(url_for("patient_profile"))
        patient = dict(patient)
        patient.update({k: f[k] for k in ("gender", "phone", "address", "insurance_provider",
                                          "insurance_policy_reference", "medical_history",
                                          "registration_symptoms")})
    # Only records the doctor has explicitly shared with the patient
    records = db.execute(
        "SELECT m.*, u.full_name AS doctor_name FROM medical_records m "
        "LEFT JOIN doctors d ON d.id = m.doctor_id LEFT JOIN users u ON u.id = d.user_id "
        "WHERE m.patient_id = ? AND m.visible_to_patient = 1 ORDER BY m.created_at DESC",
        (patient["id"],)).fetchall()
    return render_template("patient_profile.html", patient=patient, errors=errors, records=records, genders=GENDERS)


@app.route("/patient/appointments")
@role_required("patient")
def patient_appointments():
    db = get_db()
    patient = patient_for(db, g.user["id"])
    rows = decorate(db.execute(APPT_SELECT + " WHERE a.patient_id = ? ORDER BY a.appointment_date DESC, a.start_time DESC",
                               (patient["id"],)).fetchall(), "patient")
    now = datetime.now()
    upcoming = [a for a in rows if a["status"] in ("Booked", "Confirmed") and parse_dt(a["appointment_date"], a["end_time"]) >= now]
    upcoming.reverse()
    previous = [a for a in rows if a not in upcoming]
    return render_template("patient_appointments.html", upcoming=upcoming, previous=previous)


@app.route("/book/<int:doctor_id>", methods=["GET", "POST"])
@role_required("patient")
def book(doctor_id):
    db = get_db()
    patient = patient_for(db, g.user["id"])
    doctor = get_doctor(db, doctor_id)
    if doctor is None or not doctor["is_active"]:
        abort(404)
    allowed = booking_allowed(patient)
    if request.method == "POST":
        day, start = request.form.get("date", ""), request.form.get("start_time", "")
        try:
            if not allowed:
                raise BookingError("Only verified patients can book appointments. Your status is: "
                                   f"{patient['verification_status']}.")
            with transaction(db):
                end = validate_slot(db, doctor, day, start)
                check_patient_free(db, patient["id"], day, start, end)
                appt_id = db.execute(
                    "INSERT INTO appointments (patient_id, doctor_id, appointment_date, start_time, end_time, status) "
                    "VALUES (?, ?, ?, ?, ?, 'Booked')", (patient["id"], doctor["id"], day, start, end)).lastrowid
                when = f"{pretty_date(day)} at {start}"
                notify(db, g.user["id"], f"Appointment booked with {doctor['full_name']} on {when}.", "booking", appt_id)
                notify(db, doctor["user_id"], f"New appointment: {g.user['full_name']} on {when}.", "booking", appt_id)
                audit(db, "appointment_created", "appointment", appt_id)
            flash(f"Appointment confirmed with {doctor['full_name']} on {when}.", "success")
            return redirect(url_for("patient_appointments"))
        except BookingError as err:
            flash(str(err), "danger")
        except sqlite3.IntegrityError:   # the database's unique index caught a double booking
            flash("Sorry, that slot has just been taken. Please choose another time.", "danger")
        return redirect(url_for("book", doctor_id=doctor_id, date=day))
    return render_template("book_appointment.html", doctor=doctor, reschedule=None, can_book=allowed,
                           patient=patient, **slot_picker_context(db, doctor, request.args.get("date", "")))


def slot_picker_context(db, doctor, selected):
    """Days that still have free slots (next N days) and the slots of the chosen day."""
    today = date.today()
    d0 = today.strftime(DATE_FMT)
    d1 = (today + timedelta(days=current_app.config["BOOKING_WINDOW_DAYS"])).strftime(DATE_FMT)
    by_day = free_slots_range(db, doctor["id"], doctor["consultation_duration"], d0, d1)
    days = [(d, len(s)) for d, s in sorted(by_day.items())]
    if selected not in by_day:
        selected = days[0][0] if days else ""
    return {"days": days, "selected": selected, "slots": by_day.get(selected, [])}


@app.route("/appointments/<int:appt_id>/reschedule", methods=["GET", "POST"])
@role_required("patient")
def reschedule(appt_id):
    db = get_db()
    patient = patient_for(db, g.user["id"])
    appt = db.execute(APPT_SELECT + " WHERE a.id = ? AND a.patient_id = ?", (appt_id, patient["id"])).fetchone()
    if appt is None:
        abort(404)
    appt = decorate([appt], "patient")[0]
    if not appt["can_reschedule"]:
        flash(f"This appointment can no longer be rescheduled (changes must be made at least "
              f"{current_app.config['CANCELLATION_NOTICE_HOURS']} hours before the start).", "warning")
        return redirect(url_for("patient_appointments"))
    doctor = get_doctor(db, appt["doctor_id"])
    if request.method == "POST":
        day, start = request.form.get("date", ""), request.form.get("start_time", "")
        try:
            with transaction(db):
                end = validate_slot(db, doctor, day, start, ignore_appointment_id=appt_id)
                check_patient_free(db, patient["id"], day, start, end, ignore_appointment_id=appt_id)
                db.execute("UPDATE appointments SET appointment_date=?, start_time=?, end_time=?, status='Booked' WHERE id=?",
                           (day, start, end, appt_id))
                when = f"{pretty_date(day)} at {start}"
                notify(db, g.user["id"], f"Appointment rescheduled to {when} with {doctor['full_name']}.", "reschedule", appt_id)
                notify(db, doctor["user_id"], f"{g.user['full_name']} rescheduled to {when}.", "reschedule", appt_id)
                audit(db, "appointment_rescheduled", "appointment", appt_id)
            flash(f"Appointment rescheduled to {when}.", "success")
            return redirect(url_for("patient_appointments"))
        except BookingError as err:
            flash(str(err), "danger")
        except sqlite3.IntegrityError:
            flash("Sorry, that slot has just been taken. Please choose another time.", "danger")
        return redirect(url_for("reschedule", appt_id=appt_id, date=day))
    return render_template("book_appointment.html", doctor=doctor, reschedule=appt, can_book=True, patient=patient,
                           **slot_picker_context(db, doctor, request.args.get("date", "")))


# =============================================================================
# 7. DOCTOR ROUTES
# =============================================================================
@app.route("/doctor/dashboard")
@role_required("doctor")
def doctor_dashboard():
    db = get_db()
    doctor = doctor_for(db, g.user["id"])
    today = date.today()
    t0 = today.strftime(DATE_FMT)
    t1 = (today + timedelta(days=6)).strftime(DATE_FMT)
    q = APPT_SELECT + " WHERE a.doctor_id = ? "
    today_list = decorate(db.execute(q + "AND a.appointment_date = ? ORDER BY a.start_time", (doctor["id"], t0)).fetchall(), "doctor")
    week_rows = decorate(db.execute(q + "AND a.appointment_date > ? AND a.appointment_date <= ? AND a.status != 'Cancelled' "
                                    "ORDER BY a.appointment_date, a.start_time", (doctor["id"], t0, t1)).fetchall(), "doctor")
    week = {}
    for a in week_rows:
        week.setdefault(a["appointment_date"], []).append(a)
    history = decorate(db.execute(q + "AND (a.appointment_date < ? OR a.status IN ('Completed','Cancelled')) "
                                  "ORDER BY a.appointment_date DESC, a.start_time DESC LIMIT 30", (doctor["id"], t0)).fetchall(), "doctor")
    return render_template("doctor_dashboard.html", doctor=doctor, today_list=today_list, week=week,
                           history=history, today=t0)


@app.route("/doctor/schedule", methods=["GET", "POST"])
@role_required("doctor")
def doctor_schedule():
    db = get_db()
    doctor = doctor_for(db, g.user["id"])
    errors = []
    if request.method == "POST":
        day, start, end = request.form.get("available_date", ""), request.form.get("start_time", ""), request.form.get("end_time", "")
        d = parse_date(day)
        if d is None or d < date.today():
            errors.append("Choose a valid date that is today or later.")
        if not (TIME_RE.match(start) and TIME_RE.match(end)):
            errors.append("Start and end times are required (HH:MM).")
        elif start >= end:
            errors.append("End time must be after the start time.")
        elif len(build_slots(start, end, doctor["consultation_duration"])) == 0:
            errors.append(f"The window must be at least {doctor['consultation_duration']} minutes long (one consultation).")
        if not errors:
            try:
                with transaction(db):
                    overlap = db.execute("SELECT 1 FROM doctor_availability WHERE doctor_id = ? AND available_date = ? "
                                         "AND start_time < ? AND end_time > ?", (doctor["id"], day, end, start)).fetchone()
                    if overlap:
                        raise BookingError("This overlaps another availability window on the same day.")
                    new_id = db.execute("INSERT INTO doctor_availability (doctor_id, available_date, start_time, end_time) "
                                        "VALUES (?, ?, ?, ?)", (doctor["id"], day, start, end)).lastrowid
                    audit(db, "availability_added", "doctor_availability", new_id)
                flash("Availability window added.", "success")
                return redirect(url_for("doctor_schedule"))
            except BookingError as err:
                errors.append(str(err))
            except sqlite3.IntegrityError:
                errors.append("You already have a window starting at that time.")
    windows = db.execute(
        "SELECT w.*, (SELECT COUNT(*) FROM appointments a WHERE a.doctor_id = w.doctor_id AND a.appointment_date = w.available_date "
        f"AND a.status IN ('Booked','Confirmed') AND a.start_time >= w.start_time AND a.start_time < w.end_time) AS booked "
        "FROM doctor_availability w WHERE w.doctor_id = ? AND w.available_date >= ? ORDER BY w.available_date, w.start_time",
        (doctor["id"], date.today().strftime(DATE_FMT))).fetchall()
    return render_template("doctor_schedule.html", doctor=doctor, windows=windows, errors=errors,
                           today=date.today().strftime(DATE_FMT))


@app.route("/doctor/schedule/<int:window_id>/toggle", methods=["POST"])
@role_required("doctor")
def toggle_window(window_id):
    db = get_db()
    doctor = doctor_for(db, g.user["id"])
    w = db.execute("SELECT * FROM doctor_availability WHERE id = ? AND doctor_id = ?", (window_id, doctor["id"])).fetchone()
    if w is None:
        abort(404)
    new_value = 0 if w["is_available"] else 1
    with transaction(db):
        db.execute("UPDATE doctor_availability SET is_available = ? WHERE id = ?", (new_value, window_id))
        audit(db, "availability_available" if new_value else "availability_unavailable", "doctor_availability", window_id)
    flash("Window marked as available." if new_value else
          "Window marked as unavailable. Appointments already booked in it are not cancelled automatically.", "success")
    return redirect(url_for("doctor_schedule"))


@app.route("/doctor/profile", methods=["POST"])
@role_required("doctor")
def doctor_profile():
    db = get_db()
    doctor = doctor_for(db, g.user["id"])
    qualification = request.form.get("qualification", "").strip()[:200]
    try:
        minutes = int(request.form.get("consultation_duration", ""))
    except ValueError:
        minutes = 0
    if not 10 <= minutes <= 120 or minutes % 5:
        flash("Consultation duration must be between 10 and 120 minutes, in steps of 5.", "danger")
    else:
        with transaction(db):
            db.execute("UPDATE doctors SET qualification = ?, consultation_duration = ? WHERE id = ?",
                       (qualification or None, minutes, doctor["id"]))
            audit(db, "doctor_profile_updated", "doctor", doctor["id"])
        flash("Profile updated. The new duration applies to future bookings.", "success")
    return redirect(url_for("doctor_schedule"))


@app.route("/doctor/appointments/<int:appt_id>/consult", methods=["GET", "POST"])
@role_required("doctor")
def consult(appt_id):
    db = get_db()
    doctor = doctor_for(db, g.user["id"])
    appt = db.execute(APPT_SELECT + " WHERE a.id = ? AND a.doctor_id = ?", (appt_id, doctor["id"])).fetchone()
    if appt is None:
        abort(404)       # doctors can only open their OWN patients' appointments
    # Doctors see only what a consultation needs (no address, insurance or identifier)
    patient = db.execute(
        "SELECT p.id, p.date_of_birth, p.gender, p.phone, p.registration_symptoms, p.medical_history, u.full_name "
        "FROM patients p JOIN users u ON u.id = p.user_id WHERE p.id = ?", (appt["patient_id"],)).fetchone()
    record = db.execute("SELECT * FROM medical_records WHERE appointment_id = ?", (appt_id,)).fetchone()
    errors = []
    if request.method == "POST":
        if appt["status"] == "Cancelled":
            errors.append("Notes cannot be added to a cancelled appointment.")
        vals = {k: request.form.get(k, "").strip() for k in ("symptoms", "consultation_notes", "diagnosis")}
        if any(len(v) > 2000 for v in vals.values()):
            errors.append("Each field may contain at most 2000 characters.")
        if not any(vals.values()):
            errors.append("Please enter at least one of: symptoms, notes or diagnosis.")
        visible = 1 if request.form.get("visible_to_patient") else 0
        if not errors:
            with transaction(db):
                if record:
                    db.execute("UPDATE medical_records SET symptoms=?, consultation_notes=?, diagnosis=?, visible_to_patient=?, "
                               "updated_at=datetime('now') WHERE id=?",
                               (vals["symptoms"], vals["consultation_notes"], vals["diagnosis"], visible, record["id"]))
                    rid, action = record["id"], "medical_record_updated"
                else:
                    rid = db.execute("INSERT INTO medical_records (patient_id, doctor_id, appointment_id, symptoms, "
                                     "consultation_notes, diagnosis, visible_to_patient) VALUES (?,?,?,?,?,?,?)",
                                     (patient["id"], doctor["id"], appt_id, vals["symptoms"], vals["consultation_notes"],
                                      vals["diagnosis"], visible)).lastrowid
                    action = "medical_record_created"
                audit(db, action, "medical_record", rid)
                was_visible = record["visible_to_patient"] if record else 0
                if visible and not was_visible:
                    notify(db, appt["patient_user_id"], "A consultation summary is now available in your profile.", "record", appt_id)
            flash("Consultation record saved.", "success")
            return redirect(url_for("consult", appt_id=appt_id))
    previous = db.execute(
        "SELECT m.*, a.appointment_date FROM medical_records m LEFT JOIN appointments a ON a.id = m.appointment_id "
        "WHERE m.patient_id = ? AND m.doctor_id = ? AND (m.appointment_id IS NULL OR m.appointment_id != ?) "
        "ORDER BY m.created_at DESC LIMIT 10", (patient["id"], doctor["id"], appt_id)).fetchall()
    return render_template("consultation.html", appt=appt, patient=patient, record=record, previous=previous, errors=errors)


# =============================================================================
# 8. SHARED APPOINTMENT ACTIONS (cancel / change status)
# =============================================================================
def load_appointment_for_actor(db, appt_id):
    """Fetch an appointment only if the logged-in user is allowed to touch it."""
    appt = db.execute(APPT_SELECT + " WHERE a.id = ?", (appt_id,)).fetchone()
    if appt is None:
        abort(404)
    role = g.user["role"]
    if role == "patient" and appt["patient_user_id"] != g.user["id"]:
        abort(404)
    if role == "doctor" and appt["doctor_user_id"] != g.user["id"]:
        abort(404)
    return appt


@app.route("/appointments/<int:appt_id>/cancel", methods=["POST"])
@login_required
def cancel_appointment(appt_id):
    db = get_db()
    appt = load_appointment_for_actor(db, appt_id)
    role = g.user["role"]
    back = safe_next(request.form.get("next"), url_for("dashboard"))
    if not can_cancel(appt, role):
        if appt["status"] in ("Booked", "Confirmed") and role == "patient":
            flash(f"Appointments can only be cancelled at least {current_app.config['CANCELLATION_NOTICE_HOURS']} "
                  "hours before they start. Please contact the hospital.", "danger")
        else:
            flash("This appointment cannot be cancelled.", "danger")
        return redirect(back)
    with transaction(db):
        db.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appt_id,))
        when = f"{pretty_date(appt['appointment_date'])} at {appt['start_time']}"
        notify(db, appt["patient_user_id"], f"Your appointment with {appt['doctor_name']} on {when} was cancelled.", "cancellation", appt_id)
        notify(db, appt["doctor_user_id"], f"Appointment with {appt['patient_name']} on {when} was cancelled.", "cancellation", appt_id)
        audit(db, "appointment_cancelled", "appointment", appt_id)
    flash("Appointment cancelled. The slot is available again.", "success")
    return redirect(back)


@app.route("/appointments/<int:appt_id>/status", methods=["POST"])
@role_required("doctor", "admin")
def appointment_status(appt_id):
    db = get_db()
    appt = load_appointment_for_actor(db, appt_id)
    new = request.form.get("status", "")
    back = safe_next(request.form.get("next"), url_for("dashboard"))
    started = parse_dt(appt["appointment_date"], appt["start_time"]) <= datetime.now()
    ok = ((new == "Confirmed" and appt["status"] == "Booked") or
          (new == "Completed" and appt["status"] in ("Booked", "Confirmed") and started))
    if not ok:
        flash("That status change is not allowed for this appointment.", "danger")
        return redirect(back)
    with transaction(db):
        db.execute("UPDATE appointments SET status = ? WHERE id = ?", (new, appt_id))
        notify(db, appt["patient_user_id"], f"Your appointment on {pretty_date(appt['appointment_date'])} "
               f"at {appt['start_time']} is now {new}.", "status", appt_id)
        audit(db, f"appointment_{new.lower()}", "appointment", appt_id)
    flash(f"Appointment marked as {new}.", "success")
    return redirect(back)


# =============================================================================
# 9. ADMINISTRATOR ROUTES
# =============================================================================
def dashboard_stats(db):
    """All numbers come from real SQL queries (nothing is hard-coded)."""
    one = lambda sql, p=(): db.execute(sql, p).fetchone()[0]
    today = date.today().strftime(DATE_FMT)
    return {
        "patients": one("SELECT COUNT(*) FROM patients"),
        "doctors": one("SELECT COUNT(*) FROM doctors WHERE is_active = 1"),
        "appointments": one("SELECT COUNT(*) FROM appointments"),
        "today": one("SELECT COUNT(*) FROM appointments WHERE appointment_date = ? AND status != 'Cancelled'", (today,)),
        "cancelled": one("SELECT COUNT(*) FROM appointments WHERE status = 'Cancelled'"),
        "pending": one("SELECT COUNT(*) FROM patients WHERE verification_status IN ('Pending','Requires Review')"),
    }


def doctor_utilization(db):
    """Utilization = booked appointments / total slots in the doctor's available windows."""
    rows = db.execute("SELECT d.id, u.full_name, d.consultation_duration AS mins, dep.department_name "
                      "FROM doctors d JOIN users u ON u.id = d.user_id JOIN departments dep ON dep.id = d.department_id "
                      "WHERE d.is_active = 1 ORDER BY u.full_name").fetchall()
    result = []
    for r in rows:
        capacity = sum(len(build_slots(w["start_time"], w["end_time"], r["mins"])) for w in db.execute(
            "SELECT start_time, end_time FROM doctor_availability WHERE doctor_id = ? AND is_available = 1", (r["id"],)))
        booked = db.execute(f"SELECT COUNT(*) FROM appointments WHERE doctor_id = ? AND status IN {SLOT_STATUSES_SQL}",
                            (r["id"],)).fetchone()[0]
        pct = min(100.0, round(100 * booked / capacity, 1)) if capacity else 0.0
        result.append({"name": r["full_name"], "department": r["department_name"], "capacity": capacity,
                       "booked": booked, "percent": pct})
    return result


def chart_data(db):
    by_dept = db.execute(
        "SELECT dep.department_name AS label, COUNT(a.id) AS total FROM departments dep "
        "LEFT JOIN doctors d ON d.department_id = dep.id "
        "LEFT JOIN appointments a ON a.doctor_id = d.id AND a.status != 'Cancelled' "
        "GROUP BY dep.id ORDER BY total DESC, dep.department_name").fetchall()
    by_status = db.execute("SELECT status AS label, COUNT(*) AS total FROM appointments GROUP BY status ORDER BY status").fetchall()
    today = date.today()
    days = [(today + timedelta(days=i)) for i in range(-7, 8)]
    counts = {r["appointment_date"]: r["total"] for r in db.execute(
        "SELECT appointment_date, COUNT(*) AS total FROM appointments WHERE status != 'Cancelled' "
        "AND appointment_date BETWEEN ? AND ? GROUP BY appointment_date",
        (days[0].strftime(DATE_FMT), days[-1].strftime(DATE_FMT)))}
    return {
        "dept": {"type": "bar", "label": "Appointments", "labels": [r["label"] for r in by_dept], "values": [r["total"] for r in by_dept]},
        "status": {"type": "doughnut", "label": "Appointments", "labels": [r["label"] for r in by_status], "values": [r["total"] for r in by_status]},
        "daily": {"type": "line", "label": "Appointments per day", "labels": [d.strftime("%d %b") for d in days],
                  "values": [counts.get(d.strftime(DATE_FMT), 0) for d in days]},
    }


@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    db = get_db()
    util = doctor_utilization(db)
    charts = chart_data(db)
    charts["util"] = {"type": "bar", "label": "Utilization %", "labels": [u["name"] for u in util], "values": [u["percent"] for u in util]}
    upcoming = decorate(db.execute(APPT_SELECT + " WHERE a.appointment_date = ? ORDER BY a.start_time",
                                   (date.today().strftime(DATE_FMT),)).fetchall(), "admin")
    return render_template("admin_dashboard.html", stats=dashboard_stats(db), charts=charts, today_list=upcoming)


@app.route("/admin/reports")
@role_required("admin")
def reports():
    db = get_db()
    util = doctor_utilization(db)
    charts = chart_data(db)
    charts["util"] = {"type": "bar", "label": "Utilization %", "labels": [u["name"] for u in util], "values": [u["percent"] for u in util]}
    dept_table = db.execute(
        "SELECT dep.department_name, COUNT(DISTINCT d.id) AS doctors, COUNT(a.id) AS appointments, "
        "SUM(CASE WHEN a.status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled FROM departments dep "
        "LEFT JOIN doctors d ON d.department_id = dep.id LEFT JOIN appointments a ON a.doctor_id = d.id "
        "GROUP BY dep.id ORDER BY dep.department_name").fetchall()
    logs = db.execute("SELECT l.*, u.full_name, u.role FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id "
                      "ORDER BY l.id DESC LIMIT 25").fetchall()
    return render_template("reports.html", stats=dashboard_stats(db), charts=charts, util=util, dept_table=dept_table, logs=logs)


@app.route("/admin/patients")
@role_required("admin")
def manage_patients():
    db = get_db()
    q, status = request.args.get("q", "").strip(), request.args.get("status", "").strip()
    sql = ("SELECT p.*, u.full_name, u.email, u.is_active FROM patients p JOIN users u ON u.id = p.user_id WHERE 1=1")
    params = []
    if q:
        sql += " AND (u.full_name LIKE ? OR u.email LIKE ? OR p.patient_identifier LIKE ?)"
        params += [f"%{q}%"] * 3
    if status in VERIFICATION_STATUSES:
        sql += " AND p.verification_status = ?"
        params.append(status)
    rows = db.execute(sql + " ORDER BY p.id DESC", params).fetchall()
    return render_template("manage_patients.html", rows=rows, q=q, status=status, statuses=VERIFICATION_STATUSES)


@app.route("/admin/verification", methods=["GET", "POST"])
@role_required("admin")
def verification_review():
    db = get_db()
    if request.method == "POST":
        pid = request.form.get("patient_id", "")
        new, note = request.form.get("status", ""), request.form.get("note", "").strip()[:300]
        patient = db.execute("SELECT * FROM patients WHERE id = ?", (pid,)).fetchone() if pid.isdigit() else None
        if patient is None or new not in VERIFICATION_STATUSES:
            flash("Invalid verification request.", "danger")
        else:
            with transaction(db):
                db.execute("UPDATE patients SET verification_status = ?, verification_note = ?, updated_at = datetime('now') WHERE id = ?",
                           (new, note or f"Set to {new} by an administrator.", patient["id"]))
                notify(db, patient["user_id"], f"Your verification status is now: {new}." + (f" Note: {note}" if note else ""), "verification")
                audit(db, "verification_changed", "patient", patient["id"])
            flash(f"Verification status updated to {new}.", "success")
        return redirect(url_for("verification_review", show=request.form.get("show", "")))
    show = request.args.get("show", "")
    wanted = (show,) if show in VERIFICATION_STATUSES else ("Pending", "Requires Review", "Rejected")
    marks = ",".join("?" * len(wanted))
    rows = db.execute(
        "SELECT p.*, u.full_name, u.email FROM patients p JOIN users u ON u.id = p.user_id "
        f"WHERE p.verification_status IN ({marks}) ORDER BY p.updated_at DESC", wanted).fetchall()
    return render_template("verification_review.html", rows=rows, show=show, statuses=VERIFICATION_STATUSES)


@app.route("/admin/doctors", methods=["GET", "POST"])
@role_required("admin")
def manage_doctors():
    db = get_db()
    errors, form = [], {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "email", "department_id", "specialty", "qualification", "consultation_duration")}
        form["email"] = form["email"].lower()
        errors = validate_doctor_form(db, form, request.form.get("password", ""), require_password=True)
        if not errors:
            try:
                with transaction(db):
                    uid = db.execute("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'doctor')",
                                     (form["full_name"], form["email"], generate_password_hash(request.form["password"]))).lastrowid
                    did = db.execute("INSERT INTO doctors (user_id, department_id, specialty, qualification, consultation_duration) "
                                     "VALUES (?, ?, ?, ?, ?)", (uid, int(form["department_id"]), form["specialty"],
                                                                form["qualification"] or None, int(form["consultation_duration"]))).lastrowid
                    audit(db, "doctor_created", "doctor", did)
                flash("Doctor account created.", "success")
                return redirect(url_for("manage_doctors"))
            except sqlite3.IntegrityError:
                errors.append("A user with this email already exists.")
    doctors = db.execute(
        "SELECT d.*, u.full_name, u.email, u.is_active AS user_active, dep.department_name FROM doctors d "
        "JOIN users u ON u.id = d.user_id JOIN departments dep ON dep.id = d.department_id ORDER BY u.full_name").fetchall()
    departments = db.execute("SELECT * FROM departments WHERE is_active = 1 ORDER BY department_name").fetchall()
    return render_template("manage_doctors.html", doctors=doctors, departments=departments, errors=errors, f=form)


def validate_doctor_form(db, f, password, require_password, user_id=None):
    errors = []
    if not NAME_RE.match(f["full_name"] or ""):
        errors.append("Doctor name is required (letters, spaces, dots, hyphens, apostrophes).")
    if not EMAIL_RE.match(f["email"] or ""):
        errors.append("A valid email address is required.")
    elif db.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (f["email"], user_id or -1)).fetchone():
        errors.append("Another user already uses this email.")
    if require_password or password:
        pw_error = valid_password(password)
        if pw_error:
            errors.append(pw_error)
    dept = db.execute("SELECT id, is_active FROM departments WHERE id = ?",
                      (int(f["department_id"]),)).fetchone() if f["department_id"].isdigit() else None
    if dept is None or (not dept["is_active"] and not user_id):
        errors.append("Please choose an active department.")
    if not f["specialty"] or len(f["specialty"]) > 80:
        errors.append("Specialty is required (maximum 80 characters).")
    try:
        minutes = int(f["consultation_duration"])
        if not 10 <= minutes <= 120:
            raise ValueError
    except ValueError:
        errors.append("Consultation duration must be a number between 10 and 120 minutes.")
    return errors


@app.route("/admin/doctors/<int:doctor_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT d.*, u.full_name, u.email FROM doctors d JOIN users u ON u.id = d.user_id WHERE d.id = ?",
                        (doctor_id,)).fetchone()
    if doctor is None:
        abort(404)
    errors, form = [], dict(doctor)
    form = {k: str(v) if v is not None else "" for k, v in form.items()}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "email", "department_id", "specialty", "qualification", "consultation_duration")}
        form["email"] = form["email"].lower()
        password = request.form.get("password", "")
        errors = validate_doctor_form(db, form, password, require_password=False, user_id=doctor["user_id"])
        if not errors:
            try:
                with transaction(db):
                    db.execute("UPDATE users SET full_name = ?, email = ? WHERE id = ?", (form["full_name"], form["email"], doctor["user_id"]))
                    if password:
                        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), doctor["user_id"]))
                    db.execute("UPDATE doctors SET department_id = ?, specialty = ?, qualification = ?, consultation_duration = ? WHERE id = ?",
                               (int(form["department_id"]), form["specialty"], form["qualification"] or None,
                                int(form["consultation_duration"]), doctor_id))
                    audit(db, "doctor_updated", "doctor", doctor_id)
                flash("Doctor updated.", "success")
                return redirect(url_for("manage_doctors"))
            except sqlite3.IntegrityError:
                errors.append("Could not save: the email is already used.")
    departments = db.execute("SELECT * FROM departments WHERE is_active = 1 OR id = ? ORDER BY department_name", (doctor["department_id"],)).fetchall()
    return render_template("edit_doctor.html", doctor=doctor, f=form, errors=errors, departments=departments)


@app.route("/admin/doctors/<int:doctor_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT * FROM doctors WHERE id = ?", (doctor_id,)).fetchone()
    if doctor is None:
        abort(404)
    new_value = 0 if doctor["is_active"] else 1
    with transaction(db):
        db.execute("UPDATE doctors SET is_active = ? WHERE id = ?", (new_value, doctor_id))
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_value, doctor["user_id"]))
        audit(db, "doctor_activated" if new_value else "doctor_deactivated", "doctor", doctor_id)
    flash("Doctor activated." if new_value else "Doctor deactivated (they can no longer log in or receive bookings).", "success")
    return redirect(url_for("manage_doctors"))


@app.route("/admin/departments", methods=["GET", "POST"])
@role_required("admin")
def manage_departments():
    db = get_db()
    if request.method == "POST":
        name = " ".join(request.form.get("department_name", "").split())
        desc = request.form.get("description", "").strip()[:300]
        dept_id = request.form.get("department_id", "")
        if not name or len(name) > 80:
            flash("Department name is required (maximum 80 characters).", "danger")
        else:
            try:
                with transaction(db):
                    if dept_id.isdigit():       # update an existing department
                        if db.execute("UPDATE departments SET department_name = ?, description = ? WHERE id = ?",
                                      (name, desc or None, int(dept_id))).rowcount:
                            audit(db, "department_updated", "department", int(dept_id))
                            flash("Department updated.", "success")
                    else:                       # create a new department
                        new_id = db.execute("INSERT INTO departments (department_name, description) VALUES (?, ?)",
                                            (name, desc or None)).lastrowid
                        audit(db, "department_created", "department", new_id)
                        flash("Department added.", "success")
            except sqlite3.IntegrityError:
                flash("A department with that name already exists.", "danger")
        return redirect(url_for("manage_departments"))
    rows = db.execute("SELECT dep.*, (SELECT COUNT(*) FROM doctors d WHERE d.department_id = dep.id AND d.is_active = 1) AS doctor_count "
                      "FROM departments dep ORDER BY dep.department_name").fetchall()
    return render_template("manage_departments.html", rows=rows)


@app.route("/admin/departments/<int:dept_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle_department(dept_id):
    db = get_db()
    dept = db.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone()
    if dept is None:
        abort(404)
    new_value = 0 if dept["is_active"] else 1
    with transaction(db):
        db.execute("UPDATE departments SET is_active = ? WHERE id = ?", (new_value, dept_id))
        audit(db, "department_activated" if new_value else "department_deactivated", "department", dept_id)
    flash("Department activated." if new_value else "Department deactivated. Its doctors are hidden from patient searches.", "success")
    return redirect(url_for("manage_departments"))


@app.route("/admin/appointments")
@role_required("admin")
def manage_appointments():
    db = get_db()
    day, status = request.args.get("date", "").strip(), request.args.get("status", "").strip()
    doctor_id, dept = request.args.get("doctor", "").strip(), request.args.get("department", "").strip()
    sql, params = APPT_SELECT + " WHERE 1=1", []
    if parse_date(day):
        sql += " AND a.appointment_date = ?"
        params.append(day)
    if status in ("Booked", "Confirmed", "Completed", "Cancelled"):
        sql += " AND a.status = ?"
        params.append(status)
    if doctor_id.isdigit():
        sql += " AND a.doctor_id = ?"
        params.append(int(doctor_id))
    if dept.isdigit():
        sql += " AND d.department_id = ?"
        params.append(int(dept))
    rows = decorate(db.execute(sql + " ORDER BY a.appointment_date DESC, a.start_time DESC LIMIT 300", params).fetchall(), "admin")
    doctors = db.execute("SELECT d.id, u.full_name FROM doctors d JOIN users u ON u.id = d.user_id ORDER BY u.full_name").fetchall()
    departments = db.execute("SELECT id, department_name FROM departments ORDER BY department_name").fetchall()
    today = date.today().strftime(DATE_FMT)
    return render_template("manage_appointments.html", rows=rows, doctors=doctors, departments=departments, today=today,
                           filters={"date": day, "status": status, "doctor": doctor_id, "department": dept})


@app.route("/admin/users", methods=["GET", "POST"])
@role_required("admin")
def manage_users():
    db = get_db()
    errors, form = [], {}
    if request.method == "POST":       # create another administrator
        form = {"full_name": " ".join(request.form.get("full_name", "").split()), "email": request.form.get("email", "").strip().lower()}
        password = request.form.get("password", "")
        if not NAME_RE.match(form["full_name"]):
            errors.append("A valid name is required.")
        if not EMAIL_RE.match(form["email"]):
            errors.append("A valid email address is required.")
        pw_error = valid_password(password)
        if pw_error:
            errors.append(pw_error)
        if not errors:
            try:
                with transaction(db):
                    uid = db.execute("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                                     (form["full_name"], form["email"], generate_password_hash(password))).lastrowid
                    audit(db, "admin_created", "user", uid)
                flash("Administrator account created.", "success")
                return redirect(url_for("manage_users"))
            except sqlite3.IntegrityError:
                errors.append("A user with this email already exists.")
    users = db.execute("SELECT id, full_name, email, role, is_active, created_at FROM users ORDER BY role, full_name").fetchall()
    return render_template("manage_users.html", users=users, errors=errors, f=form)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle_user(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    if target["id"] == g.user["id"]:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("manage_users"))
    new_value = 0 if target["is_active"] else 1
    with transaction(db):
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_value, user_id))
        if target["role"] == "doctor":
            db.execute("UPDATE doctors SET is_active = ? WHERE user_id = ?", (new_value, user_id))
        audit(db, "user_activated" if new_value else "user_deactivated", "user", user_id)
    flash("User activated." if new_value else "User deactivated.", "success")
    return redirect(url_for("manage_users"))


if __name__ == "__main__":
    # Development server only. In production use gunicorn / the host's WSGI server.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
