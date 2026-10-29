"""
Configuration for MEDIQ Hospital ERP.

Secrets and deployment-specific values come from ENVIRONMENT VARIABLES, so they
are never written into the code or uploaded to GitHub.
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_SECRET = "dev-only-change-me"


def _flag(name, default="0"):
    """Read an on/off environment variable ('1', 'true', 'yes' = on)."""
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


class Config:
    # Used to sign session cookies. MUST be set to a long random value in production.
    SECRET_KEY = os.environ.get("SECRET_KEY", DEFAULT_SECRET)

    # Path of the SQLite database file (put it on a persistent disk when deployed).
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "mediq.db"))

    # Secure session cookies
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"         # helps against cross-site request forgery
    SESSION_COOKIE_SECURE = _flag("SESSION_COOKIE_SECURE")   # set to 1 when using HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)       # auto logout after 60 min

    # Business rules
    CANCELLATION_NOTICE_HOURS = int(os.environ.get("CANCELLATION_NOTICE_HOURS", "2"))
    BOOKING_WINDOW_DAYS = int(os.environ.get("BOOKING_WINDOW_DAYS", "14"))
    # Policy: by default ONLY verified patients may book. An administrator can
    # change this policy by setting ALLOW_UNVERIFIED_BOOKING=1 (rejected patients
    # are still blocked).
    ALLOW_UNVERIFIED_BOOKING = _flag("ALLOW_UNVERIFIED_BOOKING")

    # Show the demo accounts on the login page (turn OFF in production: =0)
    SHOW_DEMO_CREDENTIALS = _flag("SHOW_DEMO_CREDENTIALS", "1")

    # Set MEDIQ_ENV=production on the server. The app then refuses to start
    # with the default secret key.
    MEDIQ_ENV = os.environ.get("MEDIQ_ENV", "development")


# ---------------------------------------------------------------------------
# DEMONSTRATION DATA ONLY
# A pretend "hospital patient registry" used by the simulated verification.
# It is NOT a real registry; no external system is contacted.
# ---------------------------------------------------------------------------
DEMO_REGISTRY = {
    "MQ-100001": ("Demo Patient One", "1990-05-14"),
    "MQ-100002": ("Demo Patient Two", "1985-11-02"),
    "MQ-100003": ("Demo Patient Three", "2000-01-20"),
    "MQ-100004": ("Demo Patient Five", "1995-03-09"),
    "MQ-100005": ("Demo Patient Six", "1988-08-08"),      # free to use when testing registration
    "MQ-100006": ("Demo Patient Seven", "1991-01-01"),
}
