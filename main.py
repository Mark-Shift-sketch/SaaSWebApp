import json
import logging
import csv
import importlib
import ast
from flask import (
    Flask,
    session,
    redirect,
    request,
    render_template,
    url_for,
    flash,
    jsonify,
    has_request_context,
    has_app_context,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
try:
    from flask_jwt_extended import (
        JWTManager,
        create_access_token as _jwt_create_access_token,
        decode_token as _jwt_decode_token,
    )
except Exception:
    JWTManager = None
    _jwt_create_access_token = None
    _jwt_decode_token = None
from dotenv import load_dotenv
from sendotp import srotp, verify, request_signup_otp, verify_signup_otp
from config import get_connection
from sendotp import send_cc_email, send_request_email, send_pending_action_reminder_email
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from sendotp import send_cc_email_with_blob
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from reportlab.pdfgen import canvas as _rl_canvas
from reportlab.lib.utils import ImageReader as _ImageReader
from pypdf import PdfReader as _PdfReader, PdfWriter as _PdfWriter
from flask import Response, stream_with_context

import mysql.connector
import requests
import datetime
from decimal import Decimal, InvalidOperation
import os
import errno
import re
import textwrap
import base64
import time
import random
import hashlib
from threading import Thread
from io import BytesIO, StringIO
from flask import send_file

load_dotenv()

logger = logging.getLogger(__name__)

ALLOWED_EMAIL_DOMAIN = str(os.environ.get("ALLOWED_EMAIL_DOMAIN", "phinmaed.com")).strip().lower()
ALLOWED_EMAIL_SUFFIX = f"@{ALLOWED_EMAIL_DOMAIN}"
EMAIL_DOMAIN_HELPER_MESSAGE = str(
    os.environ.get("EMAIL_DOMAIN_HELPER_MESSAGE", "Please use youre phinmaed email")
).strip()
DEV_EXCEPTION_EMAIL = str(os.environ.get("DEV_EMAIL") or os.environ.get("name") or "").strip().lower()


def is_allowed_system_email(email):
    normalized_email = str(email or "").strip().lower()
    if DEV_EXCEPTION_EMAIL and normalized_email == DEV_EXCEPTION_EMAIL:
        return True
    if DEFAULT_SAAS_EMAIL and normalized_email == DEFAULT_SAAS_EMAIL:
        return True
    if "@" not in normalized_email:
        return False
    local_part, domain = normalized_email.rsplit("@", 1)
    return bool(local_part) and domain == ALLOWED_EMAIL_DOMAIN

argon2_hasher = None
argon2_verify_mismatch_error = Exception
argon2_invalid_hash_error = Exception

try:
    argon2_module = importlib.import_module("argon2")
    argon2_exceptions = importlib.import_module("argon2.exceptions")
    password_hasher_cls = getattr(argon2_module, "PasswordHasher", None)
    if password_hasher_cls is not None:
        argon2_hasher = password_hasher_cls()
    argon2_verify_mismatch_error = getattr(
        argon2_exceptions,
        "VerifyMismatchError",
        Exception,
    )
    argon2_invalid_hash_error = getattr(
        argon2_exceptions,
        "InvalidHashError",
        Exception,
    )
except Exception:
    argon2_hasher = None


def hash_user_password(raw_password):
    if argon2_hasher is None:
        raise RuntimeError(
            "argon2-cffi is required for password hashing."
        )
    return argon2_hasher.hash(raw_password)


def verify_user_password(stored_hash, candidate_password):
    stored_hash = str(stored_hash or "")
    if not stored_hash:
        return False

    if stored_hash.startswith("$argon2id$"):
        if argon2_hasher is None:
            return False
        try:
            return argon2_hasher.verify(stored_hash, candidate_password)
        except (argon2_verify_mismatch_error, argon2_invalid_hash_error):
            return False
        except Exception:
            return False

    try:
        return check_password_hash(stored_hash, candidate_password)
    except Exception:
        return False


def needs_password_rehash(stored_hash):
    if argon2_hasher is None:
        return False

    stored_hash = str(stored_hash or "")
    if not stored_hash:
        return False

    if not stored_hash.startswith("$argon2id$"):
        return True

    try:
        return argon2_hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


def run_background_task(fn, *args, **kwargs):
    def _target():
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.exception("Background task failed")

    Thread(target=_target, daemon=True).start()


def send_request_email_async(receiver, status):
    email = (receiver or "").strip()
    if not email:
        return
    run_background_task(send_request_email, email, status)


# Security / environment

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
app.secret_key = SECRET_KEY
serializer = URLSafeTimedSerializer(app.secret_key)

# JWT setup (used for API bearer tokens). Falls back to serializer tokens if unavailable.
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ALGORITHM"] = os.environ.get("JWT_ALGORITHM", "HS256")
_jwt_expires_seconds = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_SECONDS", str(60 * 60 * 24 * 7)))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(seconds=_jwt_expires_seconds)
jwt_manager = JWTManager(app) if JWTManager is not None else None

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower() in {"1", "true", "yes", "on"}),
    PERMANENT_SESSION_LIFETIME=int(os.environ.get("PERMANENT_SESSION_LIFETIME", "3600")),
)

# CSRF protection for HTML forms
try:
    from flask_wtf.csrf import CSRFProtect, CSRFError
    csrf = CSRFProtect(app)
except Exception:
    csrf = None
    CSRFError = None


def get_rate_limit_user_key():
    """Resolve a stable key for per-user global limits."""
    try:
        session_user_id = int(session.get("user_id") or 0)
    except Exception:
        session_user_id = 0

    if session_user_id > 0:
        return f"user:{session_user_id}"

    session_email = str(session.get("email") or "").strip().lower()
    if session_email:
        return f"email:{session_email}"

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.startswith("Bearer "):
        token = auth.replace("Bearer ", "", 1).strip()
        if token:
            try:
                payload = verify_token_payload(token)
                token_email = str(payload.get("email") or "").strip().lower()
                if token_email:
                    return f"token:{token_email}"
            except Exception:
                pass

    remote_address = get_remote_address() or "unknown"
    return f"guest:{remote_address}"


# Rate limiting
GLOBAL_USER_DAILY_LIMIT = os.environ.get("RATE_LIMIT_PER_USER_DAY")
GLOBAL_IP_HOURLY_LIMIT = os.environ.get("RATE_LIMIT_PER_IP_HOUR")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
)

global_user_rate_limit = limiter.shared_limit(
    GLOBAL_USER_DAILY_LIMIT,
    scope="global-user-limit",
    key_func=get_rate_limit_user_key,
)
global_ip_rate_limit = limiter.shared_limit(
    GLOBAL_IP_HOURLY_LIMIT,
    scope="global-ip-limit",
    key_func=get_remote_address,
)


def apply_global_rate_limits():
    """Apply global user/ip limits to all registered routes once."""
    for endpoint, view_func in list(app.view_functions.items()):
        if endpoint == "static":
            continue
        if getattr(view_func, "_global_rate_limited", False):
            continue

        wrapped = global_user_rate_limit(view_func)
        wrapped = global_ip_rate_limit(wrapped)
        wrapped._global_rate_limited = True
        app.view_functions[endpoint] = wrapped


FRONTEND_ORIGINS = [o.strip() for o in (os.environ.get("FRONTEND_ORIGINS", "")).split(",") if o.strip()]
if not FRONTEND_ORIGINS:
    FRONTEND_ORIGINS = [
        "http://localhost",
        "http://127.0.0.1",
    ]
CORS(
    app,
    resources={r"/api/*": {"origins": [
        r"^http://localhost(:\d+)?$",
        r"^http://127\.0\.0\.1(:\d+)?$",
        r"^http://192\.168\.0\.102(:\d+)?$",
    ]}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# Upload Size Limit
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB"))
MAX_BUG_IMAGE_MB = int(os.environ.get("MAX_BUG_IMAGE_MB"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
# Allowed Upload Types 
ALLOWED_EXTENSIONS = {"pdf"}
ALLOWED_BUG_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
ALLOWED_BUG_IMAGE_MIMES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
MAX_BUG_IMAGE_BYTES = MAX_BUG_IMAGE_MB * 1024 * 1024



def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_bug_image(filename, mimetype=""):
    cleaned_name = str(filename or "").strip().lower()
    cleaned_mime = str(mimetype or "").strip().lower()
    if not cleaned_name or "." not in cleaned_name:
        return False
    ext = cleaned_name.rsplit(".", 1)[1]
    if ext not in ALLOWED_BUG_IMAGE_EXTENSIONS:
        return False
    if cleaned_mime and cleaned_mime not in ALLOWED_BUG_IMAGE_MIMES:
        return False
    return True


def is_storage_full_exception(exc):
    if isinstance(exc, OSError) and getattr(exc, "errno", None) == errno.ENOSPC:
        return True

    if isinstance(exc, mysql.connector.Error):
        err_no = getattr(exc, "errno", None)
        if err_no in (1021, 1030, 1114):
            return True

    msg = str(exc or "").strip().lower()
    return any(
        token in msg
        for token in (
            "no space left on device",
            "disk full",
            "table is full",
            "errno: 28",
            "insufficient storage",
        )
    )


def get_request_ip_address():
    forwarded_for = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return (request.remote_addr or "Unknown").strip()


def get_request_device_info():
    ua = (request.headers.get("User-Agent") or "Unknown Device").strip()
    # Keep auth activity entries compact.
    return ua[:255]


def log_auth_activity(action_title, email):
    email = (email or "Unknown").strip().lower()
    ip_address = get_request_ip_address()
    device = get_request_device_info()
    description = f"Email: {email} | Where: {ip_address} | Device: {device}"

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (action_title, description),
        )
        conn.commit()
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("Failed to write auth activity log")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    msg = "File too large. Maximum allowed size is 20MB."
    if request.path.startswith("/api/") or request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"success": False, "message": msg}), 413
    flash(msg, "danger")
    return redirect(request.referrer or "/")


if CSRFError is not None:
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": e.description or "CSRF validation failed."}), 400
        return str(e.description or "CSRF validation failed."), 400


def create_token(email):
    if _jwt_create_access_token is not None and has_app_context():
        return _jwt_create_access_token(identity=str(email or "").strip().lower())
    return serializer.dumps({"email": email})


def create_token_with_claims(email, company_id=None, role=None):
    normalized_email = str(email or "").strip().lower()
    normalized_company_id = int(company_id or 0) if str(company_id or "").strip() else 0
    normalized_role = str(role or "").strip()

    if _jwt_create_access_token is not None and has_app_context():
        additional_claims = {
            "email": normalized_email,
            "company_id": normalized_company_id,
            "role": normalized_role,
        }
        return _jwt_create_access_token(identity=normalized_email, additional_claims=additional_claims)

    return serializer.dumps(
        {
            "email": normalized_email,
            "company_id": normalized_company_id,
            "role": normalized_role,
        }
    )


def verify_token_payload(token, max_age=60 * 60 * 24 * 7):
    if _jwt_decode_token is not None:
        try:
            payload = _jwt_decode_token(token, allow_expired=False)
            email = str(payload.get("email") or payload.get("sub") or "").strip().lower()
            if not email:
                raise BadSignature("Invalid token payload")
            return {
                "email": email,
                "company_id": int(payload.get("company_id") or 0),
                "role": str(payload.get("role") or "").strip(),
            }
        except Exception:
            # Backward-compatible fallback for old serializer tokens.
            pass

    data = serializer.loads(token, max_age=max_age)
    email = str(data.get("email") or "").strip().lower()
    if not email:
        raise BadSignature("Invalid token payload")
    return {
        "email": email,
        "company_id": int(data.get("company_id") or 0),
        "role": str(data.get("role") or "").strip(),
    }


def verify_token(token, max_age=60 * 60 * 24 * 7):
    payload = verify_token_payload(token, max_age=max_age)
    return payload["email"]


def create_password_reset_token(email):
    return serializer.dumps(
        {"email": email, "purpose": "password_reset"},
        salt="password-reset-salt",
    )


def verify_password_reset_token(token, max_age=60 * 60):
    data = serializer.loads(token, salt="password-reset-salt", max_age=max_age)
    if data.get("purpose") != "password_reset":
        raise BadSignature("Invalid token purpose")
    return data["email"]


def create_mobile_signup_otp_token(email):
    return serializer.dumps(
        {"email": email, "purpose": "mobile_signup_otp"},
        salt="mobile-signup-otp-salt",
    )


def verify_mobile_signup_otp_token(token, max_age=60 * 15):
    data = serializer.loads(token, salt="mobile-signup-otp-salt", max_age=max_age)
    if data.get("purpose") != "mobile_signup_otp":
        raise BadSignature("Invalid token purpose")
    return data["email"]


def create_coo_special_action_token(request_id, coo_email):
    return serializer.dumps(
        {
            "purpose": "coo_special_action",
            "request_id": int(request_id),
            "email": str(coo_email or "").strip().lower(),
        },
        salt="coo-special-action-salt",
    )


def verify_coo_special_action_token(token, max_age=60 * 60 * 24):
    data = serializer.loads(token, salt="coo-special-action-salt", max_age=max_age)
    if data.get("purpose") != "coo_special_action":
        raise BadSignature("Invalid token purpose")
    return {
        "request_id": int(data.get("request_id") or 0),
        "email": str(data.get("email") or "").strip().lower(),
    }


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Allow CORS preflight through auth decorator
        if request.method == "OPTIONS":
            return ("", 200)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth.replace("Bearer ", "").strip()
        try:
            payload = verify_token_payload(token)
        except SignatureExpired:
            return jsonify({"error": "Token expired"}), 401
        except BadSignature:
            return jsonify({"error": "Invalid token"}), 401

        request.user_email = payload.get("email")
        request.user_company_id = int(payload.get("company_id") or 0)
        request.user_role = str(payload.get("role") or "").strip()
        return fn(*args, **kwargs)

    return wrapper



# Auth helpers
def login_required(fn):
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        if "email" not in session:
            # For API endpoints return JSON; for pages redirect.
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return _wrapped


def role_required(*roles):
    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            if "email" not in session:
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "Unauthorized"}), 401
                return redirect(url_for("login"))
            role = (session.get("role") or "").strip()
            if role not in roles:
                return "Forbidden", 403
            return fn(*args, **kwargs)
        return _wrapped
    return _decorator


# Security headers
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    allow_same_origin_frame = request.path.startswith("/download_template/")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN" if allow_same_origin_frame else "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-site"
    # Basic CSP 
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "frame-src 'self' blob:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' https:;"
    )
    return resp


@app.before_request
def enforce_system_maintenance_mode():
    path = (request.path or "").strip()

    if not path:
        return None
    if request.method == "OPTIONS":
        return None
    if path.startswith("/static/") or path.startswith("/favicon"):
        return None

    # When running locally over plain HTTP (localhost / 127.0.0.1), allow session cookies
    # to be set even if SESSION_COOKIE_SECURE env is true. This makes local development
    # easier — production environments should serve HTTPS and keep SECURE cookies enabled.
    try:
        host = (request.host or "").split(":", 1)[0].lower()
        if host in {"127.0.0.1", "localhost"} or app.debug:
            app.config["SESSION_COOKIE_SECURE"] = False
    except Exception:
        pass

    maintenance_state = get_system_maintenance_state(use_cache=True)
    if not maintenance_state.get("enabled"):
        return None

    if is_system_maintenance_bypass_user():
        return None

    allowed_prefixes = (
        "/login",
        "/logout",
        "/dev",
        "/saas-admin",
        "/api/dev/system-maintenance",
        "/api/saas/",
        "/send-otp",
        "/verify",
        "/forgot-password",
        "/reset-password",
        "/signup",
        "/company-register",
    )
    if any(path.startswith(prefix) for prefix in allowed_prefixes):
        return None

    reason_text = str(maintenance_state.get("reason") or "").strip()
    if not reason_text:
        reason_text = "System is temporarily paused for maintenance and bug fixes."

    if path.startswith("/api/"):
        response = jsonify(
            {
                "success": False,
                "maintenance_mode": True,
                "error": "System is currently under maintenance.",
                "reason": reason_text,
            }
        )
        response.status_code = 503
        response.headers["Retry-After"] = "300"
        return response

    safe_reason = (
        reason_text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    html = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>System Maintenance</title>"
        "<style>body{margin:0;font-family:Segoe UI,Tahoma,sans-serif;background:#f3f5fa;color:#1d2433;display:grid;"
        "place-items:center;min-height:100vh;padding:24px}.card{background:#fff;border:1px solid #dfe5f0;border-radius:14px;"
        "padding:24px;max-width:560px;box-shadow:0 10px 30px rgba(18,36,70,.10)}"
        "h1{margin:0 0 8px;font-size:1.5rem}.muted{color:#5a667d;line-height:1.5}</style></head><body>"
        "<section class='card'><h1>System Paused</h1>"
        "<p class='muted'>The system is temporarily unavailable while maintenance is in progress.</p>"
        f"<p class='muted'><strong>Reason:</strong> {safe_reason}</p>"
        "<p class='muted'>Please try again later.</p></section></body></html>"
    )
    response = Response(html, status=503, mimetype="text/html")
    response.headers["Retry-After"] = "300"
    return response


def _is_organization_active(company_id):
    normalized_company_id = int(company_id or 0)
    if normalized_company_id <= 0:
        return True

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT COALESCE(is_active, 1) AS is_active FROM organizations WHERE company_id = %s LIMIT 1",
            (normalized_company_id,),
        )
        row = cursor.fetchone() or {}
        return int(row.get("is_active") or 0) == 1
    except Exception:
        logger.exception("_is_organization_active check failed")
        return True
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.before_request
def enforce_organization_pause_mode():
    path = (request.path or "").strip()
    if not path:
        return None
    if request.method == "OPTIONS":
        return None
    if path.startswith("/static/") or path.startswith("/favicon"):
        return None

    if "email" not in session:
        return None

    role = (session.get("role") or "").strip().lower()
    if role in {"dev", "saasowner", "saas_owner", "platformowner", "it", "superadmin"}:
        return None

    company_id = int(session.get("company_id") or 0)
    if company_id <= 0:
        return None

    if _is_organization_active(company_id):
        return None

    if path.startswith("/api/"):
        return jsonify(
            {
                "success": False,
                "organization_paused": True,
                "error": "Your organization is currently paused by the platform administrator.",
            }
        ), 403

    html = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Organization Paused</title>"
        "<style>body{margin:0;font-family:Segoe UI,Tahoma,sans-serif;background:#f3f5fa;color:#1d2433;display:grid;"
        "place-items:center;min-height:100vh;padding:24px}.card{background:#fff;border:1px solid #dfe5f0;border-radius:14px;"
        "padding:24px;max-width:560px;box-shadow:0 10px 30px rgba(18,36,70,.10)}"
        "h1{margin:0 0 8px;font-size:1.5rem}.muted{color:#5a667d;line-height:1.5}</style></head><body>"
        "<section class='card'><h1>Organization Paused</h1>"
        "<p class='muted'>Your organization is temporarily paused by the platform administrator.</p>"
        "<p class='muted'>Please contact Dev or SaaS Owner for reactivation.</p></section></body></html>"
    )
    return Response(html, status=403, mimetype="text/html")

# Helper Functions
def get_user_id(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        if not user:
            return None
        if isinstance(user, dict):
            return user.get("user_id")
        return None
    finally:
        cursor.close()
        conn.close()


@app.post("/api/annotations/my-signature/delete")
@login_required
def delete_my_saved_signature():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Allow admins, approvers, and reviewers to delete their saved signature
    role = (session.get("role") or "").strip()
    allowed_roles = {"admin", "assistantadmin", "superadmin", "dean", "head", "approver", "reviewer", "coo", "sbo"}
    if role.lower() not in allowed_roles:
        return jsonify({"success": False, "error": "Forbidden - signature feature not available for your role"}), 403
    
    actor_user_id = session.get("user_id")
    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    if actor_user_id is None:
        return jsonify({"success": False, "error": "Invalid user."}), 400

    conn = get_connection()
    cursor = conn.cursor()
    try:
        ensure_user_saved_signature_schema(cursor, conn)
        cursor.execute("DELETE FROM user_saved_signatures WHERE user_id = %s", (int(actor_user_id),))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


def get_user_id_for_company(email, company_id):
    normalized_company_id = int(company_id or 0)
    if normalized_company_id <= 0:
        return get_user_id(email)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT user_id FROM users WHERE email=%s AND company_id=%s",
            (email, normalized_company_id),
        )
        user = cursor.fetchone() or {}
        return user.get("user_id")
    finally:
        cursor.close()
        conn.close()


def validate_password_strength(password, require_symbol=True):
    """Return (ok: bool, message: str) for password strength checks.

    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - Optionally require a symbol (non-alphanumeric)
    """
    pw = str(password or "")
    if len(pw) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain an uppercase letter"
    if not re.search(r"[a-z]", pw):
        return False, "Password must contain a lowercase letter"
    if not re.search(r"[0-9]", pw):
        return False, "Password must contain a digit"
    if require_symbol and not re.search(r"[^A-Za-z0-9]", pw):
        return False, "Password must contain a symbol"
    return True, "OK"


_ORG_DOMAIN_COLUMN_CACHE = {"checked": False, "column": None}


def _get_org_domain_column(cursor):
    cached = _ORG_DOMAIN_COLUMN_CACHE.get("column") if _ORG_DOMAIN_COLUMN_CACHE.get("checked") else None
    if cached is not None:
        return cached
    if _ORG_DOMAIN_COLUMN_CACHE.get("checked"):
        return None

    try:
        cursor.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            AND table_name = 'organizations'
            AND column_name IN ('allowed_email_domain', 'allowed_email_domains')
            ORDER BY CASE column_name
            WHEN 'allowed_email_domains' THEN 1
            WHEN 'allowed_email_domain' THEN 2
            ELSE 3
            END
            LIMIT 1
        """
        )
        row = cursor.fetchone() or {}
        _ORG_DOMAIN_COLUMN_CACHE["column"] = row.get("column_name")
    except Exception:
        _ORG_DOMAIN_COLUMN_CACHE["column"] = None
    finally:
        _ORG_DOMAIN_COLUMN_CACHE["checked"] = True

    return _ORG_DOMAIN_COLUMN_CACHE.get("column")


def _is_allowed_email_for_company(cursor, email, company_id=None):
    # System-wide restriction: only @phinmaed.com emails are accepted.
    return is_allowed_system_email(email)


def get_effective_workflow_positions(cursor, request_id, request_type_id):
    """
    Resolve workflow for a request.
    Prefer per-request overrides, then fall back to request-type defaults.
    """
    cursor.execute(
        """
        SELECT position_id
        FROM request_workflow_reviewers
        WHERE request_id = %s
        ORDER BY order_no ASC
    """,
        (request_id,),
    )
    reviewers = [
        int(row["position_id"])
        for row in (cursor.fetchall() or [])
        if row.get("position_id") is not None
    ]

    if not reviewers:
        cursor.execute(
            """
            SELECT position_id
            FROM request_type_reviewers
            WHERE request_type_id = %s
            ORDER BY order_no ASC
        """,
            (request_type_id,),
        )
        reviewers = [
            int(row["position_id"])
            for row in (cursor.fetchall() or [])
            if row.get("position_id") is not None
        ]

    cursor.execute(
        """
        SELECT position_id
        FROM request_workflow_approvers
        WHERE request_id = %s
        ORDER BY order_no ASC
    """,
        (request_id,),
    )
    approvers = [
        int(row["position_id"])
        for row in (cursor.fetchall() or [])
        if row.get("position_id") is not None
    ]

    if not approvers:
        cursor.execute(
            """
            SELECT position_id
            FROM request_type_approvers
            WHERE request_type_id = %s
            ORDER BY order_no ASC
        """,
            (request_type_id,),
        )
        approvers = [
            int(row["position_id"])
            for row in (cursor.fetchall() or [])
            if row.get("position_id") is not None
        ]

    workflow = []
    for pid in reviewers + approvers:
        if pid not in workflow:
            workflow.append(pid)

    return reviewers, approvers, workflow


def _fetch_workflow_rows(cursor, request_id, request_type_id):
    cursor.execute(
        """
        SELECT COALESCE(order_no, 0) AS order_no, position_id
        FROM request_workflow_reviewers
        WHERE request_id = %s
        ORDER BY COALESCE(order_no, 0) ASC
    """,
        (request_id,),
    )
    reviewer_rows = [
        {"order_no": int(row.get("order_no") or 0), "position_id": int(row.get("position_id") or 0)}
        for row in (cursor.fetchall() or [])
        if row.get("position_id") is not None
    ]

    if not reviewer_rows:
        cursor.execute(
            """
            SELECT COALESCE(order_no, 0) AS order_no, position_id
            FROM request_type_reviewers
            WHERE request_type_id = %s
            ORDER BY COALESCE(order_no, 0) ASC
        """,
            (request_type_id,),
        )
        reviewer_rows = [
            {"order_no": int(row.get("order_no") or 0), "position_id": int(row.get("position_id") or 0)}
            for row in (cursor.fetchall() or [])
            if row.get("position_id") is not None
        ]

    cursor.execute(
        """
        SELECT COALESCE(order_no, 0) AS order_no, position_id
        FROM request_workflow_approvers
        WHERE request_id = %s
        ORDER BY COALESCE(order_no, 0) ASC
    """,
        (request_id,),
    )
    approver_rows = [
        {"order_no": int(row.get("order_no") or 0), "position_id": int(row.get("position_id") or 0)}
        for row in (cursor.fetchall() or [])
        if row.get("position_id") is not None
    ]

    if not approver_rows:
        cursor.execute(
            """
            SELECT COALESCE(order_no, 0) AS order_no, position_id
            FROM request_type_approvers
            WHERE request_type_id = %s
            ORDER BY COALESCE(order_no, 0) ASC
        """,
            (request_type_id,),
        )
        approver_rows = [
            {"order_no": int(row.get("order_no") or 0), "position_id": int(row.get("position_id") or 0)}
            for row in (cursor.fetchall() or [])
            if row.get("position_id") is not None
        ]

    return reviewer_rows, approver_rows


def _group_workflow_rows(rows, stage_type):
    grouped = {}
    for row in (rows or []):
        order_no = int(row.get("order_no") or 0)
        pid = int(row.get("position_id") or 0)
        if pid <= 0:
            continue
        grouped.setdefault(order_no, [])
        if pid not in grouped[order_no]:
            grouped[order_no].append(pid)

    steps = []
    for order_no in sorted(grouped.keys()):
        positions = grouped.get(order_no) or []
        if not positions:
            continue
        steps.append({"stage_type": stage_type, "order_no": order_no, "positions": positions})
    return steps


def get_effective_workflow_steps(cursor, request_id, request_type_id):
    reviewer_rows, approver_rows = _fetch_workflow_rows(cursor, request_id, request_type_id)
    steps = []
    steps.extend(_group_workflow_rows(reviewer_rows, "reviewer"))
    steps.extend(_group_workflow_rows(approver_rows, "approver"))
    return steps


def _get_request_approved_positions(cursor, request_id):
    cursor.execute(
        """
        SELECT DISTINCT actor_position_id
        FROM request_actions
        WHERE request_id = %s
        AND action IN ('APPROVED', 'COO_APPROVED')
        AND actor_position_id IS NOT NULL
    """,
        (request_id,),
    )
    return {
        int(row.get("actor_position_id"))
        for row in (cursor.fetchall() or [])
        if row.get("actor_position_id") is not None
    }


def _get_active_workflow_step_state(steps, current_stage, approved_positions):
    if not steps:
        return None, []

    approved = {int(x) for x in (approved_positions or set())}
    current_stage_int = None
    try:
        if current_stage is not None:
            current_stage_int = int(current_stage)
    except (TypeError, ValueError):
        current_stage_int = None

    chosen_idx = None
    if current_stage_int is not None:
        for idx, step in enumerate(steps):
            if current_stage_int in (step.get("positions") or []):
                chosen_idx = idx
                break

    if chosen_idx is None:
        for idx, step in enumerate(steps):
            pending_positions = [p for p in (step.get("positions") or []) if p not in approved]
            if pending_positions:
                chosen_idx = idx
                break

    if chosen_idx is None:
        return None, []

    step_positions = steps[chosen_idx].get("positions") or []
    pending_positions = [p for p in step_positions if p not in approved]
    if pending_positions:
        return chosen_idx, pending_positions

    for idx in range(chosen_idx + 1, len(steps)):
        next_positions = steps[idx].get("positions") or []
        next_pending = [p for p in next_positions if p not in approved]
        if next_pending:
            return idx, next_pending

    return None, []


def _apply_conditional_high_value_workflow_steps(cursor, request_id, steps):
    base_steps = [
        {
            "stage_type": str(step.get("stage_type") or "approver"),
            "order_no": int(step.get("order_no") or 0),
            "positions": [int(p) for p in (step.get("positions") or []) if int(p) > 0],
        }
        for step in (steps or [])
    ]

    try:
        threshold = parse_amount_decimal(os.environ.get("HIGH_VALUE_APPROVAL_THRESHOLD", "50000"))
    except Exception:
        threshold = Decimal("50000")

    if threshold <= 0:
        return base_steps

    cursor.execute(
        "SELECT COALESCE(company_id, 0) AS company_id, COALESCE(amount, 0) AS amount FROM requests WHERE request_id = %s LIMIT 1",
        (request_id,),
    )
    req_row = cursor.fetchone() or {}
    company_id = int(req_row.get("company_id") or 0)
    amount_value = parse_amount_decimal(req_row.get("amount"))
    if company_id <= 0 or amount_value <= threshold:
        return base_steps

    names_raw = str(os.environ.get("HIGH_VALUE_APPROVER_POSITION_NAMES") or "COO,Chief Operating Officer").strip()
    keywords = [k.strip().lower() for k in re.split(r"[,;]", names_raw) if k.strip()]
    if not keywords:
        return base_steps

    existing_positions = {p for step in base_steps for p in (step.get("positions") or [])}

    cursor.execute(
        "SELECT position_id, position_name FROM positions WHERE company_id = %s",
        (company_id,),
    )
    rows = cursor.fetchall() or []

    extra_positions = []
    for row in rows:
        pid = int((row or {}).get("position_id") or 0)
        pname = str((row or {}).get("position_name") or "").strip().lower()
        if pid <= 0 or not pname or pid in existing_positions:
            continue
        if any(keyword in pname for keyword in keywords):
            extra_positions.append(pid)

    if extra_positions:
        base_steps.append(
            {
                "stage_type": "approver",
                "order_no": (base_steps[-1].get("order_no") if base_steps else 0) + 1,
                "positions": extra_positions,
            }
        )

    return base_steps


_request_action_message_meta_cache = {"checked": False, "max_len": None}


def _truncate_request_action_message(cursor, message):
    text = str(message or "").strip()
    if not text:
        return None

    cached_checked = bool(_request_action_message_meta_cache.get("checked"))
    max_len = _request_action_message_meta_cache.get("max_len") if cached_checked else None

    if not cached_checked:
        try:
            cursor.execute("SHOW COLUMNS FROM request_actions LIKE 'message'")
            col = cursor.fetchone() or {}
            col_type = str(col.get("Type") or col.get("type") or "").strip().lower()
            m = re.search(r"\((\d+)\)", col_type)
            _request_action_message_meta_cache["max_len"] = int(m.group(1)) if m else None
        except Exception:
            _request_action_message_meta_cache["max_len"] = None
        finally:
            _request_action_message_meta_cache["checked"] = True
            max_len = _request_action_message_meta_cache.get("max_len")

    if isinstance(max_len, int) and max_len > 0 and len(text) > max_len:
        return text[:max_len]
    return text


def _apply_conditional_high_value_workflow(cursor, request_id, workflow):
    chain = list(workflow or [])

    try:
        threshold = parse_amount_decimal(os.environ.get("HIGH_VALUE_APPROVAL_THRESHOLD", "50000"))
    except Exception:
        threshold = Decimal("50000")

    if threshold <= 0:
        return chain

    cursor.execute(
        "SELECT COALESCE(company_id, 0) AS company_id, COALESCE(amount, 0) AS amount FROM requests WHERE request_id = %s LIMIT 1",
        (request_id,),
    )
    req_row = cursor.fetchone() or {}

    company_id = int(req_row.get("company_id") or 0)
    amount_value = parse_amount_decimal(req_row.get("amount"))
    if company_id <= 0 or amount_value <= threshold:
        return chain

    names_raw = str(os.environ.get("HIGH_VALUE_APPROVER_POSITION_NAMES") or "COO,Chief Operating Officer").strip()
    keywords = [k.strip().lower() for k in re.split(r"[,;]", names_raw) if k.strip()]
    if not keywords:
        return chain

    cursor.execute(
        "SELECT position_id, position_name FROM positions WHERE company_id = %s",
        (company_id,),
    )
    rows = cursor.fetchall() or []

    for row in rows:
        pid = int((row or {}).get("position_id") or 0)
        pname = str((row or {}).get("position_name") or "").strip().lower()
        if pid <= 0 or not pname:
            continue
        if any(keyword in pname for keyword in keywords) and pid not in chain:
            chain.append(pid)

    return chain


def apply_send_back_visibility(cursor, request_rows):
    rows = request_rows or []

    for row in rows:
        row["can_send_back"] = 0

        req_id = row.get("request_id")
        stage_position_id = row.get("stage_position_id")
        req_type_id = row.get("request_type_id")

        if req_id is None or stage_position_id is None:
            continue

        try:
            req_id = int(req_id)
            stage_position_id = int(stage_position_id)
        except (TypeError, ValueError):
            continue

        if req_type_id is None:
            cursor.execute(
                "SELECT request_type_id FROM requests WHERE request_id = %s LIMIT 1",
                (req_id,),
            )
            req_type_row = cursor.fetchone() or {}
            req_type_id = req_type_row.get("request_type_id")

        try:
            req_type_id = int(req_type_id)
        except (TypeError, ValueError):
            continue

        try:
            _reviewers, _approvers, workflow = get_effective_workflow_positions(
                cursor,
                request_id=req_id,
                request_type_id=req_type_id,
            )
        except Exception:
            workflow = []

        if not workflow:
            continue

        try:
            row["can_send_back"] = 1 if workflow.index(stage_position_id) > 0 else 0
        except ValueError:
            row["can_send_back"] = 0

    return rows


ALLOWED_ADMIN_PIN_ROLES = {"AssistantAdmin", "Admin", "SuperAdmin"}
ALLOWED_BUDGET_REPORT_ROLES = {"Admin", "SuperAdmin", "SBO"}
ALLOWED_BUDGET_SUBMIT_KEYWORDS = {"secretary", "representative", "purchasing"}
BUDGET_RELEASE_ACTOR_KEYWORDS = {"representative", "purchasing"}
COO_KEYWORDS = {"coo", "chief operating officer"}
ALLOWED_FORM_BLOCK_TYPES = {"heading", "text", "textarea", "number", "date", "shape", "table", "signature"}
ALLOWED_FORM_SHAPES = {"line", "box"}
ALLOWED_FORM_COLUMN_TYPES = {"text", "number"}
ADMIN_PIN_MAX_FAILED_ATTEMPTS = 5
ADMIN_PIN_WARNING_ATTEMPTS = 3
ADMIN_PIN_OTP_COOLDOWN_SECONDS = 60
ADMIN_PIN_OTP_MAX_AGE_SECONDS = 60 * 10
COO_ACTION_TOKEN_MAX_AGE_SECONDS = int(os.environ.get("COO_ACTION_TOKEN_MAX_AGE_SECONDS", str(60 * 60 * 24)))
BUDGET_DEFAULT_TOTAL = Decimal("100000.00")
DEFAULT_COMPANY_NAME = str(os.environ.get("DEFAULT_COMPANY_NAME") or "Default Organization").strip() or "Default Organization"
DEFAULT_DEV_EMAIL = str(os.environ.get("DEV_EMAIL") or os.environ.get("name") or "").strip().lower()
DEFAULT_DEV_PASSWORD = str(os.environ.get("DEV_PASSWORD") or os.environ.get("password") or "").strip()
DEFAULT_SAAS_EMAIL = str(os.environ.get("SAAS_EMAIL") or "").strip().lower()
DEFAULT_SAAS_PASSWORD = str(os.environ.get("SAAS_PASSWORD") or "").strip()

SAAS_PLAN_DEFINITIONS = {
    "FREE": {"monthly_price": Decimal("0.00"), "seats_limit": 10, "requests_limit": 200},
    "PRO": {"monthly_price": Decimal("299.00"), "seats_limit": 100, "requests_limit": 5000},
    "ENTERPRISE": {"monthly_price": Decimal("499.00"), "seats_limit": 1000, "requests_limit": 100000},
}

TENANT_PERMISSION_CATALOG = [
    ("manage_users", "Manage users"),
    ("manage_departments", "Manage departments"),
    ("manage_roles", "Manage roles"),
    ("manage_request_types", "Manage request types"),
    ("view_reports", "View reports"),
    ("manage_budget", "Budget management"),
    ("view_audit_logs", "View audit logs"),
    ("view_notifications", "View notifications"),
]

DEFAULT_ROLE_PERMISSIONS = {
    "SuperAdmin": {"manage_users", "manage_departments", "manage_roles", "manage_request_types", "view_reports", "manage_budget", "view_audit_logs", "view_notifications"},
    "IT": {"manage_users", "manage_departments", "manage_roles", "manage_request_types", "view_reports", "manage_budget", "view_audit_logs", "view_notifications"},
    "Admin": {"manage_users", "manage_departments", "manage_request_types", "view_reports", "manage_budget", "view_notifications"},
    "AssistantAdmin": {"manage_users", "manage_request_types", "view_reports", "manage_budget", "view_notifications"},
    "User": set(),
    "Reviewer": {"view_notifications"},
    "Dean": {"view_notifications"},
    "SBO": {"manage_budget", "view_notifications"},
}

_admin_pin_schema_checked = False
_user_account_control_schema_checked = False
_budget_schema_checked = False
_budget_request_schema_checked = False
_department_budget_schema_checked = False
_saas_owner_schema_checked = False
_bug_reports_schema_checked = False
_activity_log_schema_checked = False
_user_saved_signature_schema_checked = False
_coo_special_approval_schema_checked = False
_request_type_form_schema_checked = False
_request_form_submission_schema_checked = False
_tenant_schema_checked = False
_system_maintenance_schema_checked = False
_finance_amount_editor_schema_checked = False
_stage_reminder_schema_checked = False
_system_maintenance_cache = {
    "enabled": False,
    "reason": "",
    "updated_by": "",
    "updated_at": "",
    "expires_at": 0.0,
}
SYSTEM_MAINTENANCE_CACHE_TTL_SECONDS = 5


def _slugify_company_name(value):
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return text or "org"


def _escape_mysql_identifier(value):
    return "`" + str(value or "").replace("`", "``") + "`"


def _table_has_column(cursor, table_name, column_name):
    cursor.execute("SHOW COLUMNS FROM " + _escape_mysql_identifier(table_name) + " LIKE %s", (column_name,))
    return bool(cursor.fetchone())


def _ensure_company_scoped_unique_name(cursor, table_name, name_column, company_column="company_id"):
    table_identifier = _escape_mysql_identifier(table_name)
    company_identifier = _escape_mysql_identifier(company_column)
    name_identifier = _escape_mysql_identifier(name_column)
    target_index_name = f"uq_{table_name}_{company_column}_{name_column}".lower()
    cursor.execute("SHOW INDEX FROM " + table_identifier)
    index_rows = cursor.fetchall() or []
    has_target = False

    grouped = {}
    for row in index_rows:
        key_name = row.get("Key_name")
        seq_in_index = int(row.get("Seq_in_index") or 0)
        column_name = row.get("Column_name")
        non_unique_raw = row.get("Non_unique")
        non_unique = int(1 if non_unique_raw is None else non_unique_raw)
        if str(key_name or "").strip().lower() == target_index_name:
            has_target = True
        grouped.setdefault(key_name, {"non_unique": non_unique, "columns": []})
        grouped[key_name]["columns"].append((seq_in_index, column_name))

    target_columns = [company_column, name_column]

    legacy_index_name = str(name_column or "").strip().lower()

    for key_name, meta in grouped.items():
        cols = [col for _, col in sorted(meta["columns"], key=lambda item: item[0])]
        is_unique = meta.get("non_unique", 1) == 0
        normalized_key = str(key_name or "").strip().lower()

        if is_unique and cols == target_columns:
            has_target = True
            continue

        # Drop legacy global unique index on name only.
        if is_unique and cols == [name_column] and normalized_key != "primary":
            cursor.execute("ALTER TABLE " + table_identifier + " DROP INDEX `" + str(key_name or "").replace("`", "``") + "`")
            continue

        # Extra guard for schemas where the legacy index key name equals the column name.
        if is_unique and normalized_key == legacy_index_name and normalized_key != "primary":
            try:
                cursor.execute("ALTER TABLE " + table_identifier + " DROP INDEX `" + str(key_name or "").replace("`", "``") + "`")
            except mysql.connector.Error as exc:
                if getattr(exc, "errno", None) != 1091:
                    raise

    if not has_target:
        try:
            cursor.execute(
                "ALTER TABLE "
                + table_identifier
                + " ADD UNIQUE KEY uq_"
                + str(table_name)
                + "_"
                + str(company_column)
                + "_"
                + str(name_column)
                + " ("
                + company_identifier
                + ", "
                + name_identifier
                + ")"
            )
        except mysql.connector.Error as exc:
            # Ignore duplicate index name so startup migration remains idempotent.
            if getattr(exc, "errno", None) != 1061:
                raise


def get_current_company_id():
    raw_value = session.get("company_id")
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return 0


def ensure_session_company_context(cursor):
    company_id = get_current_company_id()
    if company_id > 0:
        return company_id

    email = (session.get("email") or "").strip().lower()
    if not email:
        return 0

    cursor.execute(
        """
        SELECT
            u.company_id,
            COALESCE(o.company_name, '') AS company_name
        FROM users u
        LEFT JOIN organizations o ON o.company_id = u.company_id
        WHERE LOWER(TRIM(u.email)) = %s
        LIMIT 1
        """,
        (email,),
    )
    row = cursor.fetchone() or {}
    try:
        company_id = int(row.get("company_id") or 0)
    except (TypeError, ValueError):
        company_id = 0

    if company_id > 0:
        session["company_id"] = company_id
        session["company_name"] = (row.get("company_name") or "").strip()

    return company_id


def ensure_default_role_permissions(cursor, company_id):
    if int(company_id or 0) <= 0:
        return

    cursor.execute(
        """
        SELECT role_id, role_name
        FROM roles
        WHERE company_id = %s
        """,
        (company_id,),
    )
    rows = cursor.fetchall() or []

    for row in rows:
        role_id = row.get("role_id")
        role_name = str(row.get("role_name") or "").strip()
        if not role_id or not role_name:
            continue

        for permission_key in sorted(DEFAULT_ROLE_PERMISSIONS.get(role_name, set())):
            cursor.execute(
                """
                INSERT IGNORE INTO role_permissions (role_id, permission_key)
                VALUES (%s, %s)
                """,
                (role_id, permission_key),
            )


def ensure_dev_user_account(cursor, company_id):
    if int(company_id or 0) <= 0:
        return

    dev_email = DEFAULT_DEV_EMAIL
    dev_password = DEFAULT_DEV_PASSWORD
    if not dev_email or not dev_password:
        return

    if not re.match(r"^[a-z0-9.%+_-]+@[a-z0-9.-]+\.[a-z]{2,}$", dev_email):
        return

    cursor.execute(
        "SELECT role_id FROM roles WHERE company_id = %s AND LOWER(TRIM(role_name)) = 'dev' LIMIT 1",
        (company_id,),
    )
    role_row = cursor.fetchone() or {}
    dev_role_id = int(role_row.get("role_id") or 0)
    if dev_role_id <= 0:
        cursor.execute("INSERT IGNORE INTO roles (role_name, company_id) VALUES ('dev', %s)", (company_id,))
        cursor.execute(
            "SELECT role_id FROM roles WHERE company_id = %s AND LOWER(TRIM(role_name)) = 'dev' LIMIT 1",
            (company_id,),
        )
        role_row = cursor.fetchone() or {}
        dev_role_id = int(role_row.get("role_id") or 0)

    cursor.execute(
        "SELECT position_id FROM positions WHERE company_id = %s AND LOWER(TRIM(position_name)) = 'developer' LIMIT 1",
        (company_id,),
    )
    position_row = cursor.fetchone() or {}
    dev_position_id = int(position_row.get("position_id") or 0)
    if dev_position_id <= 0:
        cursor.execute(
            "INSERT IGNORE INTO positions (position_name, company_id) VALUES ('Developer', %s)",
            (company_id,),
        )
        cursor.execute(
            "SELECT position_id FROM positions WHERE company_id = %s AND LOWER(TRIM(position_name)) = 'developer' LIMIT 1",
            (company_id,),
        )
        position_row = cursor.fetchone() or {}
        dev_position_id = int(position_row.get("position_id") or 0)

    cursor.execute(
        "SELECT dept_id FROM departments WHERE company_id = %s ORDER BY dept_id ASC LIMIT 1",
        (company_id,),
    )
    dept_row = cursor.fetchone() or {}
    dev_dept_id = int(dept_row.get("dept_id") or 0)
    if dev_dept_id <= 0:
        cursor.execute(
            "INSERT INTO departments (dept_name, company_id) VALUES ('IT', %s)",
            (company_id,),
        )
        dev_dept_id = int(cursor.lastrowid or 0)

    if dev_role_id <= 0 or dev_position_id <= 0 or dev_dept_id <= 0:
        return

    cursor.execute(
        "SELECT user_id, password FROM users WHERE LOWER(TRIM(email)) = %s LIMIT 1",
        (dev_email,),
    )
    existing_user = cursor.fetchone() or {}

    if existing_user:
        user_id = int(existing_user.get("user_id") or 0)
        existing_hash = str(existing_user.get("password") or "")
        password_ok = verify_user_password(existing_hash, dev_password) if existing_hash else False
        if password_ok:
            cursor.execute(
                """
                UPDATE users
                SET dept_id = %s, role_id = %s, position_id = %s, company_id = %s
                WHERE user_id = %s
                """,
                (dev_dept_id, dev_role_id, dev_position_id, company_id, user_id),
            )
        else:
            cursor.execute(
                """
                UPDATE users
                SET password = %s, dept_id = %s, role_id = %s, position_id = %s, company_id = %s
                WHERE user_id = %s
                """,
                (hash_user_password(dev_password), dev_dept_id, dev_role_id, dev_position_id, company_id, user_id),
            )
        return

    cursor.execute(
        """
        INSERT INTO users (email, password, dept_id, role_id, position_id, company_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (dev_email, hash_user_password(dev_password), dev_dept_id, dev_role_id, dev_position_id, company_id),
    )


def ensure_tenant_schema(cursor, conn):
    global _tenant_schema_checked

    if _tenant_schema_checked:
        return

    if not _table_has_column(cursor, "users", "company_id"):
        cursor.execute("ALTER TABLE users ADD COLUMN company_id INT NULL")
    if not _table_has_column(cursor, "departments", "company_id"):
        cursor.execute("ALTER TABLE departments ADD COLUMN company_id INT NULL")
    if not _table_has_column(cursor, "roles", "company_id"):
        cursor.execute("ALTER TABLE roles ADD COLUMN company_id INT NULL")
    if not _table_has_column(cursor, "positions", "company_id"):
        cursor.execute("ALTER TABLE positions ADD COLUMN company_id INT NULL")
    if not _table_has_column(cursor, "requests", "company_id"):
        cursor.execute("ALTER TABLE requests ADD COLUMN company_id INT NULL")
    if not _table_has_column(cursor, "request_types", "company_id"):
        cursor.execute("ALTER TABLE request_types ADD COLUMN company_id INT NULL")

    _ensure_company_scoped_unique_name(cursor, "departments", "dept_name")
    _ensure_company_scoped_unique_name(cursor, "roles", "role_name")
    _ensure_company_scoped_unique_name(cursor, "positions", "position_name")

    default_slug = _slugify_company_name(DEFAULT_COMPANY_NAME)
    cursor.execute(
        """
        INSERT INTO organizations (company_name, company_slug)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE company_name = VALUES(company_name)
        """,
        (DEFAULT_COMPANY_NAME, default_slug),
    )

    cursor.execute("SELECT company_id FROM organizations WHERE company_slug = %s LIMIT 1", (default_slug,))
    default_org = cursor.fetchone() or {}
    default_company_id = int(default_org.get("company_id") or 0)

    if default_company_id > 0:
        cursor.execute("UPDATE users SET company_id = %s WHERE company_id IS NULL", (default_company_id,))
        cursor.execute("UPDATE departments SET company_id = %s WHERE company_id IS NULL", (default_company_id,))
        cursor.execute("UPDATE roles SET company_id = %s WHERE company_id IS NULL", (default_company_id,))
        cursor.execute("UPDATE positions SET company_id = %s WHERE company_id IS NULL", (default_company_id,))
        cursor.execute("UPDATE request_types SET company_id = %s WHERE company_id IS NULL", (default_company_id,))
        cursor.execute(
            """
            UPDATE requests r
            JOIN users u ON u.user_id = r.user_id
            SET r.company_id = u.company_id
            WHERE r.company_id IS NULL
            """
        )
        ensure_default_role_permissions(cursor, default_company_id)
        ensure_dev_user_account(cursor, default_company_id)

    conn.commit()
    _tenant_schema_checked = True


def ensure_contact_messages_schema(cursor, conn):
    """Ensure contact_messages table exists for landing page inquiries"""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS contact_messages (
            contact_id INT AUTO_INCREMENT PRIMARY KEY,
            organization_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(20) NULL,
            inquiry_type VARCHAR(50) NOT NULL,
            message LONGTEXT NOT NULL,
            status ENUM('new', 'read', 'replied') DEFAULT 'new',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_status (status),
            INDEX idx_created_at (created_at),
            INDEX idx_email (email)
        )
        """
    )
    conn.commit()


def has_role_permission(cursor, permission_key, role_id=None):
    permission_key = str(permission_key or "").strip().lower()
    if not permission_key:
        return False

    role_name = (session.get("role") or "").strip()
    if role_name == "SuperAdmin":
        return True

    if role_id is None:
        role_id = session.get("role_id")

    try:
        role_id = int(role_id)
    except (TypeError, ValueError):
        return False

    cursor.execute(
        """
        SELECT 1
        FROM role_permissions
        WHERE role_id = %s AND permission_key = %s
        LIMIT 1
        """,
        (role_id, permission_key),
    )
    return bool(cursor.fetchone())


def can_manage_request_types(cursor, role=None, role_id=None):
    return has_role_permission(cursor, "manage_request_types", role_id=role_id)


def can_view_reports(cursor, role=None, role_id=None):
    return has_role_permission(cursor, "view_reports", role_id=role_id)


def can_manage_budget(cursor, role=None, role_id=None):
    return has_role_permission(cursor, "manage_budget", role_id=role_id)


def can_use_admin_pin(role=None):
    effective_role = (role or session.get("role") or "").strip()
    return effective_role in ALLOWED_ADMIN_PIN_ROLES


def is_saas_owner_user():
    role = (session.get("role") or "").strip().lower()
    email = (session.get("email") or "").strip().lower()

    if role in {"dev", "saasowner", "saas_owner", "platformowner"}:
        return True
    if DEFAULT_DEV_EMAIL and email == DEFAULT_DEV_EMAIL:
        return True
    if DEFAULT_SAAS_EMAIL and email == DEFAULT_SAAS_EMAIL:
        return True
    return False


def _normalize_plan_name(value):
    plan = str(value or "").strip().upper()
    if plan in SAAS_PLAN_DEFINITIONS:
        return plan
    return "FREE"


def ensure_saas_owner_schema(cursor, conn):
    global _saas_owner_schema_checked

    if _saas_owner_schema_checked:
        return

    cursor.execute(
        """
        INSERT INTO tenant_subscriptions (company_id, plan_name, subscription_status, monthly_price, seats_limit, requests_limit)
        SELECT o.company_id, 'FREE', 'ACTIVE', 0.00, 10, 200
        FROM organizations o
        LEFT JOIN tenant_subscriptions ts ON ts.company_id = o.company_id
        WHERE ts.company_id IS NULL
        """
    )

    conn.commit()
    _saas_owner_schema_checked = True


def ensure_bug_reports_schema(cursor, conn):
    global _bug_reports_schema_checked

    if _bug_reports_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS bug_reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_id INT NULL,
            reporter_email VARCHAR(255) NOT NULL,
            reporter_role VARCHAR(120) NULL,
            description TEXT NOT NULL,
            image_blob LONGBLOB NULL,
            image_mime VARCHAR(120) NULL,
            image_name VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_bug_reports_company (company_id),
            INDEX idx_bug_reports_created_at (created_at)
        )
        """
    )

    conn.commit()
    _bug_reports_schema_checked = True


def ensure_system_maintenance_schema(cursor, conn):
    global _system_maintenance_schema_checked

    if _system_maintenance_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS system_runtime_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            setting_key VARCHAR(120) NOT NULL,
            setting_value TEXT NULL,
            updated_by_email VARCHAR(255) NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_system_runtime_settings_key (setting_key)
        )
        """
    )

    conn.commit()
    _system_maintenance_schema_checked = True


def _normalize_maintenance_reason(value):
    text = str(value or "").strip()
    return text[:500]


def _read_system_maintenance_state(cursor):
    cursor.execute(
        """
        SELECT setting_value, updated_by_email, updated_at
        FROM system_runtime_settings
        WHERE setting_key = 'system_maintenance'
        LIMIT 1
        """
    )
    row = cursor.fetchone() or {}

    payload = {}
    raw_value = row.get("setting_value")
    if raw_value:
        try:
            payload = json.loads(raw_value)
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}

    enabled = bool(payload.get("enabled"))
    reason = _normalize_maintenance_reason(payload.get("reason"))
    updated_by = str(row.get("updated_by_email") or "").strip()
    updated_at_value = row.get("updated_at")
    updated_at = ""
    if updated_at_value is not None:
        updated_at = str(updated_at_value)

    return {
        "enabled": enabled,
        "reason": reason,
        "updated_by": updated_by,
        "updated_at": updated_at,
    }


def get_system_maintenance_state(use_cache=True):
    global _system_maintenance_cache

    now = time.time()
    if use_cache and now < float(_system_maintenance_cache.get("expires_at") or 0.0):
        return {
            "enabled": bool(_system_maintenance_cache.get("enabled")),
            "reason": str(_system_maintenance_cache.get("reason") or ""),
            "updated_by": str(_system_maintenance_cache.get("updated_by") or ""),
            "updated_at": str(_system_maintenance_cache.get("updated_at") or ""),
        }

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        ensure_system_maintenance_schema(cursor, conn)
        state = _read_system_maintenance_state(cursor)
    except Exception:
        logger.exception("get_system_maintenance_state failed")
        state = {
            "enabled": False,
            "reason": "",
            "updated_by": "",
            "updated_at": "",
        }
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

    _system_maintenance_cache = {
        "enabled": bool(state.get("enabled")),
        "reason": str(state.get("reason") or ""),
        "updated_by": str(state.get("updated_by") or ""),
        "updated_at": str(state.get("updated_at") or ""),
        "expires_at": now + float(SYSTEM_MAINTENANCE_CACHE_TTL_SECONDS),
    }
    return state


def set_system_maintenance_state(enabled, reason, updated_by_email):
    global _system_maintenance_cache

    normalized_enabled = bool(enabled)
    normalized_reason = _normalize_maintenance_reason(reason)
    if normalized_enabled and not normalized_reason:
        normalized_reason = "System is temporarily paused for maintenance and bug fixes."

    payload = {
        "enabled": normalized_enabled,
        "reason": normalized_reason,
    }

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_system_maintenance_schema(cursor, conn)
        cursor.execute(
            """
            INSERT INTO system_runtime_settings (setting_key, setting_value, updated_by_email)
            VALUES ('system_maintenance', %s, %s)
            ON DUPLICATE KEY UPDATE
                setting_value = VALUES(setting_value),
                updated_by_email = VALUES(updated_by_email),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                json.dumps(payload, ensure_ascii=True),
                str(updated_by_email or "").strip() or None,
            ),
        )
        conn.commit()
        state = _read_system_maintenance_state(cursor)
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    _system_maintenance_cache = {
        "enabled": bool(state.get("enabled")),
        "reason": str(state.get("reason") or ""),
        "updated_by": str(state.get("updated_by") or ""),
        "updated_at": str(state.get("updated_at") or ""),
        "expires_at": time.time() + float(SYSTEM_MAINTENANCE_CACHE_TTL_SECONDS),
    }
    return state


def is_system_maintenance_bypass_user():
    role = (session.get("role") or "").strip().lower()
    email = (session.get("email") or "").strip().lower()

    if role in {"dev", "saasowner", "saas_owner", "platformowner"}:
        return True
    if DEFAULT_DEV_EMAIL and email == DEFAULT_DEV_EMAIL:
        return True
    if DEFAULT_SAAS_EMAIL and email == DEFAULT_SAAS_EMAIL:
        return True
    return False


def _normalize_broadcast_title(value):
    text = str(value or "").strip()
    if not text:
        text = "System Broadcast"
    return text[:120]


def _normalize_broadcast_message(value):
    text = str(value or "").strip()
    return text[:1000]


def create_system_broadcast(title, message, actor_email=""):
    normalized_title = _normalize_broadcast_title(title)
    normalized_message = _normalize_broadcast_message(message)
    if not normalized_message:
        raise ValueError("Broadcast message cannot be empty")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_activity_log_schema(cursor, conn)
        cursor.execute(
            """
            INSERT INTO activity_logs (title, description, company_id, actor_email)
            VALUES (%s, %s, NULL, %s)
            """,
            (
                normalized_title,
                f"BROADCAST: {normalized_message}",
                str(actor_email or "").strip() or None,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def _clean_broadcast_description(value):
    text = str(value or "").strip()
    if text.lower().startswith("broadcast:"):
        text = text.split(":", 1)[1].strip()
    return text


def fetch_system_broadcast_rows(cursor, limit=50):
    try:
        safe_limit = int(limit or 50)
    except (TypeError, ValueError):
        safe_limit = 50
    safe_limit = max(1, min(safe_limit, 500))

    cursor.execute(
        """
        SELECT
            CONCAT('B-', log_id) AS id,
            title,
            description,
            created_at,
            actor_email
        FROM activity_logs
        WHERE LOWER(COALESCE(title, '')) IN ('system broadcast', 'system announcement')
           OR LOWER(COALESCE(description, '')) LIKE 'broadcast:%'
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (safe_limit,),
    )
    rows = cursor.fetchall() or []

    normalized = []
    for row in rows:
        normalized.append(
            {
                "id": row.get("id"),
                "title": _normalize_broadcast_title(row.get("title") or "System Broadcast"),
                "description": _clean_broadcast_description(row.get("description")),
                "created_at": row.get("created_at"),
                "actor_email": str(row.get("actor_email") or "").strip(),
            }
        )
    return normalized


def get_company_subscription_limits(cursor, company_id):
    normalized_company_id = int(company_id or 0)
    if normalized_company_id <= 0:
        return {
            "plan_name": "FREE",
            "subscription_status": "ACTIVE",
            "seats_limit": int(SAAS_PLAN_DEFINITIONS["FREE"].get("seats_limit") or 0),
            "requests_limit": int(SAAS_PLAN_DEFINITIONS["FREE"].get("requests_limit") or 0),
        }

    cursor.execute(
        """
        SELECT plan_name, subscription_status, seats_limit, requests_limit
        FROM tenant_subscriptions
        WHERE company_id = %s
        LIMIT 1
        """,
        (normalized_company_id,),
    )
    row = cursor.fetchone() or {}
    plan_name = _normalize_plan_name(row.get("plan_name"))
    plan_defaults = SAAS_PLAN_DEFINITIONS.get(plan_name, SAAS_PLAN_DEFINITIONS["FREE"])

    seats_limit = row.get("seats_limit")
    requests_limit = row.get("requests_limit")

    if seats_limit is None:
        seats_limit = int(plan_defaults.get("seats_limit") or 0)
    else:
        seats_limit = int(seats_limit or 0)

    if requests_limit is None:
        requests_limit = int(plan_defaults.get("requests_limit") or 0)
    else:
        requests_limit = int(requests_limit or 0)

    subscription_status = str(row.get("subscription_status") or "ACTIVE").strip().upper() or "ACTIVE"
    return {
        "plan_name": plan_name,
        "subscription_status": subscription_status,
        "seats_limit": seats_limit,
        "requests_limit": requests_limit,
    }


def check_company_user_seat_capacity(cursor, company_id):
    normalized_company_id = int(company_id or 0)
    if normalized_company_id <= 0:
        return False, "Invalid company context"

    limits = get_company_subscription_limits(cursor, normalized_company_id)
    status = (limits.get("subscription_status") or "ACTIVE").strip().upper()
    if status != "ACTIVE":
        return False, "Subscription is not active for this company"

    seats_limit = int(limits.get("seats_limit") or 0)
    if seats_limit <= 0:
        return True, ""

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE company_id = %s", (normalized_company_id,))
    seat_count = int((cursor.fetchone() or {}).get("count") or 0)
    if seat_count >= seats_limit:
        return False, f"Seat limit reached for plan {limits.get('plan_name')}. Please upgrade your subscription."

    return True, ""


def check_company_request_capacity(cursor, company_id):
    normalized_company_id = int(company_id or 0)
    if normalized_company_id <= 0:
        return False, "Invalid company context"

    limits = get_company_subscription_limits(cursor, normalized_company_id)
    status = (limits.get("subscription_status") or "ACTIVE").strip().upper()
    if status != "ACTIVE":
        return False, "Subscription is not active for this company"

    requests_limit = int(limits.get("requests_limit") or 0)
    if requests_limit <= 0:
        return True, ""

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM requests
        WHERE company_id = %s
          AND created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
          AND created_at < DATE_ADD(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 1 MONTH)
        """,
        (normalized_company_id,),
    )
    month_count = int((cursor.fetchone() or {}).get("count") or 0)
    if month_count >= requests_limit:
        return False, f"Monthly request limit reached for plan {limits.get('plan_name')}. Please upgrade your subscription."

    return True, ""


def can_use_budget_reports(role=None, position=None, dept=None):
    effective_role = (role or session.get("role") or "").strip()
    effective_position = (position or session.get("position") or "").strip()
    effective_dept = (dept or session.get("dept") or "").strip()

    if effective_role == "AssistantAdmin":
        return effective_position == "SBO" and bool(effective_dept)

    if effective_role == "SBO":
        return bool(effective_dept)

    return effective_role in ALLOWED_BUDGET_REPORT_ROLES


def get_budget_scope_department(role=None, position=None, dept=None):
    effective_role = (role or session.get("role") or "").strip()
    effective_position = (position or session.get("position") or "").strip()
    effective_dept = (dept or session.get("dept") or "").strip()

    if effective_role == "AssistantAdmin" and effective_position == "SBO":
        return effective_dept
    if effective_role == "SBO":
        return effective_dept
    return ""


def can_submit_budget_request(role=None, position=None):
    role_text = (role or session.get("role") or "").strip().lower()
    position_text = (position or session.get("position") or "").strip().lower()
    return any(keyword in role_text for keyword in ALLOWED_BUDGET_SUBMIT_KEYWORDS) or any(
        keyword in position_text for keyword in ALLOWED_BUDGET_SUBMIT_KEYWORDS
    )


def can_use_secretary_budget_fields(role=None, position=None):
    position_text = (position or session.get("position") or "").strip().lower()
    role_text = (role or session.get("role") or "").strip().lower()
    return ("secretary" in position_text) or ("secretary" in role_text)


def can_release_budget_on_completion(role=None, position=None):
    role_text = (role or session.get("role") or "").strip().lower()
    position_text = (position or session.get("position") or "").strip().lower()
    return any(keyword in role_text for keyword in BUDGET_RELEASE_ACTOR_KEYWORDS) or any(
        keyword in position_text for keyword in BUDGET_RELEASE_ACTOR_KEYWORDS
    )


def is_coo_user(role=None, position=None):
    role_text = (role or session.get("role") or "").strip().lower()
    position_text = (position or session.get("position") or "").strip().lower()
    return any(keyword in role_text for keyword in COO_KEYWORDS) or any(
        keyword in position_text for keyword in COO_KEYWORDS
    )


def is_coo_position_id(cursor, position_id):
    try:
        normalized_position_id = int(position_id or 0)
    except (TypeError, ValueError):
        return False

    if normalized_position_id <= 0:
        return False

    try:
        cursor.execute(
            "SELECT COALESCE(position_name, '') AS position_name FROM positions WHERE position_id = %s LIMIT 1",
            (normalized_position_id,),
        )
        row = cursor.fetchone() or {}
        position_name = str(row.get("position_name") or "").strip().lower()
        return any(keyword in position_name for keyword in COO_KEYWORDS)
    except Exception:
        return False


def queue_coo_if_stage_is_coo(cursor, conn, request_id, stage_position_id, requested_by_email=""):
    """Queue/send COO special approval when a request is currently at a COO stage."""
    if not is_coo_position_id(cursor, stage_position_id):
        return {"queued": False, "notified": 0, "reason": "stage_not_coo"}

    try:
        return queue_coo_special_approval(
            cursor,
            conn,
            request_id,
            requested_by_email=requested_by_email,
        )
    except Exception:
        logger.exception("queue_coo_if_stage_is_coo failed")
        return {"queued": False, "notified": 0, "reason": "queue_error"}


def normalize_request_budget(value):
    text = str(value or "").strip().lower()
    if text == "department budget":
        return "Department Budget"
    if text == "student budget":
        return "Student Budget"
    return ""


def _coerce_first_value(row, key, fallback=0):
    if row is None:
        return fallback
    if isinstance(row, dict):
        return row.get(key, fallback)
    if isinstance(row, (list, tuple)) and row:
        return row[0]
    return fallback


def ensure_admin_pin_schema(cursor, conn):
    global _admin_pin_schema_checked

    if _admin_pin_schema_checked:
        return

    _admin_pin_schema_checked = True


def ensure_user_account_control_schema(cursor, conn):
    global _user_account_control_schema_checked

    if _user_account_control_schema_checked:
        return

    _user_account_control_schema_checked = True


def ensure_activity_log_schema(cursor, conn):
    global _activity_log_schema_checked

    if _activity_log_schema_checked:
        return

    if not _table_has_column(cursor, "activity_logs", "company_id"):
        cursor.execute("ALTER TABLE activity_logs ADD COLUMN company_id INT NULL")

    if not _table_has_column(cursor, "activity_logs", "actor_email"):
        cursor.execute("ALTER TABLE activity_logs ADD COLUMN actor_email VARCHAR(255) NULL")

    conn.commit()
    _activity_log_schema_checked = True


def ensure_user_saved_signature_schema(cursor, conn):
    global _user_saved_signature_schema_checked

    if _user_saved_signature_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS user_saved_signatures (
            user_id INT NOT NULL PRIMARY KEY,
            company_id INT NULL,
            signature_png LONGBLOB NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_user_saved_signatures_company (company_id)
        )
        """
    )

    conn.commit()
    _user_saved_signature_schema_checked = True


def ensure_finance_amount_editor_schema(cursor, conn):
    global _finance_amount_editor_schema_checked

    if _finance_amount_editor_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS finance_amount_editors (
            member_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            user_id INT NOT NULL,
            added_by_email VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_finance_amount_editors_company_user (company_id, user_id),
            INDEX idx_finance_amount_editors_company (company_id),
            INDEX idx_finance_amount_editors_user (user_id)
        )
        """
    )

    conn.commit()
    _finance_amount_editor_schema_checked = True


def ensure_it_approval_team_schema(cursor, conn):
    global _it_approval_team_schema_checked

    try:
        _it_approval_team_schema_checked
    except NameError:
        _it_approval_team_schema_checked = False

    if _it_approval_team_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS it_approval_positions (
            member_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            position_id INT NOT NULL,
            added_by_email VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_it_approval_positions_company_position (company_id, position_id),
            INDEX idx_it_approval_positions_company (company_id),
            INDEX idx_it_approval_positions_position (position_id)
        )
        """
    )

    conn.commit()
    _it_approval_team_schema_checked = True


def ensure_stage_reminder_schema(cursor, conn):
    global _stage_reminder_schema_checked

    if _stage_reminder_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_stage_reminders (
            reminder_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            request_id INT NOT NULL,
            company_id INT NOT NULL,
            position_id INT NOT NULL,
            reminder_date DATE NOT NULL,
            recipients_json LONGTEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_request_stage_daily (request_id, position_id, reminder_date),
            INDEX idx_request_stage_reminders_company (company_id),
            INDEX idx_request_stage_reminders_position (position_id)
        )
        """
    )

    conn.commit()
    _stage_reminder_schema_checked = True


def ensure_budget_schema(cursor, conn):
    global _budget_schema_checked

    if _budget_schema_checked:
        return

    # Table is managed externally by database migrations.
    _budget_schema_checked = True


def ensure_budget_request_schema(cursor, conn):
    global _budget_request_schema_checked

    if _budget_request_schema_checked:
        return

    # Tables are managed externally by database migrations.
    _budget_request_schema_checked = True


def ensure_department_budget_schema(cursor, conn):
    global _department_budget_schema_checked

    if _department_budget_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS department_budget_allocations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            dept_name VARCHAR(255) NOT NULL,
            allocated_budget DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            consumed_budget DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            low_balance_threshold DECIMAL(15,2) NOT NULL DEFAULT 10000.00,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_department_budget_allocations_company_dept (company_id, dept_name)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS department_budget_ledger (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            dept_name VARCHAR(255) NOT NULL,
            request_id INT NULL,
            transaction_type VARCHAR(50) NOT NULL,
            budget_type_name VARCHAR(120) NULL,
            amount DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            balance_before DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            balance_after DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            note TEXT NULL,
            created_by_email VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_department_budget_ledger_company_dept_created (company_id, dept_name, created_at),
            INDEX idx_department_budget_ledger_request_type (request_id, transaction_type)
        )
        """
    )

    if not _table_has_column(cursor, "department_budget_ledger", "budget_type_name"):
        cursor.execute("ALTER TABLE department_budget_ledger ADD COLUMN budget_type_name VARCHAR(120) NULL")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS budget_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            dept_name VARCHAR(255) NOT NULL,
            request_id INT NULL,
            alert_type VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            current_balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            threshold_value DECIMAL(15,2) NOT NULL DEFAULT 0.00,
            is_resolved TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP NULL DEFAULT NULL,
            INDEX idx_budget_alerts_company_resolved_created (company_id, is_resolved, created_at),
            INDEX idx_budget_alerts_company_dept (company_id, dept_name)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS budget_types (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_id INT NOT NULL,
            type_name VARCHAR(120) NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_budget_types_company_type (company_id, type_name)
        )
        """
    )

    conn.commit()
    _department_budget_schema_checked = True


def _normalize_department_name(value):
    return str(value or "").strip()


def _ensure_department_budget_row(cursor, company_id, dept_name):
    normalized_dept = _normalize_department_name(dept_name)
    if int(company_id or 0) <= 0 or not normalized_dept:
        return None

    cursor.execute(
        """
        INSERT IGNORE INTO department_budget_allocations
            (company_id, dept_name, allocated_budget, consumed_budget, low_balance_threshold)
        VALUES (%s, %s, 0, 0, 10000)
        """,
        (company_id, normalized_dept),
    )

    cursor.execute(
        """
        SELECT id, company_id, dept_name, allocated_budget, consumed_budget, low_balance_threshold
        FROM department_budget_allocations
        WHERE company_id = %s AND dept_name = %s
        LIMIT 1
        """,
        (company_id, normalized_dept),
    )
    return cursor.fetchone() or None


def _create_budget_alert(cursor, company_id, dept_name, request_id, alert_type, message, current_balance, threshold_value):
    cursor.execute(
        """
        INSERT INTO budget_alerts
            (company_id, dept_name, request_id, alert_type, message, current_balance, threshold_value)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            int(company_id or 0),
            _normalize_department_name(dept_name),
            request_id,
            str(alert_type or "GENERAL").strip().upper(),
            str(message or "").strip(),
            str(parse_amount_decimal(current_balance)),
            str(parse_amount_decimal(threshold_value)),
        ),
    )


def apply_department_budget_deduction(cursor, conn, request_id, actor_email=""):
    ensure_budget_request_schema(cursor, conn)
    ensure_department_budget_schema(cursor, conn)

    cursor.execute(
        """
        SELECT id
        FROM department_budget_ledger
        WHERE request_id = %s AND transaction_type = 'DEDUCTION'
        LIMIT 1
        """,
        (request_id,),
    )
    if cursor.fetchone():
        return {"processed": True, "already_processed": True, "alerts": []}

    cursor.execute(
        """
        SELECT
            r.request_id,
            r.company_id,
            r.amount,
            COALESCE(meta.budget_type, r.wfor, '') AS budget_type,
            COALESCE(meta.target_department, d.dept_name, '') AS target_department
        FROM requests r
        LEFT JOIN users u ON u.user_id = r.user_id
        LEFT JOIN departments d ON d.dept_id = u.dept_id
        LEFT JOIN request_budget_metadata meta ON meta.request_id = r.request_id
        WHERE r.request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    row = cursor.fetchone() or {}
    if not row:
        return {"processed": False, "reason": "request_not_found", "alerts": []}

    budget_type = normalize_request_budget(row.get("budget_type"))
    if not budget_type:
        return {"processed": False, "reason": "not_budget_request", "alerts": []}

    company_id = int(row.get("company_id") or 0)
    target_department = _normalize_department_name(row.get("target_department"))
    amount = parse_amount_decimal(row.get("amount"))

    if company_id <= 0:
        return {"processed": False, "reason": "missing_company", "alerts": []}
    if not target_department:
        return {"processed": False, "reason": "missing_target_department", "alerts": []}
    if amount <= 0:
        return {"processed": False, "reason": "invalid_amount", "alerts": []}

    allocation_row = _ensure_department_budget_row(cursor, company_id, target_department)
    if not allocation_row:
        return {"processed": False, "reason": "allocation_not_found", "alerts": []}

    allocated_budget = parse_amount_decimal(allocation_row.get("allocated_budget"))
    consumed_budget = parse_amount_decimal(allocation_row.get("consumed_budget"))
    low_balance_threshold = parse_amount_decimal(allocation_row.get("low_balance_threshold"))

    balance_before = allocated_budget - consumed_budget
    new_consumed_budget = consumed_budget + amount
    balance_after = allocated_budget - new_consumed_budget

    cursor.execute(
        """
        UPDATE department_budget_allocations
        SET consumed_budget = %s
        WHERE company_id = %s AND dept_name = %s
        """,
        (str(new_consumed_budget), company_id, target_department),
    )

    cursor.execute(
        """
        INSERT INTO department_budget_ledger
            (company_id, dept_name, request_id, transaction_type, budget_type_name, amount, balance_before, balance_after, note, created_by_email)
        VALUES (%s, %s, %s, 'DEDUCTION', %s, %s, %s, %s, %s, %s)
        """,
        (
            company_id,
            target_department,
            request_id,
            budget_type,
            str(amount),
            str(balance_before),
            str(balance_after),
            f"Auto-deduction for approved request #{request_id} ({budget_type})",
            (actor_email or "").strip().lower(),
        ),
    )

    alerts = []

    if amount > balance_before:
        message = (
            f"Budget over-limit detected for {target_department}. "
            f"Request #{request_id} deducted {float(amount):,.2f} with only {float(balance_before):,.2f} available."
        )
        _create_budget_alert(
            cursor,
            company_id,
            target_department,
            request_id,
            "OVER_LIMIT",
            message,
            balance_after,
            low_balance_threshold,
        )
        alerts.append({"type": "OVER_LIMIT", "message": message})

    if balance_after <= low_balance_threshold:
        message = (
            f"Low budget balance for {target_department}. "
            f"Current balance is {float(balance_after):,.2f}, threshold is {float(low_balance_threshold):,.2f}."
        )
        _create_budget_alert(
            cursor,
            company_id,
            target_department,
            request_id,
            "LOW_BALANCE",
            message,
            balance_after,
            low_balance_threshold,
        )
        alerts.append({"type": "LOW_BALANCE", "message": message})

    return {
        "processed": True,
        "already_processed": False,
        "company_id": company_id,
        "department": target_department,
        "amount": float(amount),
        "balance_before": float(balance_before),
        "balance_after": float(balance_after),
        "alerts": alerts,
    }


def ensure_coo_special_approval_schema(cursor, conn):
    global _coo_special_approval_schema_checked

    if _coo_special_approval_schema_checked:
        return

    # Table is managed externally by database migrations.
    _coo_special_approval_schema_checked = True


def get_coo_notification_emails(cursor):
    recipients = set()

    env_recipients = str(os.environ.get("COO_NOTIFICATION_EMAILS") or "").strip()
    if env_recipients:
        for item in re.split(r"[,;\s]+", env_recipients):
            email = str(item or "").strip().lower()
            if email:
                recipients.add(email)

    try:
        cursor.execute(
            """
            SELECT DISTINCT LOWER(TRIM(u.email)) AS email
            FROM users u
            LEFT JOIN positions p ON p.position_id = u.position_id
            LEFT JOIN roles r ON r.role_id = u.role_id
            WHERE u.email IS NOT NULL
              AND TRIM(u.email) <> ''
              AND (
                    LOWER(COALESCE(p.position_name, '')) LIKE '%coo%'
                 OR LOWER(COALESCE(p.position_name, '')) LIKE '%chief operating officer%'
                 OR LOWER(COALESCE(r.role_name, '')) LIKE '%coo%'
                 OR LOWER(COALESCE(r.role_name, '')) LIKE '%chief operating officer%'
              )
            ORDER BY email ASC
            """
        )
        for row in (cursor.fetchall() or []):
            email = str((row or {}).get("email") or "").strip().lower()
            if email:
                recipients.add(email)
    except Exception as exc:
        logger.exception("get_coo_notification_emails primary query failed: %s", exc)

    return sorted(recipients)


def build_special_access_link(request_id, target_email=""):
    def _base_url():
        configured = str(os.environ.get("APP_BASE_URL") or "").strip().rstrip("/")
        if configured:
            return configured

        if has_request_context():
            try:
                return str(request.url_root or "").strip().rstrip("/")
            except Exception:
                pass

        return "http://192.168.0.103:5000"

    base_url = _base_url()
    target = str(target_email or "").strip().lower()
    if target:
        token = create_coo_special_action_token(request_id, target)
        try:
            return url_for("coo_action_page", token=token, _external=True)
        except Exception:
            return f"{base_url}/coo-action/{token}"

    try:
        return url_for("special_access_dashboard", request_id=request_id, _external=True)
    except Exception:
        pass

    return f"{base_url}/specialaccess?request_id={int(request_id)}"


def send_coo_special_access_notifications(request_id, recipients, primary_target_email=""):
    notified = 0
    subject = f"COO Special Approval Required - REQ#{request_id}"
    for recipient in recipients:
        review_link = build_special_access_link(request_id, recipient or primary_target_email)
        body = (
            "Good day,\n\n"
            f"REQ#{request_id} is ready for COO special approval.\n"
            "Open the secure COO action link to review summary and approve/reject using PIN or Fingerprint (if enabled).\n"
            f"Link: <{review_link}>\n\n"
            "This is an automated message. Do not reply."
        )
        try:
            if send_cc_email(recipient, subject, body):
                notified += 1
        except Exception as _send_err:
            print("coo notify email error:", _send_err)

    return notified


def queue_coo_special_approval(cursor, conn, request_id, requested_by_email=""):
    ensure_coo_special_approval_schema(cursor, conn)

    cursor.execute(
        "SELECT status, requested_to_email FROM request_coo_approvals WHERE request_id = %s LIMIT 1",
        (request_id,),
    )
    existing = cursor.fetchone() or {}
    existing_status = str(existing.get("status") or "").strip().upper()
    if existing_status == "APPROVED":
        return {
            "queued": False,
            "notified": 0,
            "reason": "already_approved",
        }

    recipients = get_coo_notification_emails(cursor)
    existing_requested_to = str(existing.get("requested_to_email") or "").strip().lower()
    if existing_requested_to and existing_requested_to not in recipients:
        recipients.append(existing_requested_to)
        recipients = sorted(set(recipients))

    if not recipients:
        return {
            "queued": False,
            "notified": 0,
            "reason": "no_coo_recipient",
        }

    requested_to_email = recipients[0]
    cursor.execute(
        """
        INSERT INTO request_coo_approvals (
            request_id,
            status,
            requested_to_email,
            requested_by_email,
            approved_by_user_id,
            approved_by_email,
            approval_method,
            approved_at,
            requested_at
        )
        VALUES (%s, 'PENDING', %s, %s, NULL, NULL, NULL, NULL, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
            status = 'PENDING',
            requested_to_email = VALUES(requested_to_email),
            requested_by_email = VALUES(requested_by_email),
            approved_by_user_id = NULL,
            approved_by_email = NULL,
            approval_method = NULL,
            approved_at = NULL,
            requested_at = CURRENT_TIMESTAMP
        """,
        (
            request_id,
            requested_to_email,
            str(requested_by_email or "").strip().lower(),
        ),
    )
    conn.commit()

    review_link = build_special_access_link(request_id, requested_to_email)

    notified = send_coo_special_access_notifications(request_id, recipients, requested_to_email)

    if notified <= 0:
        return {
            "queued": True,
            "notified": 0,
            "recipient_count": len(recipients),
            "reason": "email_delivery_failed",
            "request_id": int(request_id),
            "review_link": review_link,
        }

    return {
        "queued": True,
        "notified": notified,
        "recipient_count": len(recipients),
        "request_id": int(request_id),
        "review_link": review_link,
    }


def advance_request_after_coo_approval(cursor, conn, request_id, requested_by_email=""):
    """Move request forward (or finalize) after COO approval so request dashboards stay in sync."""
    cursor.execute(
        """
        SELECT request_id, request_type_id, stage_position_id
        FROM requests
        WHERE request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    req_row = cursor.fetchone() or {}
    if not req_row:
        return {"advanced": False, "reason": "request_not_found"}

    request_type_id = int(req_row.get("request_type_id") or 0)
    current_stage = req_row.get("stage_position_id")

    cursor.execute("SELECT status_id FROM request_status WHERE status_name='PENDING' LIMIT 1")
    pending_row = cursor.fetchone() or {}
    pending_status_id = pending_row.get("status_id")

    cursor.execute("SELECT status_id FROM request_status WHERE status_name='APPROVED' LIMIT 1")
    approved_row = cursor.fetchone() or {}
    approved_status_id = approved_row.get("status_id")

    if pending_status_id is None or approved_status_id is None:
        return {"advanced": False, "reason": "missing_status_ids"}

    workflow_steps = get_effective_workflow_steps(
        cursor,
        request_id=request_id,
        request_type_id=request_type_id,
    )
    workflow_steps = _apply_conditional_high_value_workflow_steps(
        cursor,
        request_id,
        workflow_steps,
    )

    if workflow_steps:
        approved_positions = _get_request_approved_positions(cursor, request_id)
        if is_coo_position_id(cursor, current_stage):
            try:
                approved_positions.add(int(current_stage))
            except (TypeError, ValueError):
                pass
        step_idx, pending_positions = _get_active_workflow_step_state(
            workflow_steps,
            current_stage,
            approved_positions,
        )

        if step_idx is None or not pending_positions:
            cursor.execute(
                """
                UPDATE requests
                SET status_id = %s,
                    rejection_message = NULL,
                    stage_position_id = NULL
                WHERE request_id = %s
                """,
                (approved_status_id, request_id),
            )
            return {"advanced": True, "state": "approved"}

        next_stage = int(pending_positions[0])
        cursor.execute(
            """
            UPDATE requests
            SET status_id = %s,
                rejection_message = NULL,
                stage_position_id = %s
            WHERE request_id = %s
            """,
            (pending_status_id, next_stage, request_id),
        )
        coo_result = queue_coo_if_stage_is_coo(
            cursor,
            conn,
            request_id,
            next_stage,
            requested_by_email=requested_by_email,
        )
        return {
            "advanced": True,
            "state": "pending_next_stage",
            "next_stage_position_id": next_stage,
            "coo": coo_result,
        }

    _reviewers, _approvers, workflow = get_effective_workflow_positions(
        cursor,
        request_id=request_id,
        request_type_id=request_type_id,
    )
    workflow = _apply_conditional_high_value_workflow(cursor, request_id, workflow)

    if not workflow:
        cursor.execute(
            """
            UPDATE requests
            SET status_id = %s,
                rejection_message = NULL,
                stage_position_id = NULL
            WHERE request_id = %s
            """,
            (approved_status_id, request_id),
        )
        return {"advanced": True, "state": "approved"}

    try:
        idx = workflow.index(int(current_stage)) if current_stage is not None else -1
    except Exception:
        idx = -1

    if idx < len(workflow) - 1:
        next_stage = int(workflow[idx + 1] if idx >= 0 else workflow[0])
        cursor.execute(
            """
            UPDATE requests
            SET status_id = %s,
                rejection_message = NULL,
                stage_position_id = %s
            WHERE request_id = %s
            """,
            (pending_status_id, next_stage, request_id),
        )
        coo_result = queue_coo_if_stage_is_coo(
            cursor,
            conn,
            request_id,
            next_stage,
            requested_by_email=requested_by_email,
        )
        return {
            "advanced": True,
            "state": "pending_next_stage",
            "next_stage_position_id": next_stage,
            "coo": coo_result,
        }

    cursor.execute(
        """
        UPDATE requests
        SET status_id = %s,
            rejection_message = NULL,
            stage_position_id = NULL
        WHERE request_id = %s
        """,
        (approved_status_id, request_id),
    )
    return {"advanced": True, "state": "approved"}


@app.route("/api/specialaccess/request/<int:request_id>/resend-email", methods=["GET", "POST"])
@login_required
def special_access_resend_email(request_id):
    if request.method == "GET":
        return redirect(url_for("special_access_dashboard", request_id=request_id))

    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    if not is_coo_user(role, position):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_coo_special_approval_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                request_id,
                status,
                COALESCE(requested_to_email, '') AS requested_to_email
            FROM request_coo_approvals
            WHERE request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        row = cursor.fetchone() or {}
        if not row:
            cursor.execute(
                """
                SELECT
                    request_id,
                    stage_position_id,
                    COALESCE(rs.status_name, '') AS status_name
                FROM requests r
                LEFT JOIN request_status rs ON rs.status_id = r.status_id
                WHERE r.request_id = %s
                LIMIT 1
                """,
                (request_id,),
            )
            request_row = cursor.fetchone() or {}
            if not request_row:
                return jsonify({"success": False, "error": "Request not found."}), 404

            stage_position_id = request_row.get("stage_position_id")
            if not is_coo_position_id(cursor, stage_position_id):
                status_name = str(request_row.get("status_name") or "").strip()
                return jsonify(
                    {
                        "success": False,
                        "error": "Request is not queued for COO approval.",
                        "current_status": status_name,
                        "stage_position_id": stage_position_id,
                        "hint": "COO email links are queued automatically only when the request enters a COO stage.",
                    }
                ), 409

            queue_result = queue_coo_special_approval(
                cursor,
                conn,
                request_id,
                requested_by_email=(session.get("email") or ""),
            )
            if not queue_result.get("queued"):
                return jsonify(
                    {
                        "success": False,
                        "error": "Failed to queue COO approval email link.",
                        "coo": queue_result,
                    }
                ), 502

            return jsonify(
                {
                    "success": True,
                    "message": "COO queue was missing and has been created. Email link has been (re)sent.",
                    "coo": queue_result,
                    "notified": int(queue_result.get("notified") or 0),
                    "recipient_count": int(queue_result.get("recipient_count") or 0),
                    "review_link": queue_result.get("review_link") or "",
                    "auto_queued": True,
                }
            )

        coo_status = str(row.get("status") or "").strip().upper()
        if coo_status != "PENDING":
            return jsonify(
                {
                    "success": False,
                    "error": "Email resend is only available while COO approval is pending.",
                }
            ), 400

        recipients = get_coo_notification_emails(cursor)
        requested_to_email = str(row.get("requested_to_email") or "").strip().lower()
        if requested_to_email and requested_to_email not in recipients:
            recipients.append(requested_to_email)
            recipients = sorted(set(recipients))

        if not recipients:
            return jsonify(
                {
                    "success": False,
                    "error": "No COO recipient was found for special approval notification.",
                }
            ), 400

        review_link = build_special_access_link(request_id, requested_to_email or recipients[0])
        notified = send_coo_special_access_notifications(
            request_id,
            recipients,
            requested_to_email or recipients[0],
        )
        if notified <= 0:
            return jsonify(
                {
                    "success": False,
                    "error": "COO email resend failed for all recipients.",
                    "recipient_count": len(recipients),
                    "review_link": review_link,
                }
            ), 502

        return jsonify(
            {
                "success": True,
                "message": f"COO email link resent to {notified} recipient(s).",
                "notified": notified,
                "recipient_count": len(recipients),
                "review_link": review_link,
            }
        )
    except Exception:
        logger.exception("special_access_resend_email failed")
        return jsonify({"success": False, "error": "Failed to resend COO email link."}), 500
    finally:
        cursor.close()
        conn.close()


def _normalize_coo_annotations(raw_annotations):
    annotations = []
    if isinstance(raw_annotations, list):
        annotations = raw_annotations

    signature_entries = []
    for ann in annotations:
        if not isinstance(ann, dict):
            continue

        ann_type = str(ann.get("type") or "").strip().lower()
        if ann_type not in {"image", "text"}:
            continue

        actor_email = str(ann.get("actor_email") or "").strip() or "-"
        actor_position_id = ann.get("actor_position_id")
        page = ann.get("page")
        try:
            page = int(page)
        except (TypeError, ValueError):
            page = None

        signature_entries.append(
            {
                "type": "Signature" if ann_type == "image" else "Text",
                "actor_email": actor_email,
                "actor_position_id": actor_position_id,
                "page": page,
            }
        )

    return signature_entries


def send_coo_outcome_notifications(
    request_id,
    outcome,
    request_type_name,
    requester_email,
    requested_by_email="",
    reason="",
    extra_recipients=None,
):
    recipient_set = set()
    invalid_recipients = set()
    email_pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

    candidates = [requester_email, requested_by_email]
    if extra_recipients:
        for item in extra_recipients:
            candidates.append(item)

    for email in candidates:
        value = str(email or "").strip().lower()
        if not value:
            continue
        if not email_pattern.match(value):
            invalid_recipients.add(value)
            continue
        recipient_set.add(value)

    if not recipient_set:
        return {
            "sent": 0,
            "recipients": 0,
            "invalid_recipients_count": len(invalid_recipients),
            "invalid_recipients": sorted(invalid_recipients),
        }

    outcome_text = str(outcome or "").strip().upper() or "UPDATED"
    subject = f"COO Decision - REQ#{request_id} {outcome_text}"

    details_line = ""
    if outcome_text == "REJECTED" and str(reason or "").strip():
        details_line = f"Reason: {str(reason).strip()}\n"

    body = (
        "Good day,\n\n"
        f"REQ#{request_id} ({request_type_name or 'Request'}) was marked as {outcome_text} by COO special access.\n"
        f"{details_line}\n"
        "This is an automated message. Do not reply."
    )

    sent = 0
    for recipient in sorted(recipient_set):
        try:
            if send_cc_email(recipient, subject, body):
                sent += 1
        except Exception as _mail_err:
            print("coo outcome email error:", _mail_err)

    return {
        "sent": sent,
        "recipients": len(recipient_set),
        "invalid_recipients_count": len(invalid_recipients),
        "invalid_recipients": sorted(invalid_recipients),
    }


def get_coo_actor_context(cursor, email):
    normalized = str(email or "").strip().lower()
    if not normalized:
        return {}

    cursor.execute(
        """
        SELECT
            u.user_id,
            LOWER(TRIM(u.email)) AS email,
            u.position_id,
            COALESCE(p.position_name, '') AS position_name,
            COALESCE(r.role_name, '') AS role_name,
            u.admin_pin_hash,
            COALESCE(u.admin_pin_failed_attempts, 0) AS admin_pin_failed_attempts,
            COALESCE(u.admin_pin_disabled, 0) AS admin_pin_disabled
        FROM users u
        LEFT JOIN positions p ON p.position_id = u.position_id
        LEFT JOIN roles r ON r.role_id = u.role_id
        WHERE LOWER(TRIM(u.email)) = %s
        LIMIT 1
        """,
        (normalized,),
    )
    return cursor.fetchone() or {}


def process_coo_special_decision_by_email(cursor, conn, request_id, actor_email, auth_method, pin, decision, reason=""):
    auth_method = str(auth_method or "pin").strip().lower()
    pin = str(pin or "").strip()
    decision = str(decision or "").strip().upper()

    if auth_method == "fingerprint":
        return {
            "success": False,
            "error": "Fingerprint approval is not configured yet. Please use PIN.",
        }, 400

    if auth_method != "pin":
        return {"success": False, "error": "Invalid authentication method."}, 400

    if not is_valid_admin_pin(pin):
        return {"success": False, "error": "PIN must be exactly 4 digits."}, 400

    ensure_admin_pin_schema(cursor, conn)
    ensure_coo_special_approval_schema(cursor, conn)

    cursor.execute(
        """
        SELECT
            rca.request_id,
            rca.status,
            COALESCE(rca.requested_by_email, '') AS requested_by_email,
            COALESCE(rca.requested_to_email, '') AS requested_to_email,
            COALESCE(u.email, '') AS requester_email,
            COALESCE(rt.type_name, 'Request') AS type_name
        FROM request_coo_approvals rca
        JOIN requests r ON r.request_id = rca.request_id
        LEFT JOIN users u ON u.user_id = r.user_id
        LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
        WHERE rca.request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    approval_row = cursor.fetchone() or {}
    if not approval_row:
        return {"success": False, "error": "Request is not queued for COO approval."}, 404

    current_coo_status = str(approval_row.get("status") or "").strip().upper()
    if decision == "APPROVED" and current_coo_status == "APPROVED":
        advance_result = advance_request_after_coo_approval(
            cursor,
            conn,
            request_id,
            requested_by_email=actor_email,
        )
        return {
            "success": True,
            "message": "Request already approved by COO.",
            "workflow": advance_result,
        }, 200
    if decision == "REJECTED" and current_coo_status == "REJECTED":
        return {"success": True, "message": "Request already rejected by COO."}, 200
    if decision == "REJECTED" and current_coo_status == "APPROVED":
        return {"success": False, "error": "Request is already approved by COO."}, 400

    actor_row = get_coo_actor_context(cursor, actor_email)
    if not actor_row:
        return {"success": False, "error": "COO account not found."}, 404

    role_name = str(actor_row.get("role_name") or "")
    position_name = str(actor_row.get("position_name") or "")
    if not is_coo_user(role_name, position_name):
        return {"success": False, "error": "Forbidden"}, 403

    pin_hash = actor_row.get("admin_pin_hash")
    failed_attempts = int(actor_row.get("admin_pin_failed_attempts") or 0)
    is_disabled = bool(int(actor_row.get("admin_pin_disabled") or 0))

    if not pin_hash:
        return {"success": False, "error": "PIN is not set. Please set your PIN first."}, 400

    if is_disabled:
        return {
            "success": False,
            "error": "PIN is disabled. Reset your PIN in Settings.",
            "failed_attempts": failed_attempts,
            "remaining_attempts": 0,
        }, 423

    if not check_password_hash(pin_hash, pin):
        new_failed_attempts = min(ADMIN_PIN_MAX_FAILED_ATTEMPTS, failed_attempts + 1)
        disabled_now = 1 if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS else 0
        cursor.execute(
            """
            UPDATE users
            SET admin_pin_failed_attempts=%s,
                admin_pin_disabled=%s
            WHERE user_id=%s
            """,
            (new_failed_attempts, disabled_now, actor_row.get("user_id")),
        )
        conn.commit()

        remaining = max(0, ADMIN_PIN_MAX_FAILED_ATTEMPTS - new_failed_attempts)
        if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS:
            return {
                "success": False,
                "error": "PIN has been disabled after 5 failed attempts. Reset your PIN in Settings.",
                "failed_attempts": new_failed_attempts,
                "remaining_attempts": 0,
            }, 423

        return {
            "success": False,
            "error": f"Incorrect PIN. You have {remaining} attempt(s) remaining.",
            "failed_attempts": new_failed_attempts,
            "remaining_attempts": remaining,
        }, 403

    cursor.execute(
        """
        UPDATE users
        SET admin_pin_failed_attempts=0,
            admin_pin_disabled=0
        WHERE user_id=%s
        """,
        (actor_row.get("user_id"),),
    )

    actor_user_id = actor_row.get("user_id")
    actor_position_id = actor_row.get("position_id")
    actor_email_norm = str(actor_row.get("email") or "").strip().lower()
    method_value = "PIN"
    advance_result = {"advanced": False, "reason": "not_applicable"}

    if decision == "APPROVED":
        cursor.execute(
            """
            UPDATE request_coo_approvals
            SET status='APPROVED',
                approved_by_user_id=%s,
                approved_by_email=%s,
                approval_method=%s,
                approved_at=CURRENT_TIMESTAMP
            WHERE request_id=%s
            """,
            (
                actor_user_id,
                actor_email_norm,
                method_value,
                request_id,
            ),
        )

        cursor.execute(
            """
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'COO_APPROVED', 'Approved via COO secure email link')
            """,
            (
                request_id,
                actor_user_id,
                actor_position_id,
                actor_email_norm,
            ),
        )

        try:
            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "COO Special Approval",
                    f"REQ#{request_id} approved by COO via secure email link ({actor_email_norm}).",
                ),
            )
        except Exception:
            pass

        advance_result = advance_request_after_coo_approval(
            cursor,
            conn,
            request_id,
            requested_by_email=actor_email_norm,
        )
    elif decision == "REJECTED":
        reject_reason = str(reason or "").strip() or "Rejected by COO special access."

        cursor.execute(
            """
            SELECT status_id
            FROM request_status
            WHERE status_name='REJECTED'
            LIMIT 1
            """
        )
        rejected_status_row = cursor.fetchone() or {}
        rejected_status_id = rejected_status_row.get("status_id")

        cursor.execute(
            """
            UPDATE request_coo_approvals
            SET status='REJECTED',
                approved_by_user_id=%s,
                approved_by_email=%s,
                approval_method=%s,
                approved_at=CURRENT_TIMESTAMP
            WHERE request_id=%s
            """,
            (
                actor_user_id,
                actor_email_norm,
                method_value,
                request_id,
            ),
        )

        if rejected_status_id is not None:
            cursor.execute(
                """
                UPDATE requests
                SET status_id=%s,
                    rejection_message=%s,
                    stage_position_id=NULL
                WHERE request_id=%s
                """,
                (rejected_status_id, reject_reason, request_id),
            )

        cursor.execute(
            """
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'COO_REJECTED', %s)
            """,
            (
                request_id,
                actor_user_id,
                actor_position_id,
                actor_email_norm,
                reject_reason,
            ),
        )

        try:
            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "COO Special Rejection",
                    f"REQ#{request_id} rejected by COO via secure email link ({actor_email_norm}).",
                ),
            )
        except Exception:
            pass
    else:
        return {"success": False, "error": "Invalid decision."}, 400

    try:
        render_mapped_signature_blocks_for_request(cursor, conn, request_id)
    except Exception:
        logger.exception("Failed to render mapped signatures for COO special action")

    conn.commit()

    base = "COO special approval completed." if decision == "APPROVED" else "COO special rejection completed."
    base += " No post-decision COO email is sent by design."

    return {
        "success": True,
        "message": base,
        "email": {"sent": 0, "recipients": 0},
        "workflow": advance_result,
    }, 200


@app.route("/coo-action/<token>")
def coo_action_page(token):
    token_data = None
    token_error = ""
    try:
        token_data = verify_coo_special_action_token(token, max_age=COO_ACTION_TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        token_error = "This COO action link has expired. Please request a new email link."
    except BadSignature:
        token_error = "Invalid COO action link."

    queue_rows = []
    summary = None
    selected_request_id = None
    requested_id_raw = request.args.get("request_id", "").strip()
    try:
        if requested_id_raw:
            selected_request_id = int(requested_id_raw)
    except (TypeError, ValueError):
        selected_request_id = None

    if token_data:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            ensure_coo_special_approval_schema(cursor, conn)

            cursor.execute(
                """
                SELECT
                    rca.request_id,
                    COALESCE(rca.status, 'PENDING') AS coo_status,
                    rca.requested_at,
                    COALESCE(rt.type_name, 'Request') AS request_type_name,
                    COALESCE(u.email, '') AS requester_email,
                    COALESCE(d.dept_name, '') AS requester_department,
                    COALESCE(r.amount, 0) AS amount,
                    COALESCE(rs.status_name, '') AS request_status
                FROM request_coo_approvals rca
                JOIN requests r ON r.request_id = rca.request_id
                LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
                LEFT JOIN users u ON u.user_id = r.user_id
                LEFT JOIN departments d ON d.dept_id = u.dept_id
                LEFT JOIN request_status rs ON rs.status_id = r.status_id
                ORDER BY
                    CASE WHEN UPPER(COALESCE(rca.status, '')) = 'PENDING' THEN 0 ELSE 1 END,
                    rca.requested_at DESC
                LIMIT 300
                """
            )
            queue_rows = cursor.fetchall() or []

            queue_ids = {int(row.get("request_id")) for row in queue_rows if row.get("request_id") is not None}
            token_request_id = int(token_data.get("request_id") or 0)

            if selected_request_id is None:
                if token_request_id in queue_ids:
                    selected_request_id = token_request_id
                elif queue_rows:
                    selected_request_id = int(queue_rows[0].get("request_id"))
            elif selected_request_id not in queue_ids:
                selected_request_id = token_request_id if token_request_id in queue_ids else (int(queue_rows[0].get("request_id")) if queue_rows else None)

            if selected_request_id is None and token_request_id > 0:
                selected_request_id = token_request_id

            cursor.execute(
                """
                SELECT
                    r.request_id,
                    COALESCE(rt.type_name, 'Request') AS request_type_name,
                    COALESCE(u.email, '') AS requester_email,
                    COALESCE(d.dept_name, '') AS requester_department,
                    COALESCE(r.amount, 0) AS amount,
                    COALESCE(rs.status_name, '') AS request_status,
                    COALESCE(rca.status, 'PENDING') AS coo_status,
                    COALESCE(rca.approved_by_email, '') AS coo_approved_by,
                    rca.requested_at,
                    rca.approved_at
                FROM requests r
                LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
                LEFT JOIN users u ON u.user_id = r.user_id
                LEFT JOIN departments d ON d.dept_id = u.dept_id
                LEFT JOIN request_status rs ON rs.status_id = r.status_id
                LEFT JOIN request_coo_approvals rca ON rca.request_id = r.request_id
                WHERE r.request_id = %s
                LIMIT 1
                """,
                (int(selected_request_id or 0),),
            )
            summary = cursor.fetchone() or None
        finally:
            cursor.close()
            conn.close()

    return render_template(
        "coo_action.html",
        token=token,
        token_error=token_error,
        token_email=(token_data or {}).get("email") if token_data else "",
        queue_rows=queue_rows,
        selected_request_id=selected_request_id,
        summary=summary,
    )


@app.route("/coo-action/<token>/attachment", methods=["GET"])
def coo_action_attachment_by_token(token):
    try:
        token_data = verify_coo_special_action_token(token, max_age=COO_ACTION_TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        return Response("This COO action link has expired.", status=401, mimetype="text/plain")
    except BadSignature:
        return Response("Invalid COO action link.", status=401, mimetype="text/plain")

    request_id_raw = request.args.get("request_id", "").strip()
    request_id = int(token_data.get("request_id") or 0)
    if request_id_raw:
        try:
            request_id = int(request_id_raw)
        except (TypeError, ValueError):
            request_id = 0

    if request_id <= 0:
        return Response("Invalid request id.", status=400, mimetype="text/plain")

    actor_email = str(token_data.get("email") or "").strip().lower()
    if not actor_email:
        return Response("Invalid COO token email.", status=400, mimetype="text/plain")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_coo_special_approval_schema(cursor, conn)

        cursor.execute(
            """
            SELECT request_id, COALESCE(requested_to_email, '') AS requested_to_email
            FROM request_coo_approvals
            WHERE request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        approval_row = cursor.fetchone() or {}
        if not approval_row:
            return Response("Request is not queued for COO approval.", status=404, mimetype="text/plain")

        requested_to_email = str(approval_row.get("requested_to_email") or "").strip().lower()
        if requested_to_email and requested_to_email != actor_email:
            return Response("Access denied for this COO token.", status=403, mimetype="text/plain")

        cursor.execute(
            """
            SELECT
                r.request_id,
                r.request_type_id,
                r.filename,
                r.attachment,
                rt.template_filename,
                rt.template_file,
                rfs.form_data_json,
                a.signed_pdf
            FROM requests r
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
            LEFT JOIN request_annotations a ON a.request_id = r.request_id
            WHERE r.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        row = cursor.fetchone() or {}
        if not row:
            return Response("No attachment found", status=404, mimetype="text/plain")

        filename = (row.get("filename") or "").strip() or f"request_{request_id}_attachment.pdf"
        if not filename.lower().endswith(".pdf"):
            filename = f"{filename}.pdf"

        file_bytes = row.get("signed_pdf") or row.get("attachment")

        if not file_bytes and row.get("template_file") and str(row.get("form_data_json") or "").strip():
            try:
                template_blob = row.get("template_file")
                schema = get_request_type_fillable_schema(cursor, int(row.get("request_type_id") or 0))
                payload = json.loads(str(row.get("form_data_json") or "").strip())
                if isinstance(payload, dict):
                    file_bytes = build_filled_pdf_from_submission(
                        template_blob,
                        schema,
                        payload,
                        total_amount=None,
                    )
            except Exception:
                logger.exception("coo_action_attachment_by_token regeneration failed")

        if not file_bytes and row.get("template_file"):
            file_bytes = row.get("template_file")
            filename = (row.get("template_filename") or "").strip() or filename
            if not filename.lower().endswith(".pdf"):
                filename = f"{filename}.pdf"

        if not file_bytes:
            return Response("No attachment found", status=404, mimetype="text/plain")

        force_download = request.args.get("download") == "1"

        response = send_file(
            BytesIO(file_bytes),
            download_name=filename or f"request_{request_id}_attachment.pdf",
            mimetype="application/pdf",
            as_attachment=force_download,
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    finally:
        cursor.close()
        conn.close()


@app.route("/api/coo-action/<token>/approve", methods=["POST"])
@csrf.exempt
def coo_action_approve_by_token(token):
    data = request.get_json(silent=True) or {}
    try:
        token_data = verify_coo_special_action_token(token, max_age=COO_ACTION_TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        return jsonify({"success": False, "error": "This COO action link has expired."}), 401
    except BadSignature:
        return jsonify({"success": False, "error": "Invalid COO action link."}), 401

    request_id_raw = data.get("request_id", token_data.get("request_id"))
    try:
        request_id = int(request_id_raw or 0)
    except (TypeError, ValueError):
        request_id = 0
    actor_email = str(token_data.get("email") or "").strip().lower()
    if request_id <= 0 or not actor_email:
        return jsonify({"success": False, "error": "Invalid COO action payload."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        payload, status_code = process_coo_special_decision_by_email(
            cursor=cursor,
            conn=conn,
            request_id=request_id,
            actor_email=actor_email,
            auth_method=data.get("auth_method"),
            pin=data.get("pin"),
            decision="APPROVED",
            reason="",
        )
        return jsonify(payload), status_code
    except Exception:
        conn.rollback()
        logger.exception("coo_action_approve_by_token failed")
        return jsonify({"success": False, "error": "Failed to approve request."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/coo-action/<token>/reject", methods=["POST"])
@csrf.exempt
def coo_action_reject_by_token(token):
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason") or "").strip() or "Rejected by COO special access."
    try:
        token_data = verify_coo_special_action_token(token, max_age=COO_ACTION_TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        return jsonify({"success": False, "error": "This COO action link has expired."}), 401
    except BadSignature:
        return jsonify({"success": False, "error": "Invalid COO action link."}), 401

    request_id_raw = data.get("request_id", token_data.get("request_id"))
    try:
        request_id = int(request_id_raw or 0)
    except (TypeError, ValueError):
        request_id = 0
    actor_email = str(token_data.get("email") or "").strip().lower()
    if request_id <= 0 or not actor_email:
        return jsonify({"success": False, "error": "Invalid COO action payload."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        payload, status_code = process_coo_special_decision_by_email(
            cursor=cursor,
            conn=conn,
            request_id=request_id,
            actor_email=actor_email,
            auth_method=data.get("auth_method"),
            pin=data.get("pin"),
            decision="REJECTED",
            reason=reason,
        )
        return jsonify(payload), status_code
    except Exception:
        conn.rollback()
        logger.exception("coo_action_reject_by_token failed")
        return jsonify({"success": False, "error": "Failed to reject request."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/specialaccess")
@login_required
def special_access_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    if not is_coo_user(role, position):
        return "Forbidden", 403

    request_id_raw = request.args.get("request_id", "").strip()
    selected_request_id = None
    try:
        if request_id_raw:
            selected_request_id = int(request_id_raw)
    except (TypeError, ValueError):
        selected_request_id = None

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_coo_special_approval_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                rca.request_id,
                rca.status AS coo_status,
                rca.requested_at,
                rca.approved_at,
                rca.approved_by_email,
                COALESCE(rt.type_name, 'Request') AS type_name,
                COALESCE(u.email, '') AS requester_email,
                COALESCE(d.dept_name, '') AS dept_name,
                COALESCE(r.amount, 0) AS amount,
                COALESCE(rs.status_name, '') AS request_status
            FROM request_coo_approvals rca
            JOIN requests r ON r.request_id = rca.request_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
            LEFT JOIN request_status rs ON rs.status_id = r.status_id
            ORDER BY
                CASE WHEN UPPER(COALESCE(rca.status, '')) = 'PENDING' THEN 0 ELSE 1 END,
                rca.requested_at DESC
            LIMIT 200
            """
        )
        queue_rows = cursor.fetchall() or []

        if selected_request_id is None and queue_rows:
            selected_request_id = int(queue_rows[0].get("request_id"))

        selected_summary = None
        reviewers = []
        approvers = []
        action_history = []
        signature_entries = []

        if selected_request_id is not None:
            cursor.execute(
                """
                SELECT
                    r.request_id,
                    r.request_type_id,
                    r.created_at,
                    r.filename,
                    COALESCE(r.amount, 0) AS amount,
                    COALESCE(r.wfor, '') AS request_budget,
                    COALESCE(rt.type_name, 'Request') AS request_type_name,
                    COALESCE(u.email, '') AS requester_email,
                    COALESCE(d.dept_name, '') AS requester_department,
                    COALESCE(rs.status_name, '') AS request_status,
                    COALESCE(rca.status, 'PENDING') AS coo_status,
                    rca.requested_at,
                    rca.approved_at,
                    COALESCE(rca.approved_by_email, '') AS coo_approved_by
                FROM requests r
                LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
                LEFT JOIN users u ON u.user_id = r.user_id
                LEFT JOIN departments d ON d.dept_id = u.dept_id
                LEFT JOIN request_status rs ON rs.status_id = r.status_id
                LEFT JOIN request_coo_approvals rca ON rca.request_id = r.request_id
                WHERE r.request_id = %s
                LIMIT 1
                """,
                (selected_request_id,),
            )
            selected_summary = cursor.fetchone()

            if selected_summary:
                req_type_id = selected_summary.get("request_type_id")

                cursor.execute(
                    """
                    SELECT p.position_name, rtr.order_no
                    FROM request_type_reviewers rtr
                    JOIN positions p ON p.position_id = rtr.position_id
                    WHERE rtr.request_type_id = %s
                    ORDER BY rtr.order_no ASC
                    """,
                    (req_type_id,),
                )
                reviewers = cursor.fetchall() or []

                cursor.execute(
                    """
                    SELECT p.position_name, rta.order_no
                    FROM request_type_approvers rta
                    JOIN positions p ON p.position_id = rta.position_id
                    WHERE rta.request_type_id = %s
                    ORDER BY rta.order_no ASC
                    """,
                    (req_type_id,),
                )
                approvers = cursor.fetchall() or []

                cursor.execute(
                    """
                    SELECT
                        ra.action,
                        COALESCE(ra.actor_email, u.email, '-') AS actor_email,
                        COALESCE(p.position_name, '-') AS actor_position,
                        ra.created_at
                    FROM request_actions ra
                    LEFT JOIN users u ON u.user_id = ra.actor_user_id
                    LEFT JOIN positions p ON p.position_id = ra.actor_position_id
                    WHERE ra.request_id = %s
                    ORDER BY ra.created_at ASC
                    """,
                    (selected_request_id,),
                )
                action_history = cursor.fetchall() or []

                cursor.execute(
                    "SELECT annotations_json FROM request_annotations WHERE request_id = %s LIMIT 1",
                    (selected_request_id,),
                )
                ann_row = cursor.fetchone() or {}
                annotations_json = ann_row.get("annotations_json")
                parsed_annotations = []
                if annotations_json:
                    try:
                        parsed_annotations = json.loads(annotations_json)
                    except Exception:
                        parsed_annotations = []

                signature_entries = _normalize_coo_annotations(parsed_annotations)

        return render_template(
            "specialaccess.html",
            queue_rows=queue_rows,
            selected_request_id=selected_request_id,
            selected_summary=selected_summary,
            reviewers=reviewers,
            approvers=approvers,
            action_history=action_history,
            signature_entries=signature_entries,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/specialaccess/request/<int:request_id>/approve", methods=["GET", "POST"])
@login_required
def special_access_approve_request(request_id):
    if request.method == "GET":
        return redirect(url_for("special_access_dashboard", request_id=request_id))

    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    if not is_coo_user(role, position):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    auth_method = str(data.get("auth_method") or "pin").strip().lower()
    pin = str(data.get("pin") or "").strip()

    if auth_method == "fingerprint":
        return jsonify(
            {
                "success": False,
                "error": "Fingerprint approval is not configured yet. Please use PIN.",
            }
        ), 400

    if auth_method != "pin":
        return jsonify({"success": False, "error": "Invalid authentication method."}), 400

    if not is_valid_admin_pin(pin):
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        ensure_coo_special_approval_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                rca.request_id,
                rca.status,
                COALESCE(rca.requested_by_email, '') AS requested_by_email,
                COALESCE(rca.requested_to_email, '') AS requested_to_email,
                COALESCE(u.email, '') AS requester_email,
                COALESCE(rt.type_name, 'Request') AS type_name
            FROM request_coo_approvals rca
            JOIN requests r ON r.request_id = rca.request_id
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            WHERE rca.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        approval_row = cursor.fetchone() or {}
        if not approval_row:
            return jsonify({"success": False, "error": "Request is not queued for COO approval."}), 404

        if str(approval_row.get("status") or "").strip().upper() == "APPROVED":
            advance_result = advance_request_after_coo_approval(
                cursor,
                conn,
                request_id,
                requested_by_email=(session.get("email") or ""),
            )
            conn.commit()
            return jsonify(
                {
                    "success": True,
                    "message": "Request already approved by COO.",
                    "workflow": advance_result,
                }
            )

        pin_row = get_admin_pin_state(cursor, session["email"])
        if not pin_row:
            return jsonify({"success": False, "error": "User not found"}), 404

        pin_hash = pin_row.get("admin_pin_hash")
        failed_attempts = int(pin_row.get("admin_pin_failed_attempts") or 0)
        is_disabled = bool(int(pin_row.get("admin_pin_disabled") or 0))

        if not pin_hash:
            return jsonify({"success": False, "error": "PIN is not set. Please set your PIN first."}), 400

        if is_disabled:
            return jsonify(
                {
                    "success": False,
                    "error": "PIN is disabled. Reset your PIN in Settings.",
                    "failed_attempts": failed_attempts,
                    "remaining_attempts": 0,
                }
            ), 423

        if not check_password_hash(pin_hash, pin):
            new_failed_attempts = min(ADMIN_PIN_MAX_FAILED_ATTEMPTS, failed_attempts + 1)
            disabled_now = 1 if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS else 0
            cursor.execute(
                """
                UPDATE users
                SET admin_pin_failed_attempts=%s,
                    admin_pin_disabled=%s
                WHERE user_id=%s
                """,
                (new_failed_attempts, disabled_now, pin_row["user_id"]),
            )
            conn.commit()

            remaining = max(0, ADMIN_PIN_MAX_FAILED_ATTEMPTS - new_failed_attempts)
            if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS:
                return jsonify(
                    {
                        "success": False,
                        "error": "PIN has been disabled after 5 failed attempts. Reset your PIN in Settings.",
                        "failed_attempts": new_failed_attempts,
                        "remaining_attempts": 0,
                    }
                ), 423

            return jsonify(
                {
                    "success": False,
                    "error": f"Incorrect PIN. You have {remaining} attempt(s) remaining.",
                    "failed_attempts": new_failed_attempts,
                    "remaining_attempts": remaining,
                }
            ), 403

        cursor.execute(
            """
            UPDATE users
            SET admin_pin_failed_attempts=0,
                admin_pin_disabled=0
            WHERE user_id=%s
            """,
            (pin_row["user_id"],),
        )

        cursor.execute(
            """
            UPDATE request_coo_approvals
            SET status='APPROVED',
                approved_by_user_id=%s,
                approved_by_email=%s,
                approval_method='PIN',
                approved_at=CURRENT_TIMESTAMP
            WHERE request_id=%s
            """,
            (
                session.get("user_id"),
                (session.get("email") or "").strip().lower(),
                request_id,
            ),
        )

        cursor.execute(
            """
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'COO_APPROVED', 'Approved via COO special access')
            """,
            (
                request_id,
                session.get("user_id"),
                session.get("position_id"),
                (session.get("email") or "").strip().lower(),
            ),
        )

        try:
            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "COO Special Approval",
                    f"REQ#{request_id} approved by COO via PIN ({session.get('email')}).",
                ),
            )
        except Exception:
            pass

        advance_result = advance_request_after_coo_approval(
            cursor,
            conn,
            request_id,
            requested_by_email=(session.get("email") or ""),
        )

        conn.commit()

        response_message = "COO special approval completed. No post-decision COO email is sent by design."

        return jsonify(
            {
                "success": True,
                "message": response_message,
                "email": {"sent": 0, "recipients": 0},
                "workflow": advance_result,
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("special_access_approve_request failed")
        return jsonify({"success": False, "error": "Failed to approve request."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/specialaccess/request/<int:request_id>/reject", methods=["POST"])
@login_required
def special_access_reject_request(request_id):
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    if not is_coo_user(role, position):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    auth_method = str(data.get("auth_method") or "pin").strip().lower()
    pin = str(data.get("pin") or "").strip()
    reason = str(data.get("reason") or "").strip()
    if not reason:
        reason = "Rejected by COO special access."

    if auth_method == "fingerprint":
        return jsonify(
            {
                "success": False,
                "error": "Fingerprint approval is not configured yet. Please use PIN.",
            }
        ), 400

    if auth_method != "pin":
        return jsonify({"success": False, "error": "Invalid authentication method."}), 400

    if not is_valid_admin_pin(pin):
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        ensure_coo_special_approval_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                rca.request_id,
                rca.status,
                COALESCE(rca.requested_by_email, '') AS requested_by_email,
                COALESCE(rca.requested_to_email, '') AS requested_to_email,
                COALESCE(u.email, '') AS requester_email,
                COALESCE(rt.type_name, 'Request') AS type_name
            FROM request_coo_approvals rca
            JOIN requests r ON r.request_id = rca.request_id
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            WHERE rca.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        approval_row = cursor.fetchone() or {}
        if not approval_row:
            return jsonify({"success": False, "error": "Request is not queued for COO approval."}), 404

        current_coo_status = str(approval_row.get("status") or "").strip().upper()
        if current_coo_status == "REJECTED":
            return jsonify({"success": True, "message": "Request already rejected by COO."})
        if current_coo_status == "APPROVED":
            return jsonify({"success": False, "error": "Request is already approved by COO."}), 400

        pin_row = get_admin_pin_state(cursor, session["email"])
        if not pin_row:
            return jsonify({"success": False, "error": "User not found"}), 404

        pin_hash = pin_row.get("admin_pin_hash")
        failed_attempts = int(pin_row.get("admin_pin_failed_attempts") or 0)
        is_disabled = bool(int(pin_row.get("admin_pin_disabled") or 0))

        if not pin_hash:
            return jsonify({"success": False, "error": "PIN is not set. Please set your PIN first."}), 400

        if is_disabled:
            return jsonify(
                {
                    "success": False,
                    "error": "PIN is disabled. Reset your PIN in Settings.",
                    "failed_attempts": failed_attempts,
                    "remaining_attempts": 0,
                }
            ), 423

        if not check_password_hash(pin_hash, pin):
            new_failed_attempts = min(ADMIN_PIN_MAX_FAILED_ATTEMPTS, failed_attempts + 1)
            disabled_now = 1 if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS else 0
            cursor.execute(
                """
                UPDATE users
                SET admin_pin_failed_attempts=%s,
                    admin_pin_disabled=%s
                WHERE user_id=%s
                """,
                (new_failed_attempts, disabled_now, pin_row["user_id"]),
            )
            conn.commit()

            remaining = max(0, ADMIN_PIN_MAX_FAILED_ATTEMPTS - new_failed_attempts)
            if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS:
                return jsonify(
                    {
                        "success": False,
                        "error": "PIN has been disabled after 5 failed attempts. Reset your PIN in Settings.",
                        "failed_attempts": new_failed_attempts,
                        "remaining_attempts": 0,
                    }
                ), 423

            return jsonify(
                {
                    "success": False,
                    "error": f"Incorrect PIN. You have {remaining} attempt(s) remaining.",
                    "failed_attempts": new_failed_attempts,
                    "remaining_attempts": remaining,
                }
            ), 403

        cursor.execute(
            """
            UPDATE users
            SET admin_pin_failed_attempts=0,
                admin_pin_disabled=0
            WHERE user_id=%s
            """,
            (pin_row["user_id"],),
        )

        cursor.execute(
            """
            SELECT status_id
            FROM request_status
            WHERE status_name='REJECTED'
            LIMIT 1
            """
        )
        rejected_status_row = cursor.fetchone() or {}
        rejected_status_id = rejected_status_row.get("status_id")

        cursor.execute(
            """
            UPDATE request_coo_approvals
            SET status='REJECTED',
                approved_by_user_id=%s,
                approved_by_email=%s,
                approval_method='PIN',
                approved_at=CURRENT_TIMESTAMP
            WHERE request_id=%s
            """,
            (
                session.get("user_id"),
                (session.get("email") or "").strip().lower(),
                request_id,
            ),
        )

        if rejected_status_id is not None:
            cursor.execute(
                """
                UPDATE requests
                SET status_id=%s,
                    rejection_message=%s,
                    stage_position_id=NULL
                WHERE request_id=%s
                """,
                (rejected_status_id, reason, request_id),
            )

        cursor.execute(
            """
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'COO_REJECTED', %s)
            """,
            (
                request_id,
                session.get("user_id"),
                session.get("position_id"),
                (session.get("email") or "").strip().lower(),
                reason,
            ),
        )

        try:
            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "COO Special Rejection",
                    f"REQ#{request_id} rejected by COO via PIN ({session.get('email')}).",
                ),
            )
        except Exception:
            pass

        conn.commit()

        response_message = "COO special rejection completed. No post-decision COO email is sent by design."

        return jsonify(
            {
                "success": True,
                "message": response_message,
                "email": {"sent": 0, "recipients": 0},
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("special_access_reject_request failed")
        return jsonify({"success": False, "error": "Failed to reject request."}), 500
    finally:
        cursor.close()
        conn.close()


def process_budget_request_xendit(cursor, conn, request_id):
    ensure_budget_request_schema(cursor, conn)

    # Prevent duplicate budget sends for the same request.
    cursor.execute(
        """
        SELECT id, external_id, transaction_id
        FROM request_budget_transactions
        WHERE request_id = %s AND status = 'SUCCESS'
        ORDER BY id DESC
        LIMIT 1
        """,
        (request_id,),
    )
    existing_tx = cursor.fetchone() or {}
    if existing_tx:
        return {
            "processed": True,
            "already_processed": True,
            "external_id": str(existing_tx.get("external_id") or ""),
            "transaction_id": str(existing_tx.get("transaction_id") or ""),
        }

    secret_key = (os.environ.get("XENDIT_SECRET_KEY") or "").strip()
    if not secret_key:
        return {"processed": False, "reason": "xendit_not_configured"}

    cursor.execute(
        """
        SELECT
            r.request_id,
            r.amount,
            COALESCE(meta.budget_type, r.wfor, '') AS budget_type,
            COALESCE(meta.target_department, d.dept_name, '') AS target_department,
            COALESCE(u.email, '') AS requestor_email
        FROM requests r
        JOIN users u ON u.user_id = r.user_id
        LEFT JOIN departments d ON d.dept_id = u.dept_id
        LEFT JOIN request_budget_metadata meta ON meta.request_id = r.request_id
        WHERE r.request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    row = cursor.fetchone() or {}
    if not row:
        return {"processed": False, "reason": "request_not_found"}

    budget_type = normalize_request_budget(row.get("budget_type"))
    if not budget_type:
        return {"processed": False, "reason": "not_budget_request"}

    amount_value = parse_amount_decimal(row.get("amount"))
    if amount_value <= 0:
        return {"processed": False, "reason": "invalid_amount"}

    requestor_email = (row.get("requestor_email") or "").strip().lower()
    fallback_email = (os.environ.get("XENDIT_FALLBACK_EMAIL") or "budget.test@example.com").strip().lower()
    payer_email = requestor_email or fallback_email

    target_department = (row.get("target_department") or "").strip() or "Unknown Department"

    external_id = f"budget_req_{request_id}_{int(time.time())}_{random.randint(1000,9999)}"
    payload = {
        "external_id": external_id,
        "amount": float(amount_value),
        "payer_email": payer_email,
        "description": f"Budget release for {target_department} ({budget_type}) request #{request_id}",
        "currency": "PHP",
        "metadata": {
            "request_id": int(request_id),
            "budget_type": budget_type,
            "target_department": target_department,
        },
    }

    base_url = (os.environ.get("XENDIT_API_BASE_URL") or "https://api.xendit.co").strip().rstrip("/")
    endpoint = f"{base_url}/v2/invoices"

    try:
        response = requests.post(
            endpoint,
            json=payload,
            auth=(secret_key, ""),
            timeout=30,
        )
        response_json = response.json() if response.content else {}
    except Exception as exc:
        cursor.execute(
            """
            INSERT INTO request_budget_transactions (
                request_id, provider, external_id, status, amount, currency,
                budget_type, target_department, payload_json, error_message
            ) VALUES (%s, 'xendit', %s, 'FAILED', %s, 'PHP', %s, %s, %s, %s)
            """,
            (
                request_id,
                external_id,
                str(amount_value),
                budget_type,
                target_department,
                json.dumps(payload, ensure_ascii=True),
                str(exc),
            ),
        )
        conn.commit()
        return {"processed": False, "reason": "xendit_request_error", "error": str(exc)}

    transaction_id = ""
    if isinstance(response_json, dict):
        transaction_id = str(response_json.get("id") or "")

    status = "SUCCESS" if response.ok else "FAILED"
    cursor.execute(
        """
        INSERT INTO request_budget_transactions (
            request_id, provider, external_id, transaction_id, status, amount, currency,
            budget_type, target_department, payload_json, response_json, error_message
        ) VALUES (%s, 'xendit', %s, %s, %s, %s, 'PHP', %s, %s, %s, %s, %s)
        """,
        (
            request_id,
            external_id,
            transaction_id,
            status,
            str(amount_value),
            budget_type,
            target_department,
            json.dumps(payload, ensure_ascii=True),
            json.dumps(response_json, ensure_ascii=True) if isinstance(response_json, dict) else "",
            "" if response.ok else f"Xendit error: {response.status_code}",
        ),
    )
    conn.commit()

    return {
        "processed": bool(response.ok),
        "status": status,
        "transaction_id": transaction_id,
        "external_id": external_id,
    }


def ensure_request_type_form_schema_table(cursor, conn):
    global _request_type_form_schema_checked

    if _request_type_form_schema_checked:
        return

    # Table is managed externally by database migrations.
    _request_type_form_schema_checked = True


def ensure_request_form_submission_table(cursor, conn):
    global _request_form_submission_schema_checked

    if _request_form_submission_schema_checked:
        return

    # Table is managed externally by database migrations.
    _request_form_submission_schema_checked = True


def _sanitize_schema_identifier(value, fallback):
    text = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "").strip()).strip("_").lower()
    return text or fallback


def _normalize_table_columns(raw_columns):
    columns = []
    used = set()

    for index, raw in enumerate(raw_columns or [], start=1):
        if not isinstance(raw, dict):
            continue

        key = _sanitize_schema_identifier(raw.get("key"), f"column_{index}")
        if key in used:
            key = _sanitize_schema_identifier(f"{key}_{index}", f"column_{index}")
        used.add(key)

        col_type = str(raw.get("type") or "text").strip().lower()
        if col_type not in ALLOWED_FORM_COLUMN_TYPES:
            col_type = "text"

        label = str(raw.get("label") or key.replace("_", " ").title()).strip() or key
        columns.append({"key": key, "label": label, "type": col_type})

    if not columns:
        columns = [
            {"key": "item", "label": "Item", "type": "text"},
            {"key": "amount", "label": "Amount", "type": "number"},
        ]

    return columns


def _normalize_pdf_overlay_config(raw_overlay):
    if not isinstance(raw_overlay, dict):
        return None

    try:
        page = int(raw_overlay.get("page", 0) or 0)
    except (TypeError, ValueError):
        page = 0
    page = max(0, min(page, 500))

    def _as_ratio(value, default):
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = default
        return max(0.0, min(number, 1.0))

    x_rel = _as_ratio(raw_overlay.get("x_rel", 0.05), 0.05)
    y_rel = _as_ratio(raw_overlay.get("y_rel", 0.05), 0.05)
    w_rel = _as_ratio(raw_overlay.get("w_rel", 0.3), 0.3)
    h_rel = _as_ratio(raw_overlay.get("h_rel", 0.04), 0.04)

    try:
        font = int(raw_overlay.get("font", 10) or 10)
    except (TypeError, ValueError):
        font = 10
    font = max(8, min(font, 28))

    return {
        "page": page,
        "x_rel": x_rel,
        "y_rel": y_rel,
        "w_rel": w_rel,
        "h_rel": h_rel,
        "font": font,
    }


def _pdf_resolve_object(obj):
    try:
        if hasattr(obj, "get_object"):
            return obj.get_object()
    except Exception:
        pass
    return obj


def _pdf_field_property(field_obj, key, default=None):
    current = _pdf_resolve_object(field_obj)
    visited = 0

    while isinstance(current, dict) and visited < 16:
        if key in current:
            return current.get(key)

        parent = current.get("/Parent")
        current = _pdf_resolve_object(parent)
        visited += 1

    return default


def _extract_pdf_fields(reader):
    extracted = {}

    try:
        direct = reader.get_fields() or {}
    except Exception:
        direct = {}

    if isinstance(direct, dict):
        for raw_name, raw_obj in direct.items():
            name = str(raw_name or "").strip()
            if not name:
                continue
            obj = _pdf_resolve_object(raw_obj)
            extracted[name] = obj if isinstance(obj, dict) else {}

    # Fallback walk for PDFs where get_fields() is empty but AcroForm/Kids exist.
    try:
        root = _pdf_resolve_object((reader.trailer or {}).get("/Root"))
        acroform = _pdf_resolve_object((root or {}).get("/AcroForm"))
        roots = (acroform or {}).get("/Fields") or []
    except Exception:
        roots = []

    def walk(node, prefix=""):
        obj = _pdf_resolve_object(node)
        if not isinstance(obj, dict):
            return

        raw_name = obj.get("/T")
        name = str(raw_name or "").strip()
        full_name = f"{prefix}.{name}" if prefix and name else (name or prefix)

        kids = obj.get("/Kids") or []
        if isinstance(kids, list):
            for kid in kids:
                walk(kid, full_name)

        field_type = str(obj.get("/FT") or "").strip()
        if full_name and field_type and full_name not in extracted:
            extracted[full_name] = obj

    for node in roots:
        walk(node)

    # Additional fallback: scan page annotations for widget fields.
    try:
        for page in reader.pages:
            page_obj = _pdf_resolve_object(page)
            annots = (page_obj or {}).get("/Annots") or []
            if not isinstance(annots, list):
                continue

            for annot_ref in annots:
                annot = _pdf_resolve_object(annot_ref)
                if not isinstance(annot, dict):
                    continue

                subtype = str(annot.get("/Subtype") or "").strip().lower()
                if subtype != "/widget":
                    continue

                parent = _pdf_resolve_object(annot.get("/Parent"))
                field_obj = {}
                if isinstance(parent, dict):
                    field_obj.update(parent)
                field_obj.update(annot)

                name = str(field_obj.get("/T") or "").strip()
                if not name:
                    continue

                if name not in extracted:
                    extracted[name] = field_obj
    except Exception:
        pass

    return extracted


def _is_numeric_pdf_field(field_name, field_obj):
    name = str(field_name or "").strip().lower()
    if not name:
        return False

    keywords = {
        "amount",
        "total",
        "subtotal",
        "cost",
        "price",
        "rate",
        "qty",
        "quantity",
        "tax",
        "vat",
        "balance",
    }
    if any(token in name for token in keywords):
        return True

    field_type = str(_pdf_field_property(field_obj, "/FT", "") or "").strip().lower()
    return field_type in {"/number", "/num"}


def _is_multiline_pdf_field(field_obj):
    flags = _pdf_field_property(field_obj, "/Ff", 0)
    try:
        flags = int(flags)
    except Exception:
        flags = 0

    # PDF form flag bit 13 (4096) indicates multiline text.
    return bool(flags & 4096)


def build_fillable_schema_from_pdf_template(template_blob, total_formula=""):
    if not template_blob:
        raise ValueError("Fillable mode requires uploading a PDF template.")

    try:
        reader = _PdfReader(BytesIO(template_blob))
        fields = _extract_pdf_fields(reader)
    except Exception as exc:
        raise ValueError("Could not read PDF form fields from uploaded template.") from exc

    if not isinstance(fields, dict) or not fields:
        try:
            root = _pdf_resolve_object((reader.trailer or {}).get("/Root"))
            acroform = _pdf_resolve_object((root or {}).get("/AcroForm"))
            if isinstance(acroform, dict) and acroform.get("/XFA") is not None:
                raise ValueError(
                    "Uploaded PDF appears to use XFA forms, which are not supported by this server parser. "
                    "Please convert it to a standard AcroForm fillable PDF."
                )
        except ValueError:
            raise
        except Exception:
            pass

        raise ValueError(
            "Uploaded PDF does not contain detectable fillable fields. "
            "Use a fillable AcroForm PDF (not flattened/scanned), or switch this request type to Download mode."
        )

    blocks = []
    used_ids = set()

    for index, (raw_name, raw_obj) in enumerate(fields.items(), start=1):
        field_name = str(raw_name or "").strip()
        if not field_name:
            continue

        field_obj = raw_obj if isinstance(raw_obj, dict) else {}
        field_type = str(_pdf_field_property(field_obj, "/FT", "") or "").strip().lower()

        # Keep common user-input fields. (/tx text, /ch choice, /btn button)
        if field_type and field_type not in {"/tx", "/ch", "/btn"}:
            continue

        block_id = _sanitize_schema_identifier(field_name, f"field_{index}")
        if block_id in used_ids:
            block_id = _sanitize_schema_identifier(f"{block_id}_{index}", f"field_{index}")
        used_ids.add(block_id)

        if _is_numeric_pdf_field(field_name, field_obj):
            blocks.append(
                {
                    "id": block_id,
                    "type": "number",
                    "label": field_name,
                    "pdf_field_name": field_name,
                    "required": False,
                    "placeholder": "",
                    "include_in_total": False,
                }
            )
            continue

        blocks.append(
            {
                "id": block_id,
                "type": "textarea" if _is_multiline_pdf_field(field_obj) else "text",
                "label": field_name,
                "pdf_field_name": field_name,
                "required": False,
                "placeholder": "",
            }
        )

    if not blocks:
        raise ValueError(
            "Uploaded PDF has no supported user-input fields. "
            "Expected text/choice/button fields in the fillable PDF."
        )

    schema = {
        "version": 1,
        "total_formula": _sanitize_total_formula(total_formula),
        "blocks": blocks,
    }
    return normalize_request_type_form_schema(schema)


def extract_template_field_names(template_blob):
    if not template_blob:
        return []

    try:
        reader = _PdfReader(BytesIO(template_blob))
        fields = _extract_pdf_fields(reader)
    except Exception:
        return []

    names = []
    for raw_name in (fields or {}).keys():
        name = str(raw_name or "").strip()
        if name:
            names.append(name)

    return sorted(set(names), key=lambda item: item.lower())


def _sanitize_total_formula(raw_formula):
    formula = str(raw_formula or "").strip()
    if not formula:
        return ""

    if len(formula) > 300:
        raise ValueError("Total formula is too long.")

    if not re.fullmatch(r"[A-Za-z0-9_+\-*/().\s]+", formula):
        raise ValueError("Total formula contains unsupported characters.")

    return formula


def _prepare_total_formula_for_parse(raw_formula, value_map):
    formula = str(raw_formula or "").strip()
    if not formula:
        return ""

    # Normalize common operator/input variants users type in formulas.
    formula = formula.replace("×", "*").replace("÷", "/").replace("–", "-").replace("—", "-")
    formula = re.sub(r"\b([A-Za-z0-9_]+)\s*[xX]\s*([A-Za-z0-9_]+)\b", r"\1 * \2", formula)

    if isinstance(value_map, dict) and value_map:
        variants = []
        for raw_key in value_map.keys():
            key = str(raw_key or "").strip()
            if not key:
                continue

            spaced = key.replace("_", " ")
            hyphenated = key.replace("_", "-")
            for variant in {spaced, hyphenated}:
                if variant and variant.lower() != key.lower():
                    variants.append((variant, key))

        # Replace longer variants first to avoid partial replacements.
        variants.sort(key=lambda item: len(item[0]), reverse=True)
        for variant, key in variants:
            pattern = rf"(?<![A-Za-z0-9_]){re.escape(variant)}(?![A-Za-z0-9_])"
            formula = re.sub(pattern, key, formula, flags=re.IGNORECASE)

    formula = re.sub(r"\s+", " ", formula).strip()
    return formula


def _eval_total_formula_node(node, value_map):
    if isinstance(node, ast.Expression):
        return _eval_total_formula_node(node.body, value_map)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return Decimal(str(node.value))
        raise ValueError("Total formula only supports numeric constants.")

    if isinstance(node, ast.Num):
        return Decimal(str(node.n))

    if isinstance(node, ast.Name):
        if node.id in value_map:
            return value_map[node.id]

        lowered = str(node.id).lower()
        if lowered in value_map:
            return value_map[lowered]

        normalized = re.sub(r"[^a-z0-9]+", "", lowered)
        if normalized and normalized in value_map:
            return value_map[normalized]

        # Common plural/singular tolerance: Prices <-> Price, Quantities <-> Quantity, etc.
        if normalized.endswith("s") and normalized[:-1] in value_map:
            return value_map[normalized[:-1]]
        if normalized and f"{normalized}s" in value_map:
            return value_map[f"{normalized}s"]

        # Compatibility aliases when templates only expose amount-like totals.
        alias_map = {
            "qty": ["quantity", "amount"],
            "quantity": ["qty", "amount"],
            "price": ["prices", "amount"],
            "prices": ["price", "amount"],
        }
        for alias_key in alias_map.get(lowered, []):
            if alias_key in value_map:
                return value_map[alias_key]

        raise ValueError(f"Unknown formula key '{node.id}'")

    if isinstance(node, ast.UnaryOp):
        value = _eval_total_formula_node(node.operand, value_map)
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.USub):
            return -value
        raise ValueError("Unsupported unary operator in total formula.")

    if isinstance(node, ast.BinOp):
        left = _eval_total_formula_node(node.left, value_map)
        right = _eval_total_formula_node(node.right, value_map)

        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("Division by zero in total formula.")
            return left / right

        raise ValueError("Unsupported operator in total formula.")

    raise ValueError("Unsupported total formula expression.")


def evaluate_total_formula(total_formula, value_map):
    normalized_formula = _prepare_total_formula_for_parse(total_formula, value_map)
    formula = _sanitize_total_formula(normalized_formula)
    if not formula:
        return Decimal("0")

    try:
        tree = ast.parse(formula, mode="eval")
    except Exception as exc:
        raise ValueError("Could not parse total formula.") from exc

    result = _eval_total_formula_node(tree, value_map)
    return Decimal(result).quantize(Decimal("0.01"))


def normalize_request_type_form_schema(raw_schema):
    if isinstance(raw_schema, str):
        try:
            parsed = json.loads(raw_schema)
        except Exception as exc:
            raise ValueError("Invalid form schema JSON.") from exc
    elif isinstance(raw_schema, dict):
        parsed = raw_schema
    else:
        raise ValueError("Form schema is required.")

    blocks = parsed.get("blocks")
    if not isinstance(blocks, list):
        blocks = []

    normalized_blocks = []
    used_ids = set()
    total_formula = _sanitize_total_formula(parsed.get("total_formula"))

    for index, block in enumerate(blocks, start=1):
        if not isinstance(block, dict):
            continue

        block_type = str(block.get("type") or "").strip().lower()
        if block_type not in ALLOWED_FORM_BLOCK_TYPES:
            continue

        block_id = _sanitize_schema_identifier(block.get("id"), f"field_{index}")
        if block_id in used_ids:
            block_id = _sanitize_schema_identifier(f"{block_id}_{index}", f"field_{index}")
        used_ids.add(block_id)

        label_default = block_id.replace("_", " ").title()
        label = str(block.get("label") or label_default).strip() or label_default
        required = bool(block.get("required"))

        if block_type == "heading":
            normalized_blocks.append(
                {
                    "id": block_id,
                    "type": "heading",
                    "text": str(block.get("text") or label).strip() or label,
                }
            )
            continue

        if block_type == "shape":
            shape = str(block.get("shape") or "line").strip().lower()
            if shape not in ALLOWED_FORM_SHAPES:
                shape = "line"
            normalized_blocks.append(
                {
                    "id": block_id,
                    "type": "shape",
                    "shape": shape,
                    "text": str(block.get("text") or "").strip(),
                }
            )
            continue

        if block_type in {"text", "textarea", "number", "date"}:
            normalized = {
                "id": block_id,
                "type": block_type,
                "label": label,
                "required": required,
                "placeholder": str(block.get("placeholder") or "").strip(),
            }
            pdf_field_name = str(block.get("pdf_field_name") or "").strip()
            if pdf_field_name:
                normalized["pdf_field_name"] = pdf_field_name

            overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))
            if overlay_cfg:
                normalized["pdf_overlay"] = overlay_cfg

            if block_type == "number":
                normalized["include_in_total"] = bool(block.get("include_in_total"))
            normalized_blocks.append(normalized)
            continue

        if block_type == "signature":
            # signature block: where an approver/reviewer/position signature image should be placed
            sig_source = str(block.get("signature_source") or "approver").strip().lower()
            sig_position_id = None
            try:
                if block.get("signature_position_id") not in (None, ""):
                    sig_position_id = int(block.get("signature_position_id"))
            except (TypeError, ValueError):
                sig_position_id = None

            overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))
            sig_norm = {
                "id": block_id,
                "type": "signature",
                "label": label,
                "required": required,
                "signature_source": sig_source,
            }
            if sig_position_id:
                sig_norm["signature_position_id"] = sig_position_id
            if overlay_cfg:
                sig_norm["pdf_overlay"] = overlay_cfg

            normalized_blocks.append(sig_norm)
            continue

        if block_type == "table":
            columns = _normalize_table_columns(block.get("columns"))
            numeric_keys = [col["key"] for col in columns if col["type"] == "number"]
            requested_sum_key = _sanitize_schema_identifier(block.get("sum_column_key"), "")
            if requested_sum_key in numeric_keys:
                sum_column_key = requested_sum_key
            else:
                sum_column_key = numeric_keys[0] if numeric_keys else ""

            try:
                min_rows = int(block.get("min_rows") or 0)
            except (TypeError, ValueError):
                min_rows = 0
            min_rows = max(0, min(min_rows, 100))

            table_overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))

            normalized_blocks.append(
                {
                    "id": block_id,
                    "type": "table",
                    "label": label,
                    "required": required,
                    "min_rows": min_rows,
                    "sum_column_key": sum_column_key,
                    "columns": columns,
                    **({"pdf_overlay": table_overlay_cfg} if table_overlay_cfg else {}),
                }
            )

    return {
        "version": 1,
        "total_formula": total_formula,
        "blocks": normalized_blocks,
    }


def get_default_request_form_schema():
    return {
        "version": 1,
        "total_formula": "",
        "blocks": [
            {
                "id": "particulars",
                "type": "table",
                "label": "Particulars",
                "required": True,
                "min_rows": 1,
                "sum_column_key": "amount",
                "columns": [
                    {"key": "item", "label": "Particular", "type": "text"},
                    {"key": "amount", "label": "Amount", "type": "number"},
                ],
            },
        ],
    }


def _strip_legacy_cdr_prefilled_blocks(schema):
    """
    Backward compatibility for old fallback CDR schemas that duplicated
    Name/Department/Disbursement Type even though those are already provided.
    """
    if not isinstance(schema, dict):
        return schema

    blocks = schema.get("blocks") if isinstance(schema.get("blocks"), list) else []
    if not blocks:
        return schema

    legacy_ids = {"requestor_name", "requesting_department", "disbursement_type"}
    block_ids = {str((block or {}).get("id") or "").strip() for block in blocks if isinstance(block, dict)}

    # Only strip when this is the old default CDR-style schema shape.
    if not legacy_ids.issubset(block_ids):
        return schema

    has_particulars_table = any(
        isinstance(block, dict)
        and str(block.get("type") or "").strip().lower() == "table"
        and str(block.get("id") or "").strip() == "particulars"
        for block in blocks
    )
    if not has_particulars_table:
        return schema

    cleaned_schema = dict(schema)
    cleaned_schema["blocks"] = [
        block
        for block in blocks
        if not (
            isinstance(block, dict)
            and str(block.get("id") or "").strip() in legacy_ids
        )
    ]
    return cleaned_schema


def _is_cdr_request_type_name(request_type_name):
    text = str(request_type_name or "").strip().lower()
    return ("check disbursement request" in text) or ("cdr" in text)


def _strip_cdr_particulars_table(schema, request_type_name=""):
    if not isinstance(schema, dict):
        return schema

    if not _is_cdr_request_type_name(request_type_name):
        return schema

    blocks = schema.get("blocks") if isinstance(schema.get("blocks"), list) else []
    if not blocks:
        return schema

    filtered_blocks = []
    for block in blocks:
        if not isinstance(block, dict):
            continue

        block_id = str(block.get("id") or "").strip().lower()
        block_type = str(block.get("type") or "").strip().lower()
        block_label = str(block.get("label") or "").strip().lower()

        is_particulars_table = (
            block_type == "table"
            and (block_id == "particulars" or block_label == "particulars")
        )
        if not is_particulars_table:
            filtered_blocks.append(block)

    # Keep schema unchanged if this would leave no inputs at all.
    if not filtered_blocks:
        return schema

    cleaned_schema = dict(schema)
    cleaned_schema["blocks"] = filtered_blocks
    return cleaned_schema


def get_request_type_fillable_schema(cursor, request_type_id):
    cursor.execute(
        """
        SELECT
            rt.type_name,
            fs.schema_json
        FROM request_types rt
        LEFT JOIN request_type_form_schemas fs
            ON fs.request_type_id = rt.request_type_id
        WHERE rt.request_type_id = %s
        LIMIT 1
        """,
        (request_type_id,),
    )
    row = cursor.fetchone() or {}
    request_type_name = str(_coerce_first_value(row, "type_name", "") or "").strip()
    raw_schema = _coerce_first_value(row, "schema_json", "")

    if raw_schema:
        try:
            normalized = normalize_request_type_form_schema(raw_schema)
            normalized = _strip_legacy_cdr_prefilled_blocks(normalized)
            return _strip_cdr_particulars_table(normalized, request_type_name)
        except ValueError:
            fallback = _strip_legacy_cdr_prefilled_blocks(get_default_request_form_schema())
            return _strip_cdr_particulars_table(fallback, request_type_name)

    fallback = _strip_legacy_cdr_prefilled_blocks(get_default_request_form_schema())
    return _strip_cdr_particulars_table(fallback, request_type_name)


def _is_derived_total_block(block):
    block_id = str((block or {}).get("id") or "").strip().lower()
    block_label = str((block or {}).get("label") or "").strip().lower()
    return ("total" in block_id) or ("total" in block_label)


def validate_fillable_submission(schema, template_data_json):
    if not template_data_json:
        return None, None, False, "Please fill out the representative form first."

    try:
        payload = json.loads(template_data_json)
    except Exception:
        return None, None, False, "Invalid form data payload."

    if not isinstance(payload, dict):
        return None, None, False, "Invalid form data payload."

    fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else {}
    tables = payload.get("tables") if isinstance(payload.get("tables"), dict) else {}
    extra_pages_raw = payload.get("extra_pages") if isinstance(payload.get("extra_pages"), list) else []

    cleaned_fields = {}
    cleaned_tables = {}
    formula_values = {}
    table_column_alias_keys = set()
    total = Decimal("0")
    has_total_sources = False

    def _split_list_values(raw_value):
        text = str(raw_value or "").strip()
        if not text:
            return []
        return [segment.strip() for segment in re.split(r"[\r\n,;]+", text) if segment and segment.strip()]

    def _is_strict_number_text(raw_value):
        text = str(raw_value or "").strip()
        if not text:
            return False
        return bool(re.fullmatch(r"[-+]?(?:\d+(?:\.\d+)?|\.\d+)", text))

    def _is_valid_iso_date(raw_value):
        text = str(raw_value or "").strip()
        if not text:
            return False
        try:
            datetime.datetime.strptime(text, "%Y-%m-%d")
            return True
        except Exception:
            return False

    def _sanitize_optional_extra_page(raw_page):
        page = raw_page if isinstance(raw_page, dict) else {}
        page_fields = page.get("fields") if isinstance(page.get("fields"), dict) else {}
        page_tables = page.get("tables") if isinstance(page.get("tables"), dict) else {}
        raw_copy_template_page = page.get("copy_template_page")

        copy_template_page = None
        if raw_copy_template_page not in (None, ""):
            try:
                copy_template_page = int(str(raw_copy_template_page).strip())
            except (TypeError, ValueError):
                return None, "Copied template page must be a valid page number."
            if copy_template_page <= 0:
                return None, "Copied template page must be a valid page number."

        clean_fields = {}
        clean_tables = {}
        has_any_value = False

        for block in schema.get("blocks", []):
            block_id = str(block.get("id") or "").strip()
            block_type = str(block.get("type") or "").strip().lower()
            if not block_id or not block_type:
                continue

            if block_type in {"text", "textarea", "number", "date"}:
                raw_value = page_fields.get(block_id, "")
                if isinstance(raw_value, (dict, list)):
                    raw_value = ""
                value = str(raw_value or "").strip()
                clean_fields[block_id] = value
                if value:
                    has_any_value = True

                if block_type == "date" and value and not _is_valid_iso_date(value):
                    return None, f"{block.get('label') or block_id} must be a valid date (YYYY-MM-DD)."

                if block_type == "number":
                    number_tokens = _split_list_values(value)
                    if value and (not number_tokens or not all(_is_strict_number_text(token) for token in number_tokens)):
                        return None, f"{block.get('label') or block_id} must contain numbers only."

            if block_type == "table":
                rows = page_tables.get(block_id)
                if not isinstance(rows, list):
                    rows = []

                columns = block.get("columns") if isinstance(block.get("columns"), list) else []
                clean_rows = []

                for row in rows:
                    if not isinstance(row, dict):
                        continue

                    clean_row = {}
                    row_has_value = False
                    for column in columns:
                        key = str(column.get("key") or "").strip()
                        if not key:
                            continue

                        raw_cell = row.get(key, "")
                        if isinstance(raw_cell, (dict, list)):
                            raw_cell = ""
                        cell = str(raw_cell or "").strip()
                        clean_row[key] = cell
                        if cell:
                            row_has_value = True

                        col_type = str(column.get("type") or "").strip().lower()
                        if col_type == "number":
                            cell_tokens = _split_list_values(cell)
                            if cell and (not cell_tokens or not all(_is_strict_number_text(token) for token in cell_tokens)):
                                return None, f"{block.get('label') or block_id} column {key} must contain numbers only."

                    if row_has_value:
                        has_any_value = True
                        clean_rows.append(clean_row)

                clean_tables[block_id] = clean_rows

        if not has_any_value:
            return None, ""

        cleaned_page = {"fields": clean_fields, "tables": clean_tables}
        if copy_template_page is not None:
            cleaned_page["copy_template_page"] = copy_template_page

        return cleaned_page, ""

    for block in schema.get("blocks", []):
        block_id = str(block.get("id") or "").strip()
        block_type = str(block.get("type") or "").strip().lower()
        if not block_id or not block_type:
            continue

        if block_type in {"text", "textarea", "number", "date"}:
            raw_value = fields.get(block_id, "")
            if isinstance(raw_value, (dict, list)):
                raw_value = ""
            value = str(raw_value or "").strip()
            cleaned_fields[block_id] = value

            if block.get("required") and not value:
                return None, None, False, f"{block.get('label') or block_id} is required."

            if block_type == "date" and value and not _is_valid_iso_date(value):
                return None, None, False, f"{block.get('label') or block_id} must be a valid date (YYYY-MM-DD)."

            if block_type == "number":
                number_tokens = _split_list_values(value)
                if value and (not number_tokens or not all(_is_strict_number_text(token) for token in number_tokens)):
                    return None, None, False, f"{block.get('label') or block_id} must contain numbers only."

                number_value = sum((parse_amount_decimal(token) for token in number_tokens), Decimal("0"))
                formula_values[block_id] = number_value

            if (
                block_type == "number"
                and bool(block.get("include_in_total"))
                and not _is_derived_total_block(block)
            ):
                has_total_sources = True
                total += formula_values[block_id]

        if block_type == "table":
            rows = tables.get(block_id)
            if not isinstance(rows, list):
                rows = []

            columns = block.get("columns") if isinstance(block.get("columns"), list) else []
            sum_column_key = str(block.get("sum_column_key") or "").strip()
            clean_rows = []
            numeric_column_totals = {}

            for column in columns:
                col_key = str(column.get("key") or "").strip()
                col_type = str(column.get("type") or "").strip().lower()
                if col_key and col_type == "number":
                    numeric_column_totals[col_key] = Decimal("0")

            for row in rows:
                if not isinstance(row, dict):
                    continue

                clean_row = {}
                has_any_value = False
                for column in columns:
                    key = str(column.get("key") or "").strip()
                    if not key:
                        continue

                    raw_cell = row.get(key, "")
                    if isinstance(raw_cell, (dict, list)):
                        raw_cell = ""
                    cell = str(raw_cell or "").strip()
                    clean_row[key] = cell
                    if cell:
                        has_any_value = True

                    if key in numeric_column_totals:
                        cell_tokens = _split_list_values(cell)
                        if cell and (not cell_tokens or not all(_is_strict_number_text(token) for token in cell_tokens)):
                            return None, None, False, f"{block.get('label') or block_id} row {len(clean_rows) + 1} column {key} must contain numbers only."
                        amount_value = sum((parse_amount_decimal(token) for token in cell_tokens), Decimal("0"))
                        numeric_column_totals[key] += amount_value

                        if key == sum_column_key:
                            has_total_sources = True
                            total += amount_value

                if has_any_value:
                    clean_rows.append(clean_row)

            try:
                min_rows = int(block.get("min_rows") or 0)
            except (TypeError, ValueError):
                min_rows = 0
            if bool(block.get("required")) and min_rows < 1:
                min_rows = 1

            if len(clean_rows) < min_rows:
                return None, None, False, f"{block.get('label') or block_id} requires at least {min_rows} row(s)."

            block_sum_total = parse_amount_decimal(numeric_column_totals.get(sum_column_key, Decimal("0")))
            cleaned_tables[block_id] = clean_rows
            formula_values[block_id] = block_sum_total

            for numeric_key, numeric_total in numeric_column_totals.items():
                formula_values[f"{block_id}_{numeric_key}"] = numeric_total

                if numeric_key in table_column_alias_keys:
                    formula_values[numeric_key] = parse_amount_decimal(formula_values.get(numeric_key, Decimal("0"))) + numeric_total
                elif numeric_key not in formula_values:
                    formula_values[numeric_key] = numeric_total
                    table_column_alias_keys.add(numeric_key)

    total_formula = str(schema.get("total_formula") or "").strip()
    if total_formula:
        try:
            total = evaluate_total_formula(total_formula, formula_values)
            has_total_sources = True
        except ValueError as exc:
            error_text = str(exc)
            # Formula mistakes should not block request submission; fallback to normal totals.
            if (
                "Unknown formula key" in error_text
                or "Could not parse total formula" in error_text
                or "Unsupported total formula expression" in error_text
                or "Unsupported operator in total formula" in error_text
                or "Total formula contains unsupported characters" in error_text
            ):
                logger.warning(
                    "Formula validation failed, using fallback total. formula=%s available=%s error=%s",
                    total_formula,
                    sorted(formula_values.keys()),
                    exc,
                )
            else:
                available = ", ".join(sorted(formula_values.keys())) or "none"
                return None, None, False, f"Invalid total formula: {exc}. Available keys: {available}."

    cleaned_payload = {
        "version": schema.get("version") or 1,
        "fields": cleaned_fields,
        "tables": cleaned_tables,
    }

    cleaned_extra_pages = []
    for raw_page in extra_pages_raw:
        page_payload, page_error = _sanitize_optional_extra_page(raw_page)
        if page_error:
            return None, None, False, page_error
        if page_payload:
            cleaned_extra_pages.append(page_payload)

    if cleaned_extra_pages:
        cleaned_payload["extra_pages"] = cleaned_extra_pages

    return cleaned_payload, total.quantize(Decimal("0.01")), has_total_sources, ""


def _build_preview_fill_payload_and_total(schema, raw_payload):
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    fields_raw = payload.get("fields") if isinstance(payload.get("fields"), dict) else {}
    tables_raw = payload.get("tables") if isinstance(payload.get("tables"), dict) else {}
    extra_pages_raw = payload.get("extra_pages") if isinstance(payload.get("extra_pages"), list) else []

    cleaned_fields = {}
    cleaned_tables = {}
    formula_values = {}
    table_column_alias_keys = set()
    total = Decimal("0")
    has_total_sources = False

    def _split_list_values(raw_value):
        text = str(raw_value or "").strip()
        if not text:
            return []
        return [segment.strip() for segment in re.split(r"[\r\n,;]+", text) if segment and segment.strip()]

    def _is_strict_number_text(raw_value):
        text = str(raw_value or "").strip()
        if not text:
            return False
        return bool(re.fullmatch(r"[-+]?(?:\d+(?:\.\d+)?|\.\d+)", text))

    for block in schema.get("blocks", []):
        block_id = str(block.get("id") or "").strip()
        block_type = str(block.get("type") or "").strip().lower()
        if not block_id or not block_type:
            continue

        if block_type in {"text", "textarea", "number", "date"}:
            raw_value = fields_raw.get(block_id, "")
            if isinstance(raw_value, (dict, list)):
                raw_value = ""
            value = str(raw_value or "").strip()
            cleaned_fields[block_id] = value

            if block_type == "number":
                list_values = _split_list_values(value)
                number_tokens = []
                if value and list_values and all(_is_strict_number_text(token) for token in list_values):
                    number_tokens = list_values
                number_value = sum((parse_amount_decimal(token) for token in number_tokens), Decimal("0"))
                formula_values[block_id] = number_value

                if bool(block.get("include_in_total")) and not _is_derived_total_block(block):
                    has_total_sources = True
                    total += number_value

        if block_type == "table":
            rows = tables_raw.get(block_id)
            if not isinstance(rows, list):
                rows = []

            columns = block.get("columns") if isinstance(block.get("columns"), list) else []
            sum_column_key = str(block.get("sum_column_key") or "").strip()
            clean_rows = []
            numeric_column_totals = {}

            for column in columns:
                col_key = str(column.get("key") or "").strip()
                col_type = str(column.get("type") or "").strip().lower()
                if col_key and col_type == "number":
                    numeric_column_totals[col_key] = Decimal("0")

            for row in rows:
                if not isinstance(row, dict):
                    continue

                clean_row = {}
                has_any_value = False
                for column in columns:
                    key = str(column.get("key") or "").strip()
                    if not key:
                        continue

                    raw_cell = row.get(key, "")
                    if isinstance(raw_cell, (dict, list)):
                        raw_cell = ""
                    cell = str(raw_cell or "").strip()
                    clean_row[key] = cell
                    if cell:
                        has_any_value = True

                    if key in numeric_column_totals:
                        cell_tokens = _split_list_values(cell)
                        amount_value = (
                            sum((parse_amount_decimal(token) for token in cell_tokens), Decimal("0"))
                            if cell_tokens and all(_is_strict_number_text(token) for token in cell_tokens)
                            else Decimal("0")
                        )
                        numeric_column_totals[key] += amount_value

                        if key == sum_column_key:
                            has_total_sources = True
                            total += amount_value

                if has_any_value:
                    clean_rows.append(clean_row)

            block_sum_total = parse_amount_decimal(numeric_column_totals.get(sum_column_key, Decimal("0")))
            cleaned_tables[block_id] = clean_rows
            formula_values[block_id] = block_sum_total

            for numeric_key, numeric_total in numeric_column_totals.items():
                formula_values[f"{block_id}_{numeric_key}"] = numeric_total

                if numeric_key in table_column_alias_keys:
                    formula_values[numeric_key] = parse_amount_decimal(formula_values.get(numeric_key, Decimal("0"))) + numeric_total
                elif numeric_key not in formula_values:
                    formula_values[numeric_key] = numeric_total
                    table_column_alias_keys.add(numeric_key)

    total_formula = str(schema.get("total_formula") or "").strip()
    if total_formula:
        try:
            total = evaluate_total_formula(total_formula, formula_values)
            has_total_sources = True
        except ValueError:
            # Preview should still render even while formula is being edited.
            pass

    cleaned_payload = {
        "version": schema.get("version") or 1,
        "fields": cleaned_fields,
        "tables": cleaned_tables,
    }

    cleaned_extra_pages = []
    for raw_page in extra_pages_raw:
        if not isinstance(raw_page, dict):
            continue
        page_fields = raw_page.get("fields") if isinstance(raw_page.get("fields"), dict) else {}
        page_tables = raw_page.get("tables") if isinstance(raw_page.get("tables"), dict) else {}
        raw_copy_template_page = raw_page.get("copy_template_page")

        copy_template_page = None
        if raw_copy_template_page not in (None, ""):
            try:
                parsed_copy_page = int(str(raw_copy_template_page).strip())
                if parsed_copy_page > 0:
                    copy_template_page = parsed_copy_page
            except (TypeError, ValueError):
                copy_template_page = None

        page_clean_fields = {}
        page_clean_tables = {}
        has_any_value = False

        for block in schema.get("blocks", []):
            block_id = str(block.get("id") or "").strip()
            block_type = str(block.get("type") or "").strip().lower()
            if not block_id or not block_type:
                continue

            if block_type in {"text", "textarea", "number", "date"}:
                raw_value = page_fields.get(block_id, "")
                if isinstance(raw_value, (dict, list)):
                    raw_value = ""
                value = str(raw_value or "").strip()
                page_clean_fields[block_id] = value
                if value:
                    has_any_value = True

            if block_type == "table":
                rows = page_tables.get(block_id)
                if not isinstance(rows, list):
                    rows = []

                columns = block.get("columns") if isinstance(block.get("columns"), list) else []
                clean_rows = []
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    clean_row = {}
                    row_has_value = False
                    for column in columns:
                        key = str(column.get("key") or "").strip()
                        if not key:
                            continue
                        raw_cell = row.get(key, "")
                        if isinstance(raw_cell, (dict, list)):
                            raw_cell = ""
                        cell = str(raw_cell or "").strip()
                        clean_row[key] = cell
                        if cell:
                            row_has_value = True
                    if row_has_value:
                        has_any_value = True
                        clean_rows.append(clean_row)

                page_clean_tables[block_id] = clean_rows

        if has_any_value:
            cleaned_page = {"fields": page_clean_fields, "tables": page_clean_tables}
            if copy_template_page is not None:
                cleaned_page["copy_template_page"] = copy_template_page
            cleaned_extra_pages.append(cleaned_page)

    if cleaned_extra_pages:
        cleaned_payload["extra_pages"] = cleaned_extra_pages

    return cleaned_payload, total.quantize(Decimal("0.01")), has_total_sources


def parse_amount_decimal(value):
    if isinstance(value, Decimal):
        return value

    text = str(value or "").strip()
    if not text:
        return Decimal("0")

    cleaned = re.sub(r"[^0-9.\-]", "", text)
    if cleaned in {"", "-", ".", "-."}:
        return Decimal("0")

    try:
        return Decimal(cleaned)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0")


def parse_amount_input_decimal(value):
    """Parse amount input that may be a single number or a comma-separated list.

    Examples:
    - "8000" -> 8000
    - "8,000" -> 8000
    - "2000,1000,4000" -> 7000
    """
    text = str(value or "").strip()
    if not text:
        return Decimal("0")

    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"-?\d{1,3}(,\d{3})+(\.\d+)?", compact):
        return parse_amount_decimal(compact)

    if "," not in text:
        return parse_amount_decimal(text)

    total = Decimal("0")
    for token in [t.strip() for t in text.split(",") if str(t).strip()]:
        total += parse_amount_decimal(token)
    return total


def _normalize_pdf_field_lookup_key(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def build_filled_pdf_from_submission(
    template_pdf_bytes,
    schema,
    cleaned_payload,
    total_amount=None,
    total_amount_scope="first",
    total_amount_template_page=None,
):
    if not template_pdf_bytes:
        return template_pdf_bytes

    if not isinstance(cleaned_payload, dict):
        return template_pdf_bytes

    fields_payload = cleaned_payload.get("fields")
    if not isinstance(fields_payload, dict):
        fields_payload = {}

    tables_payload = cleaned_payload.get("tables")
    if not isinstance(tables_payload, dict):
        tables_payload = {}

    extra_pages_payload = cleaned_payload.get("extra_pages") if isinstance(cleaned_payload.get("extra_pages"), list) else []

    try:
        reader = _PdfReader(BytesIO(template_pdf_bytes))
        template_fields = _extract_pdf_fields(reader)
        writer = _PdfWriter()
        writer.clone_document_from_reader(reader)
        page_sizes = [
            (float(p.mediabox.width), float(p.mediabox.height))
            for p in reader.pages
        ]

        if hasattr(writer, "set_need_appearances_writer"):
            writer.set_need_appearances_writer()
    except Exception:
        logger.exception("build_filled_pdf_from_submission failed to initialize PDF reader/writer")
        return template_pdf_bytes

    exact_name_map = {}
    lower_name_map = {}
    norm_name_map = {}

    for raw_name in (template_fields or {}).keys():
        name = str(raw_name or "").strip()
        if not name:
            continue
        exact_name_map[name] = name
        lower_name_map[name.lower()] = name
        normalized = _normalize_pdf_field_lookup_key(name)
        if normalized and normalized not in norm_name_map:
            norm_name_map[normalized] = name

    def resolve_field_name(candidates, used_names=None):
        used_names = used_names or set()
        for candidate in candidates:
            key = str(candidate or "").strip()
            if not key:
                continue
            if key in exact_name_map:
                resolved = exact_name_map[key]
                if resolved not in used_names:
                    return resolved

            lower = key.lower()
            if lower in lower_name_map:
                resolved = lower_name_map[lower]
                if resolved not in used_names:
                    return resolved

            normalized = _normalize_pdf_field_lookup_key(key)
            if normalized in norm_name_map:
                resolved = norm_name_map[normalized]
                if resolved not in used_names:
                    return resolved

        return None

    field_values = {}
    used_pdf_fields = set()
    unmapped_lines = []
    overlay_text_items = []
    overflow_overlay_requests = []

    def format_list_value_text(raw_text):
        text = str(raw_text or "").strip()
        if not text:
            return ""

        parts = [segment.strip() for segment in re.split(r"[\r\n,;]+", text) if segment and segment.strip()]
        if len(parts) > 1:
            return "\n".join(parts)
        return text

    def append_overlay_text(raw_text, raw_overlay):
        text = format_list_value_text(raw_text)
        overlay = _normalize_pdf_overlay_config(raw_overlay)
        if not text or not overlay:
            return

        page = int(overlay.get("page", 0) or 0)
        if page < 0 or page >= len(page_sizes):
            return

        page_w, page_h = page_sizes[page]
        font = int(overlay.get("font", 10) or 10)
        box_w = max(10.0, float(overlay.get("w_rel", 0.3)) * page_w)
        box_h = max(10.0, float(overlay.get("h_rel", 0.04)) * page_h)
        leading = max(10.0, font * 1.2)

        # Fit text to the mapped box; any overflow is moved to fallback summary pages.
        max_lines = max(1, int(box_h / leading))
        approx_char_width = max(4.5, font * 0.55)
        wrap_width = max(8, int(max(10.0, box_w - 6.0) / approx_char_width))
        wrapped_lines = []
        for paragraph in (str(text).splitlines() or [""]):
            wrapped_lines.extend(textwrap.wrap(paragraph, width=wrap_width) or [""])

        fitted_lines = wrapped_lines[:max_lines]
        overflow_lines = [line for line in wrapped_lines[max_lines:] if str(line or "").strip()]

        fitted_text = "\n".join(fitted_lines).strip()
        if overflow_lines:
            while overflow_lines:
                chunk_lines = overflow_lines[:max_lines]
                overflow_lines = overflow_lines[max_lines:]
                chunk_text = "\n".join(chunk_lines).strip()
                if not chunk_text:
                    continue
                overflow_overlay_requests.append(
                    {
                        "source_page": page,
                        "x": float(overlay.get("x_rel", 0.05)) * page_w,
                        "y": max(0.0, page_h - (float(overlay.get("y_rel", 0.05)) * page_h) - box_h),
                        "h": box_h,
                        "w": box_w,
                        "text": chunk_text,
                        "font": font,
                    }
                )

        if not fitted_text:
            return

        x = float(overlay.get("x_rel", 0.05)) * page_w
        y_top = float(overlay.get("y_rel", 0.05)) * page_h
        y = max(0.0, page_h - y_top - box_h)

        overlay_text_items.append(
            {
                "page": page,
                "x": x,
                "y": y,
                "h": box_h,
                "w": box_w,
                "text": fitted_text,
                "font": font,
            }
        )

    for block in schema.get("blocks", []):
        block_type = str(block.get("type") or "").strip().lower()
        if block_type in {"text", "textarea", "number", "date"}:
            block_id = str(block.get("id") or "").strip()
            if not block_id:
                continue

            block_overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))

            value = fields_payload.get(block_id, "")
            if isinstance(value, (dict, list)):
                value = ""
            value_text = str(value or "")
            list_value_text = format_list_value_text(
                value_text
            )

            pdf_field_name = str(
                block.get("pdf_field_name")
                or block.get("label")
                or block_id
            ).strip()
            matched_name = resolve_field_name([
                pdf_field_name,
                block.get("label"),
                block_id,
            ], used_pdf_fields)
            value_for_pdf = list_value_text if list_value_text else value_text

            if matched_name:
                field_values[matched_name] = value_for_pdf
                used_pdf_fields.add(matched_name)
            elif list_value_text:
                # If an overlay placement exists, keep output on-template instead of fallback summary.
                if not block_overlay_cfg:
                    unmapped_lines.append(list_value_text)

            # Avoid duplicate text when AcroForm field mapping already succeeded.
            if (not matched_name) and block_overlay_cfg:
                append_overlay_text(list_value_text, block_overlay_cfg)
            continue

        if block_type != "table":
            continue

        block_id = str(block.get("id") or "").strip()
        if not block_id:
            continue

        rows = tables_payload.get(block_id)
        if not isinstance(rows, list) or not rows:
            continue

        table_label = str(block.get("label") or block_id).strip() or block_id
        table_norm = _sanitize_schema_identifier(table_label, block_id)
        table_overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))
        table_overlay_values = []
        table_unmapped_values = []

        for idx, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue

            row_unmapped_parts = []
            row_all_parts = []
            for key, raw_val in row.items():
                val = format_list_value_text(raw_val, multiline=True)
                if not val:
                    continue

                # Keep only user-entered content (no "Row X" or "Key=Value" wrappers).
                row_all_parts.append(val)

                col_norm = _sanitize_schema_identifier(key, key)
                candidates = [
                    f"{block_id}_{col_norm}_{idx}",
                    f"{block_id}_{idx}_{col_norm}",
                    f"{table_norm}_{col_norm}_{idx}",
                    f"{table_norm}_{idx}_{col_norm}",
                    f"{col_norm}_{idx}",
                    f"{col_norm}{idx}",
                    f"{col_norm}_{idx:02d}",
                    f"{col_norm}{idx:02d}",
                ]

                matched_name = resolve_field_name(candidates, used_pdf_fields)
                if matched_name:
                    field_values[matched_name] = val
                    used_pdf_fields.add(matched_name)
                else:
                    row_unmapped_parts.append(val)

            if row_unmapped_parts:
                # If table overlay is configured, keep row text inside placed overlay instead of fallback summary.
                if not table_overlay_cfg:
                    table_unmapped_values.extend(row_unmapped_parts)

            if row_all_parts:
                table_overlay_values.extend(row_all_parts)

        if table_unmapped_values:
            unmapped_lines.append("\n".join(table_unmapped_values))

        if table_overlay_cfg and table_overlay_values:
            append_overlay_text("\n".join(table_overlay_values), table_overlay_cfg)

    # Ensure auto-calculated total is visible in the final file.
    if total_amount is not None:
        total_decimal = parse_amount_decimal(total_amount).quantize(Decimal("0.01"))
        total_text = f"{total_decimal}"
        total_written = False

        normalized_scope = str(total_amount_scope or "first").strip().lower()
        if normalized_scope not in {"first", "all", "specific"}:
            normalized_scope = "first"

        normalized_specific_page = None
        if normalized_scope == "specific":
            try:
                parsed_page = int(str(total_amount_template_page).strip())
                if parsed_page > 0:
                    normalized_specific_page = parsed_page - 1
            except (TypeError, ValueError):
                normalized_specific_page = None

        def _is_total_block_target(block_obj):
            if normalized_scope == "all":
                return True

            if normalized_scope != "specific":
                return True

            if normalized_specific_page is None:
                return True

            overlay = _normalize_pdf_overlay_config(block_obj.get("pdf_overlay"))
            if not overlay:
                return False

            try:
                page_idx = int(overlay.get("page", 0) or 0)
            except (TypeError, ValueError):
                page_idx = 0

            return page_idx == normalized_specific_page

        for block in schema.get("blocks", []):
            block_type = str(block.get("type") or "").strip().lower()
            if block_type != "number":
                continue

            block_id = str(block.get("id") or "").strip().lower()
            block_label = str(block.get("label") or "").strip().lower()
            if "total" not in block_id and "total" not in block_label:
                continue

            if not _is_total_block_target(block):
                continue

            block_overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))
            matched_name = resolve_field_name([
                block.get("pdf_field_name"),
                block.get("label"),
                block.get("id"),
            ], used_pdf_fields)

            if matched_name:
                field_values[matched_name] = total_text
                used_pdf_fields.add(matched_name)
                total_written = True
                if normalized_scope == "first":
                    break
                continue

            if block_overlay_cfg:
                append_overlay_text(total_text, block_overlay_cfg)
                total_written = True
                if normalized_scope == "first":
                    break
                continue

        if not total_written:
            matched_total_name = resolve_field_name([
                "total_amount",
                "total amount",
                "grand_total",
                "grand total",
                "amount_total",
                "total",
            ], used_pdf_fields)

            if matched_total_name:
                field_values[matched_total_name] = total_text
                used_pdf_fields.add(matched_total_name)
            else:
                unmapped_lines.append("")
                unmapped_lines.append(total_text)

    try:
        if field_values:
            for page in writer.pages:
                writer.update_page_form_field_values(
                    page,
                    field_values,
                    auto_regenerate=False,
                )

        if overflow_overlay_requests:
            for request_item in overflow_overlay_requests:
                source_page = int(request_item.get("source_page", -1) or -1)
                if source_page < 0 or source_page >= len(reader.pages):
                    text_fallback = str(request_item.get("text") or "").strip()
                    if text_fallback:
                        unmapped_lines.append(text_fallback)
                    continue

                writer.add_page(reader.pages[source_page])
                cloned_page_index = len(writer.pages) - 1
                overlay_text_items.append(
                    {
                        "page": cloned_page_index,
                        "x": float(request_item.get("x") or 0.0),
                        "y": float(request_item.get("y") or 0.0),
                        "h": float(request_item.get("h") or 0.0),
                        "w": float(request_item.get("w") or 0.0),
                        "text": str(request_item.get("text") or ""),
                        "font": int(request_item.get("font") or 10),
                    }
                )

        if unmapped_lines:
            from reportlab.lib.pagesizes import letter

            summary_buf = BytesIO()
            if writer.pages:
                page_w = float(writer.pages[0].mediabox.width)
                page_h = float(writer.pages[0].mediabox.height)
            else:
                page_w, page_h = letter

            summary_canvas = _rl_canvas.Canvas(summary_buf, pagesize=(page_w, page_h))
            y = page_h - 56

            def _draw_line(text, bold=False, gap=14):
                nonlocal y
                font_name = "Helvetica-Bold" if bold else "Helvetica"
                font_size = 10
                summary_canvas.setFont(font_name, font_size)

                for paragraph in (str(text or "").splitlines() or [""]):
                    wrapped_lines = textwrap.wrap(paragraph, width=105) or [""]
                    for line in wrapped_lines:
                        if y < 56:
                            summary_canvas.showPage()
                            y = page_h - 56
                            summary_canvas.setFont(font_name, font_size)
                        summary_canvas.drawString(48, y, line)
                        y -= gap

            normalized_lines = []
            for raw_line in unmapped_lines:
                normalized = format_list_value_text(raw_line)
                if normalized:
                    normalized_lines.append(normalized)

            if normalized_lines:
                compact_text = "\n".join(normalized_lines)
                _draw_line(compact_text, bold=False, gap=13)

            summary_canvas.save()
            summary_reader = _PdfReader(BytesIO(summary_buf.getvalue()))
            if summary_reader.pages and (not field_values) and writer.pages:
                writer.pages[0].merge_page(summary_reader.pages[0])
                for page in summary_reader.pages[1:]:
                    writer.add_page(page)
            else:
                for page in summary_reader.pages:
                    writer.add_page(page)

        out = BytesIO()
        writer.write(out)
        final_pdf_bytes = out.getvalue()

        if overlay_text_items:
            overlay_pdf = make_overlay_pdf(final_pdf_bytes, overlay_text_items, [])
            final_pdf_bytes = merge_overlay(final_pdf_bytes, overlay_pdf)

        if extra_pages_payload:
            stitched_reader = _PdfReader(BytesIO(final_pdf_bytes))
            stitched_writer = _PdfWriter()
            for page in stitched_reader.pages:
                stitched_writer.add_page(page)

            def _uniquify_widget_field_names(page_obj, suffix):
                try:
                    page_dict = _pdf_resolve_object(page_obj)
                    annots = (page_dict or {}).get("/Annots") or []
                    if not isinstance(annots, list):
                        return

                    renamed_parent_ids = set()
                    for annot_ref in annots:
                        annot = _pdf_resolve_object(annot_ref)
                        if not isinstance(annot, dict):
                            continue

                        subtype = str(annot.get("/Subtype") or "").strip().lower()
                        if subtype != "/widget":
                            continue

                        existing_name = str(annot.get("/T") or "").strip()
                        if existing_name:
                            annot["/T"] = f"{existing_name}{suffix}"

                        parent = _pdf_resolve_object(annot.get("/Parent"))
                        if isinstance(parent, dict):
                            parent_id = id(parent)
                            if parent_id in renamed_parent_ids:
                                continue

                            parent_name = str(parent.get("/T") or "").strip()
                            if parent_name:
                                parent["/T"] = f"{parent_name}{suffix}"
                                renamed_parent_ids.add(parent_id)
                except Exception:
                    logger.exception("Failed to uniquify widget field names for copied template page")

            for extra_page_index, extra_page in enumerate(extra_pages_payload, start=1):
                if not isinstance(extra_page, dict):
                    continue
                extra_fields = extra_page.get("fields") if isinstance(extra_page.get("fields"), dict) else {}
                extra_tables = extra_page.get("tables") if isinstance(extra_page.get("tables"), dict) else {}
                if not extra_fields and not extra_tables:
                    continue

                selected_template_page = None
                raw_selected_template_page = extra_page.get("copy_template_page")
                if raw_selected_template_page not in (None, ""):
                    try:
                        parsed_selected_page = int(str(raw_selected_template_page).strip())
                        if parsed_selected_page > 0:
                            selected_template_page = parsed_selected_page - 1
                    except (TypeError, ValueError):
                        selected_template_page = None

                extra_payload = {
                    "version": schema.get("version") or 1,
                    "fields": extra_fields,
                    "tables": extra_tables,
                }
                extra_pdf_bytes = build_filled_pdf_from_submission(
                    template_pdf_bytes,
                    schema,
                    extra_payload,
                    total_amount=None,
                    total_amount_scope="first",
                    total_amount_template_page=None,
                )
                extra_reader = _PdfReader(BytesIO(extra_pdf_bytes))
                copy_suffix = f"__copy_{extra_page_index}_{int(time.time() * 1000) % 100000}"
                if selected_template_page is not None and extra_reader.pages:
                    if 0 <= selected_template_page < len(extra_reader.pages):
                        selected_page_obj = extra_reader.pages[selected_template_page]
                        _uniquify_widget_field_names(selected_page_obj, copy_suffix)
                        stitched_writer.add_page(selected_page_obj)
                    else:
                        selected_page_obj = extra_reader.pages[0]
                        _uniquify_widget_field_names(selected_page_obj, copy_suffix)
                        stitched_writer.add_page(selected_page_obj)
                else:
                    for page_index, page in enumerate(extra_reader.pages, start=1):
                        _uniquify_widget_field_names(page, f"{copy_suffix}_p{page_index}")
                        stitched_writer.add_page(page)

            stitched_out = BytesIO()
            stitched_writer.write(stitched_out)
            final_pdf_bytes = stitched_out.getvalue()

        return final_pdf_bytes
    except Exception:
        logger.exception("build_filled_pdf_from_submission failed; using original template bytes")
        return template_pdf_bytes


def _resolve_saved_signature_png(cursor, actor_user_id=None, actor_email=None, company_id=None):
    ensure_user_saved_signature_schema(cursor, None)

    normalized_company_id = None
    try:
        if company_id not in (None, ""):
            normalized_company_id = int(company_id)
    except (TypeError, ValueError):
        normalized_company_id = None

    normalized_user_id = None
    try:
        if actor_user_id not in (None, ""):
            normalized_user_id = int(actor_user_id)
    except (TypeError, ValueError):
        normalized_user_id = None

    if normalized_user_id is None and str(actor_email or "").strip():
        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE LOWER(TRIM(email)) = %s
              AND (%s IS NULL OR company_id = %s)
            ORDER BY user_id DESC
            LIMIT 1
            """,
            (
                str(actor_email or "").strip().lower(),
                normalized_company_id,
                normalized_company_id,
            ),
        )
        user_row = cursor.fetchone() or {}
        try:
            if user_row.get("user_id") not in (None, ""):
                normalized_user_id = int(user_row.get("user_id"))
        except (TypeError, ValueError):
            normalized_user_id = None

    if normalized_user_id is None:
        return None

    cursor.execute(
        """
        SELECT signature_png
        FROM user_saved_signatures
        WHERE user_id = %s
          AND (%s IS NULL OR company_id = %s OR company_id IS NULL)
        LIMIT 1
        """,
        (normalized_user_id, normalized_company_id, normalized_company_id),
    )
    row = cursor.fetchone() or {}
    return row.get("signature_png")


def render_mapped_signature_blocks_for_request(cursor, conn, request_id):
    ensure_tenant_schema(cursor, conn)
    ensure_request_type_form_schema_table(cursor, conn)
    ensure_request_form_submission_table(cursor, conn)
    ensure_user_saved_signature_schema(cursor, conn)
    ensure_it_approval_team_schema(cursor, conn)

    cursor.execute(
        """
        SELECT
            r.request_id,
            r.company_id,
            r.request_type_id,
            r.amount,
            r.attachment,
            COALESCE(rs.status_name, '') AS status_name,
            rt.template_mode,
            rt.template_file,
            rfs.form_data_json,
            a.signed_pdf
        FROM requests r
        LEFT JOIN request_status rs ON rs.status_id = r.status_id
        LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
        LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
        LEFT JOIN request_annotations a ON a.request_id = r.request_id
        WHERE r.request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    req = cursor.fetchone() or {}
    if not req:
        return {"applied": False, "reason": "request_not_found"}

    template_mode = str(req.get("template_mode") or "").strip().upper()
    template_blob = req.get("template_file")
    raw_form_json = str(req.get("form_data_json") or "").strip()
    request_type_id = req.get("request_type_id")

    if template_mode != "FILLABLE":
        return {"applied": False, "reason": "not_fillable"}
    if not request_type_id:
        return {"applied": False, "reason": "missing_request_type"}

    schema = get_request_type_fillable_schema(cursor, int(request_type_id))

    # Preserve existing data first: use current signed PDF or request attachment as base.
    base_pdf = req.get("signed_pdf") or req.get("attachment")

    # Fallback to regenerated fillable PDF only when no existing rendered PDF is available.
    if not base_pdf and template_blob and raw_form_json:
        try:
            payload = json.loads(raw_form_json)
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            base_pdf = build_filled_pdf_from_submission(
                template_blob,
                schema,
                payload,
                total_amount=req.get("amount"),
            )

    if not base_pdf and template_blob:
        base_pdf = template_blob

    if not base_pdf:
        return {"applied": False, "reason": "base_pdf_not_generated"}

    signature_blocks = [
        b
        for b in (schema.get("blocks") or [])
        if isinstance(b, dict) and str(b.get("type") or "").strip().lower() == "signature"
    ]
    if not signature_blocks:
        return {"applied": False, "reason": "no_signature_blocks"}

    cursor.execute(
        """
        SELECT actor_user_id, actor_position_id, actor_email, action, created_at
        FROM request_actions
        WHERE request_id = %s
          AND action IN ('APPROVED', 'COO_APPROVED')
        ORDER BY created_at ASC
        """,
        (request_id,),
    )
    action_rows = cursor.fetchall() or []

    if not action_rows and str(req.get("status_name") or "").strip().upper() != "REJECTED":
        return {"applied": False, "reason": "no_approval_actions"}

    latest_by_position = {}
    for row in action_rows:
        try:
            pos_id = int(row.get("actor_position_id")) if row.get("actor_position_id") not in (None, "") else None
        except (TypeError, ValueError):
            pos_id = None
        if pos_id is not None:
            latest_by_position[pos_id] = row

    cursor.execute(
        "SELECT position_id FROM it_approval_positions WHERE company_id = %s",
        (int(req.get("company_id") or 0),),
    )
    allowed_it_positions = {
        int(r.get("position_id"))
        for r in (cursor.fetchall() or [])
        if r.get("position_id") is not None
    }

    status_upper = str(req.get("status_name") or "").strip().upper()

    try:
        page_sizes = [
            (float(p.mediabox.width), float(p.mediabox.height))
            for p in _PdfReader(BytesIO(base_pdf)).pages
        ]
    except Exception:
        page_sizes = []

    text_items = []
    image_items = []

    def _append_rejected_text(overlay_cfg):
        if not overlay_cfg or not page_sizes:
            return
        page = int(overlay_cfg.get("page", 0) or 0)
        if page < 0 or page >= len(page_sizes):
            return
        page_w, page_h = page_sizes[page]
        box_w = max(10.0, float(overlay_cfg.get("w_rel", 0.25)) * page_w)
        box_h = max(10.0, float(overlay_cfg.get("h_rel", 0.05)) * page_h)
        x = float(overlay_cfg.get("x_rel", 0.05)) * page_w
        y_top = float(overlay_cfg.get("y_rel", 0.05)) * page_h
        y = max(0.0, page_h - y_top - box_h)
        text_items.append(
            {
                "page": page,
                "x": x,
                "y": y,
                "w": box_w,
                "h": box_h,
                "text": "REJECTED",
                "font": max(10, int(overlay_cfg.get("font", 12) or 12)),
            }
        )

    for block in signature_blocks:
        overlay_cfg = _normalize_pdf_overlay_config(block.get("pdf_overlay"))
        if not overlay_cfg:
            continue

        if status_upper == "REJECTED":
            _append_rejected_text(overlay_cfg)
            continue

        sig_source = str(block.get("signature_source") or "approver").strip().lower()
        target_action = None

        if sig_source == "reviewer":
            target_action = action_rows[0] if action_rows else None
        elif sig_source == "position":
            mapped_pos = None
            try:
                if block.get("signature_position_id") not in (None, ""):
                    mapped_pos = int(block.get("signature_position_id"))
            except (TypeError, ValueError):
                mapped_pos = None

            if mapped_pos is not None and mapped_pos in allowed_it_positions:
                target_action = latest_by_position.get(mapped_pos)
        else:
            target_action = action_rows[-1] if action_rows else None

        if not target_action and action_rows:
            target_action = action_rows[-1]
        if not target_action:
            continue

        sig_png = _resolve_saved_signature_png(
            cursor,
            actor_user_id=target_action.get("actor_user_id"),
            actor_email=target_action.get("actor_email"),
            company_id=req.get("company_id"),
        )
        if not sig_png:
            continue

        page = int(overlay_cfg.get("page", 0) or 0)
        if page < 0 or page >= len(page_sizes):
            continue

        page_w, page_h = page_sizes[page]
        box_w = max(10.0, float(overlay_cfg.get("w_rel", 0.25)) * page_w)
        box_h = max(10.0, float(overlay_cfg.get("h_rel", 0.05)) * page_h)
        x = float(overlay_cfg.get("x_rel", 0.05)) * page_w
        y_top = float(overlay_cfg.get("y_rel", 0.05)) * page_h
        y = max(0.0, page_h - y_top - box_h)
        image_items.append(
            {
                "page": page,
                "x": x,
                "y": y,
                "w": box_w,
                "h": box_h,
                "image_bytes": sig_png,
            }
        )

    final_pdf = base_pdf
    if text_items or image_items:
        overlay_pdf = make_overlay_pdf(base_pdf, text_items, image_items)
        final_pdf = merge_overlay(base_pdf, overlay_pdf)

    cursor.execute(
        """
        INSERT INTO request_annotations (request_id, signed_pdf)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE signed_pdf = VALUES(signed_pdf)
        """,
        (request_id, final_pdf),
    )

    return {
        "applied": True,
        "signature_blocks": len(signature_blocks),
        "image_overlays": len(image_items),
        "text_overlays": len(text_items),
    }


def parse_budget_record_date(value):
    text = str(value or "").strip()
    if not text:
        return None

    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        pass

    try:
        return datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def get_user_budget_total(cursor, email):
    cursor.execute(
        """
        SELECT total_budget
        FROM admin_budget_totals
        WHERE email = %s
        LIMIT 1
        """,
        (email,),
    )
    row = cursor.fetchone() or {}
    value = _coerce_first_value(row, "total_budget", BUDGET_DEFAULT_TOTAL)
    amount = parse_amount_decimal(value)
    return amount if amount >= 0 else BUDGET_DEFAULT_TOTAL


def get_admin_pin_state(cursor, email):
    cursor.execute(
        """
        SELECT
            user_id,
            email,
            admin_pin_hash,
            COALESCE(admin_pin_failed_attempts, 0) AS admin_pin_failed_attempts,
            COALESCE(admin_pin_disabled, 0) AS admin_pin_disabled
        FROM users
        WHERE email = %s
        LIMIT 1
        """,
        (email,),
    )
    return cursor.fetchone()


def is_finance_amount_editor(cursor, company_id, user_id):
    try:
        normalized_company_id = int(company_id or 0)
        normalized_user_id = int(user_id or 0)
    except (TypeError, ValueError):
        return False

    if normalized_company_id <= 0 or normalized_user_id <= 0:
        return False

    cursor.execute(
        """
        SELECT 1
        FROM finance_amount_editors
        WHERE company_id = %s AND user_id = %s
        LIMIT 1
        """,
        (normalized_company_id, normalized_user_id),
    )
    return bool(cursor.fetchone())


def _run_pending_stage_reminder_email_batch(email_jobs):
    for job in email_jobs or []:
        try:
            send_pending_action_reminder_email(
                receiver=(job or {}).get("receiver"),
                request_id=(job or {}).get("request_id"),
                request_type=(job or {}).get("request_type"),
                stage_name=(job or {}).get("stage_name"),
                age_hours=(job or {}).get("age_hours", 24),
            )
        except Exception:
            logger.exception("Pending stage reminder email failed")


def process_position_pending_reminders(cursor, conn, company_id, position_id):
    """Return overdue requests for the current stage and queue one reminder email per request per day."""
    try:
        normalized_company_id = int(company_id or 0)
        normalized_position_id = int(position_id or 0)
    except (TypeError, ValueError):
        return []

    if normalized_company_id <= 0 or normalized_position_id <= 0:
        return []

    ensure_stage_reminder_schema(cursor, conn)

    cursor.execute(
        """
        SELECT
            r.request_id,
            COALESCE(rt.type_name, 'Request') AS request_type_name,
            COALESCE(p.position_name, 'Assigned Stage') AS stage_name,
            TIMESTAMPDIFF(HOUR, r.created_at, NOW()) AS age_hours
        FROM requests r
        JOIN request_status s ON s.status_id = r.status_id
        LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
        LEFT JOIN positions p ON p.position_id = r.stage_position_id
        WHERE r.company_id = %s
          AND r.stage_position_id = %s
          AND UPPER(COALESCE(s.status_name, '')) = 'PENDING'
          AND TIMESTAMPDIFF(HOUR, r.created_at, NOW()) >= 24
        ORDER BY r.created_at ASC
        LIMIT 100
        """,
        (normalized_company_id, normalized_position_id),
    )
    overdue_rows = cursor.fetchall() or []

    if not overdue_rows:
        return []

    cursor.execute(
        """
        SELECT DISTINCT LOWER(TRIM(email)) AS email
        FROM users
        WHERE company_id = %s
          AND position_id = %s
          AND COALESCE(is_deleted, 0) = 0
          AND COALESCE(is_banned, 0) = 0
          AND email IS NOT NULL
          AND TRIM(email) <> ''
        """,
        (normalized_company_id, normalized_position_id),
    )
    recipient_rows = cursor.fetchall() or []
    recipients = sorted(
        {
            str((row or {}).get("email") or "").strip().lower()
            for row in recipient_rows
            if str((row or {}).get("email") or "").strip()
        }
    )

    email_jobs = []
    for row in overdue_rows:
        request_id = int(row.get("request_id") or 0)
        if request_id <= 0:
            continue

        cursor.execute(
            """
            INSERT IGNORE INTO request_stage_reminders
                (request_id, company_id, position_id, reminder_date, recipients_json)
            VALUES (%s, %s, %s, CURDATE(), %s)
            """,
            (
                request_id,
                normalized_company_id,
                normalized_position_id,
                json.dumps(recipients, ensure_ascii=True),
            ),
        )

        if cursor.rowcount > 0 and recipients:
            age_hours = int(row.get("age_hours") or 24)
            for receiver in recipients:
                email_jobs.append(
                    {
                        "receiver": receiver,
                        "request_id": request_id,
                        "request_type": row.get("request_type_name") or "Request",
                        "stage_name": row.get("stage_name") or "Assigned Stage",
                        "age_hours": age_hours,
                    }
                )

    if email_jobs:
        conn.commit()
        run_background_task(_run_pending_stage_reminder_email_batch, email_jobs)

    return [
        {
            "request_id": int(row.get("request_id") or 0),
            "request_type_name": row.get("request_type_name") or "Request",
            "stage_name": row.get("stage_name") or "Assigned Stage",
            "age_hours": int(row.get("age_hours") or 24),
        }
        for row in overdue_rows
        if int(row.get("request_id") or 0) > 0
    ]


def _build_admin_pin_state_payload(row):
    failed_attempts = int(_coerce_first_value(row, "admin_pin_failed_attempts", 0) or 0)
    pin_disabled = bool(int(_coerce_first_value(row, "admin_pin_disabled", 0) or 0))
    pin_set = bool(_coerce_first_value(row, "admin_pin_hash", None))

    return {
        "pin_set": pin_set,
        "pin_disabled": pin_disabled,
        "failed_attempts": failed_attempts,
        "remaining_attempts": max(0, ADMIN_PIN_MAX_FAILED_ATTEMPTS - failed_attempts),
    }


def is_valid_admin_pin(pin):
    return bool(re.fullmatch(r"\d{4}", str(pin or "")))


def clear_admin_pin_otp_session_flags():
    session.pop("admin_pin_otp_pending_email", None)
    session.pop("admin_pin_otp_pending_at", None)
    session.pop("admin_pin_otp_verified_email", None)
    session.pop("admin_pin_otp_verified_at", None)


def send_admin_pin_otp(cursor, conn, email):
    cursor.execute(
        """
        SELECT TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age_seconds
        FROM otp_codes
        WHERE email = %s
        LIMIT 1
        """,
        (email,),
    )
    row = cursor.fetchone()
    age_seconds = _coerce_first_value(row, "age_seconds", None)

    if age_seconds is not None:
        try:
            age_seconds = int(age_seconds)
        except (TypeError, ValueError):
            age_seconds = None

    if age_seconds is not None and age_seconds < ADMIN_PIN_OTP_COOLDOWN_SECONDS:
        wait_for = ADMIN_PIN_OTP_COOLDOWN_SECONDS - age_seconds
        return False, f"Please wait {wait_for} seconds before requesting a new OTP."

    otp = random.randint(100000, 999999)
    cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
    cursor.execute("INSERT INTO otp_codes (email, otp) VALUES (%s, %s)", (email, otp))
    conn.commit()

    body = (
        "Good day,\n\n"
        f"Your PIN verification OTP is: {otp}\n\n"
        "This OTP expires in 10 minutes.\n"
        "If you did not request this, please ignore this message."
    )
    sent = send_cc_email(email, "PIN Verification OTP", body)
    if not sent:
        cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
        conn.commit()
        return False, "Failed to send OTP email. Please try again."

    session["admin_pin_otp_pending_email"] = email
    session["admin_pin_otp_pending_at"] = int(time.time())
    session.pop("admin_pin_otp_verified_email", None)
    session.pop("admin_pin_otp_verified_at", None)
    return True, "OTP sent to your email."


def is_admin_pin_otp_verified(email):
    verified_email = (session.get("admin_pin_otp_verified_email") or "").strip().lower()
    verified_at = int(session.get("admin_pin_otp_verified_at") or 0)
    now_ts = int(time.time())
    if not verified_email or verified_email != email:
        return False
    if verified_at <= 0:
        return False
    if (now_ts - verified_at) > ADMIN_PIN_OTP_MAX_AGE_SECONDS:
        return False
    return True


# OTP Routes
srotp_view = limiter.limit("5 per minute")(srotp)
verify_view = limiter.limit("10 per minute")(verify)

app.add_url_rule("/send-otp", "send_otp", srotp_view, methods=["POST"])
app.add_url_rule("/verify", "verify_otp", verify_view, methods=["POST"])



# Main routes
@app.route("/")
def home():
    if "email" not in session:
        return render_template("landing.html")
    
    return redirect("/dashboard")


@app.route("/dashboard")
@login_required
def dashboard():
    if "email" not in session:
        return redirect("/login")

    role = (session.get("role") or "").strip()
    email = (session.get("email") or "").strip().lower()
    dept = (session.get("dept") or "").strip()
    position = (session.get("position") or "").strip()
    is_it_context = role == "IT" or (role == "SuperAdmin" and position.lower() == "it")

    if DEFAULT_SAAS_EMAIL and email == DEFAULT_SAAS_EMAIL:
        flash("Login Successful", "success")
        return redirect("/saas-admin")
    
    if dept == "GSD" and role in ["AssistantAdmin", "Admin"]:
        flash("Login Successful", "success")
        return redirect("/gsd_dashboard")

    elif role in ["Dean", "Reviewer",]:
        flash("Login Successful", "success")
        return redirect("/dean")

    elif is_it_context:
        flash("Login Successful", "success")
        return redirect("/IT")

    elif role in ["Admin", "AssistantAdmin", "SuperAdmin", "SBO"]:
        flash("Login Successful", "success")
        return redirect("/admin")

    elif role.lower() == "dev":
        flash("Login Successful", "success")
        return redirect("/dev")
    else:
        flash("Login Successful", "success")
        return redirect("/udashboard")


@app.route("/dev")
@login_required
def dev_dashboard():
    if (session.get("role") or "").strip().lower() != "dev":
        return "Forbidden", 403

    maintenance_state = get_system_maintenance_state(use_cache=False)

    return render_template(
        "dev.html",
        email=(session.get("email") or "").strip(),
        company_id=int(session.get("company_id") or 0),
        company_name=(session.get("company_name") or "").strip(),
        maintenance_mode_enabled=bool(maintenance_state.get("enabled")),
        maintenance_reason=str(maintenance_state.get("reason") or ""),
        maintenance_updated_by=str(maintenance_state.get("updated_by") or ""),
        maintenance_updated_at=str(maintenance_state.get("updated_at") or ""),
    )


@app.route("/api/dev/system-maintenance", methods=["GET"])
@login_required
def dev_get_system_maintenance_api():
    if (session.get("role") or "").strip().lower() != "dev":
        return jsonify({"success": False, "error": "Forbidden"}), 403

    state = get_system_maintenance_state(use_cache=False)
    return jsonify(
        {
            "success": True,
            "enabled": bool(state.get("enabled")),
            "reason": str(state.get("reason") or ""),
            "updated_by": str(state.get("updated_by") or ""),
            "updated_at": str(state.get("updated_at") or ""),
        }
    )


@app.route("/api/dev/system-maintenance", methods=["POST"])
@login_required
def dev_set_system_maintenance_api():
    if (session.get("role") or "").strip().lower() != "dev":
        return jsonify({"success": False, "error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    raw_enabled = payload.get("enabled")
    enabled = str(raw_enabled).strip().lower() in {"1", "true", "yes", "on"}
    reason = _normalize_maintenance_reason(payload.get("reason"))

    try:
        state = set_system_maintenance_state(
            enabled=enabled,
            reason=reason,
            updated_by_email=(session.get("email") or "").strip(),
        )
    except Exception:
        logger.exception("dev_set_system_maintenance_api failed")
        return jsonify({"success": False, "error": "Failed to update maintenance mode"}), 500

    return jsonify(
        {
            "success": True,
            "enabled": bool(state.get("enabled")),
            "reason": str(state.get("reason") or ""),
            "updated_by": str(state.get("updated_by") or ""),
            "updated_at": str(state.get("updated_at") or ""),
        }
    )


@app.route("/api/dev/system-broadcast", methods=["POST"])
@login_required
def dev_send_system_broadcast_api():
    if (session.get("role") or "").strip().lower() != "dev":
        return jsonify({"success": False, "error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    title = _normalize_broadcast_title(payload.get("title"))
    message = _normalize_broadcast_message(payload.get("message"))

    if not message:
        return jsonify({"success": False, "error": "Message is required"}), 400

    try:
        broadcast_id = create_system_broadcast(
            title=title,
            message=message,
            actor_email=(session.get("email") or "").strip(),
        )
    except Exception:
        logger.exception("dev_send_system_broadcast_api failed")
        return jsonify({"success": False, "error": "Failed to send broadcast"}), 500

    return jsonify(
        {
            "success": True,
            "id": broadcast_id,
            "title": title,
            "message": message,
        }
    )


@csrf.exempt
@app.post("/api/contact-message")
def submit_contact_message():
    """Handle contact form submissions from landing page"""
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            data = request.form.to_dict(flat=True) if request.form else {}

        def _field(*keys):
            for key in keys:
                value = data.get(key)
                if value is None:
                    continue
                value = str(value).strip()
                if value:
                    return value
            return ""
        
        organization_name = _field("organization_name", "organizationName", "contactName", "name", "company_name")
        email = _field("email", "contactEmail")
        phone = _field("phone", "contactPhone")
        inquiry_type = _field("inquiry_type", "inquiryType", "contactType", "type")
        message = _field("message", "contactMessage", "contact_message")
        
        if not organization_name:
            return jsonify({"success": False, "error": "Organization name is required"}), 400
        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        if not inquiry_type:
            return jsonify({"success": False, "error": "Inquiry type is required"}), 400
        if not message:
            return jsonify({"success": False, "error": "Message is required"}), 400
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        ensure_contact_messages_schema(cursor, conn)
        
        cursor.execute(
            """
            INSERT INTO contact_messages 
            (organization_name, email, phone, inquiry_type, message, status)
            VALUES (%s, %s, %s, %s, %s, 'new')
            """,
            (organization_name, email, phone, inquiry_type, message)
        )
        conn.commit()
        
        contact_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "contact_id": contact_id,
            "message": "Thank you for your inquiry. We will contact you soon."
        }), 201
        
    except Exception as e:
        logger.exception("submit_contact_message failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/saas-admin")
@login_required
def saas_admin_dashboard():
    if not is_saas_owner_user():
        return "Forbidden", 403

    return render_template(
        "saas_admin.html",
        email=(session.get("email") or "").strip(),
        role=(session.get("role") or "").strip(),
    )


@app.route("/api/saas/contact-messages", methods=["GET"])
@login_required
def saas_get_contact_messages():
    """Get all contact messages from landing page"""
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    try:
        status = request.args.get("status", "").strip().lower()
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        ensure_contact_messages_schema(cursor, conn)
        
        if status and status in ["new", "read", "replied"]:
            cursor.execute(
                """
                SELECT contact_id, organization_name, email, phone, inquiry_type, status, created_at
                FROM contact_messages
                WHERE status = %s
                ORDER BY created_at DESC
                """,
                (status,)
            )
        else:
            cursor.execute(
                """
                SELECT contact_id, organization_name, email, phone, inquiry_type, status, created_at
                FROM contact_messages
                ORDER BY created_at DESC
                """
            )
        
        messages = cursor.fetchall() or []
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "messages": messages
        }), 200
        
    except Exception as e:
        logger.exception("saas_get_contact_messages failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/saas/contact-messages/<int:contact_id>", methods=["GET"])
@login_required
def saas_get_contact_message(contact_id):
    """Get a specific contact message"""
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        ensure_contact_messages_schema(cursor, conn)
        
        cursor.execute(
            """
            SELECT *
            FROM contact_messages
            WHERE contact_id = %s
            """,
            (contact_id,)
        )
        
        message = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not message:
            return jsonify({"success": False, "error": "Message not found"}), 404
        
        return jsonify({
            "success": True,
            "message": message
        }), 200
        
    except Exception as e:
        logger.exception("saas_get_contact_message failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/saas/contact-messages/<int:contact_id>/status", methods=["POST"])
@login_required
def saas_update_contact_message_status(contact_id):
    """Update contact message status (new, read, replied)"""
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    try:
        data = request.get_json(silent=True) or {}
        new_status = (data.get("status") or "").strip().lower()
        
        if new_status not in ["new", "read", "replied"]:
            return jsonify({"success": False, "error": "Invalid status"}), 400
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        ensure_contact_messages_schema(cursor, conn)
        
        cursor.execute(
            """
            UPDATE contact_messages
            SET status = %s, updated_at = NOW()
            WHERE contact_id = %s
            """,
            (new_status, contact_id)
        )
        
        conn.commit()
        
        cursor.execute(
            """
            SELECT *
            FROM contact_messages
            WHERE contact_id = %s
            """,
            (contact_id,)
        )
        
        message = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": message
        }), 200
        
    except Exception as e:
        logger.exception("saas_update_contact_message_status failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/saas/companies", methods=["GET"])
@login_required
def saas_companies_api():
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                o.company_id,
                o.company_name,
                o.company_slug,
                o.is_active,
                o.created_at,
                COALESCE(ts.plan_name, 'FREE') AS plan_name,
                COALESCE(ts.subscription_status, 'ACTIVE') AS subscription_status,
                COALESCE(ts.monthly_price, 0) AS monthly_price,
                COALESCE(ts.seats_limit, 0) AS seats_limit,
                COALESCE(ts.requests_limit, 0) AS requests_limit,
                COALESCE(u.user_count, 0) AS user_count,
                COALESCE(r.request_count, 0) AS request_count
            FROM organizations o
            LEFT JOIN tenant_subscriptions ts ON ts.company_id = o.company_id
            LEFT JOIN (
                SELECT company_id, COUNT(*) AS user_count
                FROM users
                GROUP BY company_id
            ) u ON u.company_id = o.company_id
            LEFT JOIN (
                SELECT company_id, COUNT(*) AS request_count
                FROM requests
                GROUP BY company_id
            ) r ON r.company_id = o.company_id
            ORDER BY o.created_at DESC
            """
        )
        rows = cursor.fetchall() or []

        for row in rows:
            row["monthly_price"] = float(parse_amount_decimal(row.get("monthly_price")))
            row["is_active"] = int(row.get("is_active") or 0)

        return jsonify({"success": True, "companies": rows})
    except Exception:
        logger.exception("saas_companies_api failed")
        return jsonify({"success": False, "error": "Failed to load companies"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/saas/companies/<int:company_id>/status", methods=["POST"])
@login_required
def saas_company_status_update_api(company_id):
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    raw_active = payload.get("is_active")
    is_active = 1 if str(raw_active).strip().lower() in {"1", "true", "yes", "on"} else 0

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        cursor.execute("SELECT company_id FROM organizations WHERE company_id = %s LIMIT 1", (company_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Company not found"}), 404

        cursor.execute(
            "UPDATE organizations SET is_active = %s WHERE company_id = %s",
            (is_active, company_id),
        )
        conn.commit()
        return jsonify({"success": True, "company_id": company_id, "is_active": is_active})
    except Exception:
        conn.rollback()
        logger.exception("saas_company_status_update_api failed")
        return jsonify({"success": False, "error": "Failed to update company status"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/saas/subscription/plans", methods=["GET"])
@login_required
def saas_subscription_plans_api():
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    plans = []
    for plan_name, values in SAAS_PLAN_DEFINITIONS.items():
        plans.append(
            {
                "plan_name": plan_name,
                "monthly_price": float(parse_amount_decimal(values.get("monthly_price"))),
                "seats_limit": int(values.get("seats_limit") or 0),
                "requests_limit": int(values.get("requests_limit") or 0),
            }
        )

    return jsonify({"success": True, "plans": plans})


@app.route("/api/saas/subscription/assign", methods=["POST"])
@login_required
def saas_assign_subscription_api():
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        company_id = int(payload.get("company_id") or 0)
    except (TypeError, ValueError):
        company_id = 0
    plan_name = _normalize_plan_name(payload.get("plan_name"))
    subscription_status = str(payload.get("subscription_status") or "ACTIVE").strip().upper() or "ACTIVE"
    plan_config = SAAS_PLAN_DEFINITIONS.get(plan_name, SAAS_PLAN_DEFINITIONS["FREE"])

    if company_id <= 0:
        return jsonify({"success": False, "error": "Invalid company_id"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)

        cursor.execute("SELECT company_id FROM organizations WHERE company_id = %s LIMIT 1", (company_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Company not found"}), 404

        cursor.execute(
            """
            INSERT INTO tenant_subscriptions
                (company_id, plan_name, subscription_status, monthly_price, seats_limit, requests_limit)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                plan_name = VALUES(plan_name),
                subscription_status = VALUES(subscription_status),
                monthly_price = VALUES(monthly_price),
                seats_limit = VALUES(seats_limit),
                requests_limit = VALUES(requests_limit),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                company_id,
                plan_name,
                subscription_status,
                str(parse_amount_decimal(plan_config.get("monthly_price"))),
                int(plan_config.get("seats_limit") or 0),
                int(plan_config.get("requests_limit") or 0),
            ),
        )
        conn.commit()

        return jsonify(
            {
                "success": True,
                "company_id": company_id,
                "plan_name": plan_name,
                "subscription_status": subscription_status,
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("saas_assign_subscription_api failed")
        return jsonify({"success": False, "error": "Failed to assign subscription"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/saas/analytics", methods=["GET"])
@login_required
def saas_analytics_api():
    if not is_saas_owner_user():
        return jsonify({"success": False, "error": "Forbidden"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)

        cursor.execute("SELECT COUNT(*) AS count FROM organizations")
        total_companies = int((cursor.fetchone() or {}).get("count") or 0)

        cursor.execute("SELECT COUNT(*) AS count FROM organizations WHERE is_active = 1")
        active_companies = int((cursor.fetchone() or {}).get("count") or 0)

        cursor.execute("SELECT COUNT(*) AS count FROM users")
        total_users = int((cursor.fetchone() or {}).get("count") or 0)

        cursor.execute("SELECT COUNT(*) AS count FROM requests")
        total_requests = int((cursor.fetchone() or {}).get("count") or 0)

        cursor.execute(
            """
            SELECT COALESCE(plan_name, 'FREE') AS plan_name, COUNT(*) AS count
            FROM tenant_subscriptions
            GROUP BY plan_name
            ORDER BY count DESC
            """
        )
        plan_distribution = cursor.fetchall() or []

        cursor.execute(
            """
            SELECT DATE(created_at) AS metric_date, COUNT(*) AS count
            FROM requests
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY DATE(created_at)
            ORDER BY metric_date ASC
            """
        )
        request_trend_30d = cursor.fetchall() or []

        return jsonify(
            {
                "success": True,
                "summary": {
                    "total_companies": total_companies,
                    "active_companies": active_companies,
                    "inactive_companies": max(0, total_companies - active_companies),
                    "total_users": total_users,
                    "total_requests": total_requests,
                },
                "plan_distribution": plan_distribution,
                "request_trend_30d": request_trend_30d,
            }
        )
    except Exception:
        logger.exception("saas_analytics_api failed")
        return jsonify({"success": False, "error": "Failed to load SaaS analytics"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/dean")
def dean_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    if (session.get("role") or "").strip() not in ["Dean", "Reviewer"]:
        return "Forbidden", 403

    position_id = session.get("position_id")
    if not position_id:
        return "Forbidden", 403

    position_id = int(position_id)

    dept = session.get("dept")
    if not dept:
        return "Forbidden", 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return "Forbidden", 403

        cursor.execute("""
            SELECT
            r.request_id,
            r.request_type_id,
            r.filename,
            r.created_at,
            u.email,
            d.dept_name,
            s.status_name,
            rt.type_name,
            r.stage_position_id,
            sp.position_name AS stage_position_name,

            ra.action AS my_action,

            CASE
                WHEN s.status_name = 'PENDING' AND r.stage_position_id = %s THEN 'PENDING'
                WHEN ra.action IS NOT NULL THEN ra.action
                ELSE s.status_name
            END AS status_for_me,

            CASE
                WHEN (s.status_name='PENDING' AND r.stage_position_id=%s) THEN 1
                ELSE 0
            END AS can_act

            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN positions sp ON r.stage_position_id = sp.position_id

            LEFT JOIN (
            SELECT x.request_id, x.action
            FROM request_actions x
            JOIN (
                SELECT request_id, MAX(created_at) AS max_created
                FROM request_actions
                WHERE actor_position_id = %s
                GROUP BY request_id
            ) last
                ON last.request_id = x.request_id AND last.max_created = x.created_at
            WHERE x.actor_position_id = %s
            ) ra ON ra.request_id = r.request_id

            WHERE
            (s.status_name='PENDING' AND r.stage_position_id=%s)
            OR (ra.request_id IS NOT NULL)

            ORDER BY r.created_at ASC
            LIMIT 50
            """, (position_id, position_id, position_id, position_id, position_id))
        r_requests = cursor.fetchall()
        apply_send_back_visibility(cursor, r_requests)

        # Total Approved (unique requests approved by THIS position)
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action='APPROVED'
            """, (position_id,))
        approved_count = cursor.fetchone()["count"]

        # Total Rejected (unique requests rejected by THIS position)
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action='REJECTED'
            """, (position_id,))
        rejected_count = cursor.fetchone()["count"]

        # Approvals Today (unique requests approved today by THIS position)
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s
                AND action='APPROVED'
                AND DATE(created_at) = CURDATE()
            """, (position_id,))
        approvals_today = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.stage_position_id = %s AND s.status_name='PENDING'
            """, (position_id,))
        pending_count = cursor.fetchone()["count"]
        
        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s
                AND action = 'APPROVED'
                AND DATE(created_at) = CURDATE()
            """, (position_id,))
        approvals_today = cursor.fetchone()["count"]

        reminder_overdue_requests = process_position_pending_reminders(
            cursor,
            conn,
            company_id,
            position_id,
        )

        return render_template(
            "dean.html",
            approvals_today=approvals_today,
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            r_requests=r_requests,
            reminder_overdue_requests=reminder_overdue_requests,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/udashboard")
def udashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    role = (session.get("role") or "").strip().lower()
    if role not in {"user", "dev"}:
        return "Forbidden", 403
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return "No company context found", 403

        user_id = get_user_id_for_company(session["email"], company_id)
        if not user_id:
            return "Forbidden", 403

        ensure_request_type_form_schema_table(cursor, conn)
        can_request_budget = can_use_secretary_budget_fields()

        cursor.execute("""
            SELECT
                rt.request_type_id,
                rt.type_name,
                rt.template_filename,
                rt.template_mode,
                EXISTS(
                    SELECT 1
                    FROM request_type_form_schemas fs
                    WHERE fs.request_type_id = rt.request_type_id
                ) AS has_form_schema
            FROM request_types rt
            WHERE rt.company_id = %s
            ORDER BY type_name ASC
        """, (company_id,))
        request_types = cursor.fetchall()

        cursor.execute("SELECT dept_name FROM departments WHERE company_id = %s ORDER BY dept_name ASC", (company_id,))
        departments = [row.get("dept_name") for row in (cursor.fetchall() or []) if row.get("dept_name")]

        # user table list WITH status
        cursor.execute("""
            SELECT
                r.request_id,
                rt.type_name,
                r.wfor,
                r.filename,
                s.status_name,
                r.created_at
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s AND r.company_id = %s
            ORDER BY r.request_id 
        """, (user_id, company_id))
        all_request = cursor.fetchall()

        # CARD COUNTS
        cursor.execute("""
            SELECT
                SUM(CASE WHEN s.status_name = 'PENDING' THEN 1 ELSE 0 END) AS pending_count,
                SUM(CASE WHEN s.status_name = 'APPROVED' THEN 1 ELSE 0 END) AS approved_count,
                SUM(CASE WHEN s.status_name = 'REJECTED' THEN 1 ELSE 0 END) AS rejected_count,
                SUM(CASE WHEN s.status_name = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s AND r.company_id = %s
        """, (user_id, company_id))
        counts = cursor.fetchone() or {}

        user_role = (session.get("role") or "").strip()
        return render_template(
            "user.html", message="Log in Successful",
            request_types=request_types,
            departments=departments,
            can_request_budget=can_request_budget,
            all_request=all_request,
            pending_count=counts.get("pending_count", 0) or 0,
            approved_count=counts.get("approved_count", 0) or 0,
            rejected_count=counts.get("rejected_count", 0) or 0,
            completed_count=counts.get("completed_count", 0) or 0,
            user_role=user_role,
        )

    finally:
        cursor.close()
        conn.close()

@app.route("/api/user_notifications")
def get_user_notifications():
    if "email" not in session:
        return jsonify([]), 401

    user_id = get_user_id(session["email"])
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # get all activity for notification
        query = """
            SELECT r.request_id, r.filename, rt.type_name, s.status_name, 
            r.rejection_message, r.created_at, p.position_name as current_stage
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at ASC
        """
        cursor.execute(query, (user_id,))
        requests = cursor.fetchall()

        notifications = []
        for req in requests:
            # Create a notification
            notif = {
                "id": req["request_id"],
                "title": f"Update on {req['type_name']}",
                "time": req["created_at"].strftime("%b %d, %H:%M"),
                "icon": "info",
            }

            # message and style based on status

            status_lower = req["status_name"].lower()

            if status_lower == "approved":
                notif["message"] = (
                    f"Your request for {req['filename']} has been fully approved."
                )
                notif["type"] = "success"
                notif["icon"] = "check-circle"
            elif status_lower == "rejected":
                notif["message"] = (
                    f"Your request was rejected. Reason: {req['rejection_message']}"
                )
                notif["type"] = "error"
                notif["icon"] = "x-circle"
                
            elif status_lower == "completed":
                notif["message"] = "Your request has been completed successfully."
                notif["type"] = "success"
                notif["icon"] = "check-circle"
            else:
                notif["message"] = (
                    f"New request submitted. Currently being reviewed by: {req['current_stage']}"
                )
                notif["type"] = "pending"
                notif["icon"] = "clock"

            notifications.append(notif)

        broadcast_rows = fetch_system_broadcast_rows(cursor, limit=80)
        for row in reversed(broadcast_rows):
            created_at = row.get("created_at")
            if hasattr(created_at, "strftime"):
                display_time = created_at.strftime("%b %d, %H:%M")
            else:
                display_time = ""

            notifications.append(
                {
                    "id": row.get("id"),
                    "title": row.get("title") or "System Broadcast",
                    "time": display_time,
                    "message": row.get("description") or "",
                    "type": "info",
                    "icon": "bell",
                }
            )

        return jsonify(notifications)
    except Exception as e:
        print(f"Notification Error: {e}")
        return jsonify([])
    finally:
        cursor.close()
        conn.close()


@app.route("/api/bugs/report", methods=["POST"])
@login_required
def api_report_bug():
    reporter_email = (session.get("email") or "").strip().lower()
    if not reporter_email:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    description = str(request.form.get("description") or "").strip()
    if len(description) < 5:
        return jsonify({"success": False, "error": "Please provide a clear bug description."}), 400

    image_blob = None
    image_mime = None
    image_name = None
    image_file = request.files.get("image")

    if image_file and str(image_file.filename or "").strip():
        raw_name = str(image_file.filename or "").strip()
        safe_name = secure_filename(raw_name)
        mime_type = str(image_file.mimetype or "").strip().lower()

        if not allowed_bug_image(safe_name, mime_type):
            return jsonify({"success": False, "error": "Supported image formats: PNG, JPG, JPEG, WEBP, GIF."}), 400

        image_bytes = image_file.read() or b""
        if not image_bytes:
            return jsonify({"success": False, "error": "Uploaded image is empty."}), 400
        if len(image_bytes) > MAX_BUG_IMAGE_BYTES:
            return jsonify({"success": False, "error": "Image is too large. Maximum size is 5MB."}), 413

        image_blob = image_bytes
        image_mime = mime_type or "application/octet-stream"
        image_name = safe_name

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_bug_reports_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        reporter_role = (session.get("role") or "").strip()

        cursor.execute(
            """
            INSERT INTO bug_reports
                (company_id, reporter_email, reporter_role, description, image_blob, image_mime, image_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                int(company_id or 0) if int(company_id or 0) > 0 else None,
                reporter_email,
                reporter_role or None,
                description,
                image_blob,
                image_mime,
                image_name,
            ),
        )
        conn.commit()
        return jsonify({"success": True, "message": "Bug report submitted successfully."})
    except Exception:
        conn.rollback()
        logger.exception("api_report_bug failed")
        return jsonify({"success": False, "error": "Failed to submit bug report."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/bug-reports", methods=["GET"])
@login_required
def bug_reports_dashboard():
    if not is_saas_owner_user():
        return "Forbidden", 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_bug_reports_schema(cursor, conn)

        cursor.execute(
            """
            SELECT
                b.id,
                b.company_id,
                COALESCE(o.company_name, '') AS company_name,
                b.reporter_email,
                COALESCE(b.reporter_role, '') AS reporter_role,
                b.description,
                COALESCE(b.image_mime, '') AS image_mime,
                COALESCE(b.image_name, '') AS image_name,
                b.created_at
            FROM bug_reports b
            LEFT JOIN organizations o ON o.company_id = b.company_id
            ORDER BY b.created_at DESC
            LIMIT 500
            """
        )
        rows = cursor.fetchall() or []

        for row in rows:
            row["has_image"] = bool(row.get("image_name"))

        return render_template(
            "bug_reports.html",
            email=(session.get("email") or "").strip(),
            bug_reports=rows,
            role=(session.get("role") or "").strip(),
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/bug-reports/image/<int:report_id>", methods=["GET"])
@login_required
def bug_report_image(report_id):
    if not is_saas_owner_user():
        return "Forbidden", 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_bug_reports_schema(cursor, conn)
        cursor.execute(
            """
            SELECT image_blob, COALESCE(image_mime, 'application/octet-stream') AS image_mime, COALESCE(image_name, 'bug-image') AS image_name
            FROM bug_reports
            WHERE id = %s
            LIMIT 1
            """,
            (report_id,),
        )
        row = cursor.fetchone() or {}
        image_blob = row.get("image_blob")
        if not image_blob:
            return "Image not found", 404

        return send_file(
            BytesIO(image_blob),
            mimetype=str(row.get("image_mime") or "application/octet-stream"),
            as_attachment=False,
            download_name=str(row.get("image_name") or f"bug-{report_id}-image"),
            conditional=True,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/activity_logs")
def api_activity_logs():

    if "email" not in session:
        return jsonify({"success": False})

    position_id = session.get("position_id")
    try:
        position_id = int(position_id)
    except (TypeError, ValueError):
        position_id = 0

    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT
                CONCAT('A-', ra.action_id) AS id,
                ra.request_id,
                r.request_type_id,
                ra.created_at,
                CONCAT(
                    'Request ',
                    CASE
                    WHEN ra.message LIKE 'Sent back to %' THEN 'SENT BACK'
                    ELSE REPLACE(ra.action, '_', ' ')
                    END
                ) AS title,
                CONCAT(
                    'REQ#', ra.request_id, ' ',
                    LOWER(
                        CASE
                        WHEN ra.message LIKE 'Sent back to %' THEN 'SENT BACK'
                        ELSE REPLACE(ra.action, '_', ' ')
                        END
                    ), ' by ',
                    COALESCE(ra.actor_email,'Unknown'),
                    CASE
                    WHEN ra.actor_position_id IS NULL THEN ''
                    ELSE CONCAT(' (pos_id=', ra.actor_position_id, ')')
                    END,
                    CASE
                    WHEN ra.message IS NULL OR ra.message = '' THEN '.'
                    ELSE CONCAT('. Reason/Note: ', ra.message)
                    END
                ) AS description
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            ORDER BY ra.created_at DESC
            LIMIT 300
        """)
        action_rows = cur.fetchall() or []

        cur.execute("""
            SELECT
                CONCAT('R-', r.request_id) AS id,
                r.request_id,
                r.request_type_id,
                r.created_at,
                'New Request Submitted' AS title,
                CONCAT(
                    'REQ#', r.request_id,
                    ' submitted by ', COALESCE(u.email, 'Unknown'),
                    CASE
                    WHEN rt.type_name IS NULL OR rt.type_name = '' THEN ''
                    ELSE CONCAT(' for ', rt.type_name)
                    END,
                    CASE
                    WHEN p.position_name IS NULL OR p.position_name = '' THEN '.'
                    ELSE CONCAT('. Routed to ', p.position_name, '.')
                    END
                ) AS description
            FROM requests r
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN positions p ON p.position_id = r.stage_position_id
            ORDER BY r.created_at DESC
            LIMIT 300
        """)
        request_rows = cur.fetchall() or []

        visibility_cache = {}

        def can_view_request(req_id, req_type_id):
            if req_id is None or req_type_id is None:
                return False

            key = (int(req_id), int(req_type_id))
            if key in visibility_cache:
                return visibility_cache[key]

            try:
                reviewers, approvers, workflow = get_effective_workflow_positions(
                    cur,
                    request_id=key[0],
                    request_type_id=key[1],
                )
            except Exception:
                reviewers, approvers, workflow = [], [], []

            allowed_positions = set(reviewers + approvers + workflow)
            visible = position_id in allowed_positions
            visibility_cache[key] = visible
            return visible

        rows = []
        for row in action_rows:
            if can_view_request(row.get("request_id"), row.get("request_type_id")):
                rows.append(
                    {
                        "id": row.get("id"),
                        "created_at": row.get("created_at"),
                        "title": row.get("title"),
                        "description": row.get("description"),
                    }
                )

        for row in request_rows:
            if can_view_request(row.get("request_id"), row.get("request_type_id")):
                rows.append(
                    {
                        "id": row.get("id"),
                        "created_at": row.get("created_at"),
                        "title": row.get("title"),
                        "description": row.get("description"),
                    }
                )

        broadcast_rows = fetch_system_broadcast_rows(cur, limit=120)
        for row in broadcast_rows:
            rows.append(
                {
                    "id": row.get("id"),
                    "created_at": row.get("created_at"),
                    "title": row.get("title") or "System Broadcast",
                    "description": row.get("description") or "",
                }
            )

        rows.sort(
            key=lambda item: (
                item.get("created_at").timestamp()
                if hasattr(item.get("created_at"), "timestamp")
                else 0
            ),
            reverse=True,
        )
        rows = rows[:200]

        return jsonify({
            "success": True,
            "data": rows
        })

    finally:
        cur.close()
        conn.close()


@app.route("/api/request/<int:request_id>/rejected-details", methods=["GET"])
@login_required
def get_rejected_request_details(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cur, conn)
        ensure_request_form_submission_table(cur, conn)

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        # fetch basic request data
        cur.execute(
            """
            SELECT r.request_id, r.user_id, r.created_at, r.rejection_message, r.request_type_id, rt.type_name, r.filename, rs.status_name
            FROM requests r
            JOIN request_status rs ON r.status_id = rs.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            WHERE r.request_id = %s AND r.company_id = %s
            LIMIT 1
            """,
            (request_id, company_id),
        )
        row = cur.fetchone() or {}
        if not row:
            return jsonify({"error": "Request not found"}), 404

        # only requester can view rejection details here
        user_id = get_user_id_for_company(session.get("email"), company_id)
        if not user_id or int(row.get("user_id") or 0) != int(user_id):
            return jsonify({"error": "Forbidden"}), 403

        if str(row.get("status_name") or "").strip().upper() != "REJECTED":
            return jsonify({"error": "Request is not rejected"}), 400

        # find latest rejection action
        cur.execute(
            """
            SELECT created_at, actor_email
            FROM request_actions
            WHERE request_id = %s AND action = 'REJECTED'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (request_id,)
        )
        act = cur.fetchone() or {}

        return jsonify(
            {
                "request_id": int(row.get("request_id") or 0),
                "created_at": str(row.get("created_at") or ""),
                "rejection_message": str(row.get("rejection_message") or "").strip(),
                "rejected_at": str(act.get("created_at") or ""),
                "rejected_by": str(act.get("actor_email") or "").strip(),
                "type_name": str(row.get("type_name") or "").strip(),
                "filename": str(row.get("filename") or "").strip(),
            }
        ), 200

    except Exception:
        logger.exception("get_rejected_request_details failed")
        return jsonify({"error": "Failed to load rejected request details."}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/request/<int:request_id>/resubmit", methods=["POST"])
@login_required
def resubmit_rejected_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cur, conn)

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        user_id = get_user_id_for_company(session.get("email"), company_id)
        if not user_id:
            return jsonify({"error": "User not found"}), 404

        # verify request exists and is rejected and belongs to user
        cur.execute(
            "SELECT r.request_id, rs.status_name FROM requests r JOIN request_status rs ON r.status_id = rs.status_id WHERE r.request_id=%s AND r.company_id=%s LIMIT 1",
            (request_id, company_id),
        )
        row = cur.fetchone() or {}
        if not row:
            return jsonify({"error": "Request not found"}), 404

        if str(row.get("status_name") or "").strip().upper() != "REJECTED":
            return jsonify({"error": "Request is not in rejected state"}), 400

        # ensure requester is owner
        cur.execute("SELECT user_id FROM requests WHERE request_id=%s LIMIT 1", (request_id,))
        rrow = cur.fetchone() or {}
        if int(rrow.get("user_id") or 0) != int(user_id):
            return jsonify({"error": "Forbidden"}), 403

        # get DRAFT status id
        cur.execute("SELECT status_id FROM request_status WHERE UPPER(status_name)='DRAFT' LIMIT 1")
        srow = cur.fetchone() or {}
        draft_status_id = srow.get("status_id")
        if draft_status_id is None:
            return jsonify({"error": "Draft status not configured"}), 500

        # convert to draft: clear rejection_message, set status_id to draft, clear stage
        cur.execute(
            "UPDATE requests SET status_id=%s, rejection_message=NULL, stage_position_id=NULL WHERE request_id=%s",
            (draft_status_id, request_id),
        )

        # log action
        cur.execute(
            "INSERT INTO request_actions (request_id, actor_user_id, actor_email, action, message) VALUES (%s, %s, %s, 'RESUBMIT_TO_DRAFT', %s)",
            (
                request_id,
                int(user_id),
                (session.get("email") or "").strip().lower(),
                "Resubmitted by requester (converted to draft)",
            ),
        )

        conn.commit()
        return jsonify({"success": True, "message": "Request converted to draft."}), 200
    except Exception:
        conn.rollback()
        logger.exception("resubmit_rejected_request failed")
        return jsonify({"error": "Failed to convert request to draft."}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/user_dashboard", methods=["GET", "OPTIONS"])
@require_token
def api_user_dashboard():
    if request.method == "OPTIONS":
        return ("", 200)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        company_id = int(getattr(request, "user_company_id", 0) or 0)
        if company_id <= 0:
            cursor.execute(
                "SELECT COALESCE(company_id, 0) AS company_id FROM users WHERE email = %s LIMIT 1",
                (request.user_email,),
            )
            row = cursor.fetchone() or {}
            company_id = int(row.get("company_id") or 0)

        if company_id <= 0:
            return jsonify({"error": "Unauthorized"}), 401

        user_id = get_user_id_for_company(request.user_email, company_id)
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401

        cursor.execute("""
            SELECT request_type_id, type_name, template_filename, template_mode
            FROM request_types
            WHERE company_id = %s
            ORDER BY type_name ASC
        """, (company_id,))
        request_types = cursor.fetchall()

        cursor.execute("""
            SELECT
                r.request_id,
                r.request_type_id,
                rt.type_name,
                r.filename,
                r.wfor,
                s.status_name,
                r.rejection_message,
                COALESCE(p.position_name, '-') AS current_stage,
                r.created_at
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s AND r.company_id = %s
            ORDER BY r.request_id ASC
        """, (user_id, company_id))
        all_request = cursor.fetchall()

        for r in all_request:
            status_name = (r.get("status_name") or "").strip().upper()
            current_stage = (r.get("current_stage") or "").strip()

            if status_name == "PENDING" and (
                not current_stage
                or current_stage == "-"
                or current_stage.lower() in ("none", "null")
            ):
                req_id = r.get("request_id")
                req_type_id = r.get("request_type_id")

                try:
                    req_id = int(req_id)
                    req_type_id = int(req_type_id)
                except (TypeError, ValueError):
                    req_id = None
                    req_type_id = None

                if req_id and req_type_id:
                    _, _, workflow = get_effective_workflow_positions(
                        cursor,
                        request_id=req_id,
                        request_type_id=req_type_id,
                    )
                    if workflow:
                        cursor.execute(
                            "SELECT position_name FROM positions WHERE position_id = %s LIMIT 1",
                            (workflow[0],),
                        )
                        stage_row = cursor.fetchone() or {}
                        stage_name = (stage_row.get("position_name") or "").strip()
                        if stage_name:
                            r["current_stage"] = stage_name

                # Final fallback for unresolved pending stage.
                if not (r.get("current_stage") or "").strip() or str(
                    r.get("current_stage")
                ).strip() in ("-", "none", "null", "None", "NULL"):
                    r["current_stage"] = "Pending Review"

            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()

        cursor.execute("""
            SELECT
                SUM(CASE WHEN s.status_name = 'PENDING' THEN 1 ELSE 0 END) AS pending_count,
                SUM(CASE WHEN s.status_name = 'APPROVED' THEN 1 ELSE 0 END) AS approved_count,
                SUM(CASE WHEN s.status_name = 'REJECTED' THEN 1 ELSE 0 END) AS rejected_count,
                SUM(CASE WHEN s.status_name = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s AND r.company_id = %s
        """, (user_id, company_id))
        counts = cursor.fetchone() or {}

        return jsonify({
            "request_types": request_types,
            "all_request": all_request,
            "counts": counts,
        })
    finally:
        cursor.close()
        conn.close()

@app.route("/gsd_dashboard")
def gsdh_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    dept = (session.get("dept") or "").strip()
    role = (session.get("role") or "").strip()
    if not (dept == "GSD" and role in ["Admin", "AssistantAdmin"]):
        return "Forbidden", 403

    position_id = session.get("position_id")
    if not position_id:
        return redirect("/")

    position_id = int(position_id)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return "Forbidden", 403

        # Inventory
        cursor.execute("""
            SELECT product_id, product_name, quantity
            FROM inventory
            ORDER BY product_name
        """)
        inventory_items = cursor.fetchall()

        # Requests assigned to THIS position (PENDING)
        cursor.execute("""
            SELECT 
                r.request_id,
                r.request_type_id,
                r.stage_position_id,
                r.filename,
                r.created_at,
                u.email,
                d.dept_name,
                s.status_name,
                rt.type_name
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            WHERE r.stage_position_id = %s
            ORDER BY r.created_at ASC
            LIMIT 50
            """, (position_id,))
        recent_requests = cursor.fetchall()
        apply_send_back_visibility(cursor, recent_requests)

                # Pending count (assigned to THIS position)
        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'PENDING'
            AND r.stage_position_id = %s
        """, (position_id,))
        pending_count = cursor.fetchone()["count"]

        # Total approved by THIS position (actions)
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'APPROVED'
        """, (position_id,))
        approved_count = cursor.fetchone()["count"]

        # Total rejected by THIS position (actions)
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'REJECTED'
        """, (position_id,))
        rejected_count = cursor.fetchone()["count"]

        # Approvals today by THIS position
        cursor.execute("""
            SELECT COUNT(DISTINCT request_id) AS count
            FROM request_actions
            WHERE actor_position_id = %s
            AND action = 'APPROVED'
            AND DATE(created_at) = CURDATE()
        """, (position_id,))
        approvals_today = cursor.fetchone()["count"]

        # Completed count (requests completed that were handled by THIS position)
        cursor.execute("""
            SELECT COUNT(DISTINCT r.request_id) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            JOIN request_actions ra ON ra.request_id = r.request_id
            WHERE s.status_name = 'COMPLETED'
            AND ra.actor_position_id = %s
        """, (position_id,))
        completed_count = cursor.fetchone()["count"]

        reminder_overdue_requests = process_position_pending_reminders(
            cursor,
            conn,
            company_id,
            position_id,
        )

        return render_template(
            "gsddashboard.html",
            inventory_items=inventory_items,
            recent_requests=recent_requests,
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            approvals_today=approvals_today,
            completed_count=completed_count,
            reminder_overdue_requests=reminder_overdue_requests,
        )
    finally:
        cursor.close()
        conn.close()

@app.post("/api/inventory")
@login_required
def inv_add():
    dept = (session.get("dept") or "").strip()
    role = (session.get("role") or "").strip()
    if not (dept == "GSD" and role in ["Admin", "AssistantAdmin"]):
        return "Forbidden", 403
    data = request.get_json() or {}
    name = " ".join((data.get("product_name") or "").split()).strip()
    qty = data.get("quantity")

    if not name:
        return jsonify(error="Product name is required.")

    try:
        qty = int(qty)
        if qty < 0:
            return jsonify(error="Quantity must be 0 or above.")
    except:
        return jsonify(error="Quantity must be a number.")

    conn = None
    cur = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO inventory (product_name, quantity) VALUES (%s, %s)",
            (name, qty),
        )
        conn.commit()
        return jsonify(message="Added")

    except mysql.connector.Error as e:
        if getattr(e, "errno", None) == 1062:
            return jsonify(error="Product already in inventory.")
        return jsonify(error=str(e))

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.put("/api/inventory/<int:pid>")
@login_required
def inv_edit(pid):
    dept = (session.get("dept") or "").strip()
    role = (session.get("role") or "").strip()
    if not (dept == "GSD" and role in ["Admin", "AssistantAdmin"]):
        return "Forbidden", 403
    data = request.get_json() or {}
    name = (data.get("product_name") or "").strip()
    qty = data.get("quantity")

    if not name:
        return jsonify(error="Product name is required.")
    try:
        qty = int(qty)
        if qty < 0:
            raise ValueError()
    except:
        return jsonify(error="Quantity must be a non-negative integer.")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE inventory SET product_name=%s, quantity=%s WHERE product_id=%s",
        (name, qty, pid),
    )
    conn.commit()
    return jsonify(message="Updated")


@app.delete("/api/inventory/<int:pid>")
@login_required
def inv_delete(pid):
    dept = (session.get("dept") or "").strip()
    role = (session.get("role") or "").strip()
    if not (dept == "GSD" and role in ["Admin", "AssistantAdmin"]):
        return "Forbidden", 403
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM inventory WHERE product_id=%s", (pid,))
    conn.commit()
    return jsonify(message="Deleted")


# Admin Dashboard

@app.route("/admin")
def admin_dashboard():
    if "email" not in session:
        return redirect("/login")

    position_id = session.get("position_id")
    role = (session.get("role") or "").strip()
    if not (role in ["Admin", "AssistantAdmin", "SuperAdmin", "SBO"]):
        return "Forbidden", 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return "No company context found", 403

        ensure_finance_amount_editor_schema(cursor, conn)
        can_edit_amount_team = is_finance_amount_editor(
            cursor,
            company_id,
            int(session.get("user_id") or 0),
        )

        can_manage_request_types_access = can_manage_request_types(cursor, role=role)
        can_view_reports_access = can_view_reports(cursor, role=role)
        can_manage_budget_access = can_manage_budget(cursor, role=role)

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'PENDING'
            AND r.stage_position_id = %s
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        pending_count = cursor.fetchone()["count"]

        # Per-position totals (who actually clicked approve/reject)
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            WHERE ra.actor_position_id = %s AND ra.action = 'APPROVED'
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        approved_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            WHERE ra.actor_position_id = %s AND ra.action = 'REJECTED'
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        rejected_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            WHERE ra.actor_position_id = %s
            AND ra.action = 'APPROVED'
            AND DATE(ra.created_at) = CURDATE()
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        approvals_today = cursor.fetchone()["count"]
        
        cursor.execute(
            """
            SELECT COUNT(*) AS count 
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'IN PROGRESS'
            AND r.company_id = %s
            """,
            (company_id,),
        )
        in_progress = cursor.fetchone()["count"]
        
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'COMPLETED'
            AND r.company_id = %s
            """,
            (company_id,),
        )
        completed = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM users WHERE company_id = %s", (company_id,))
        total_users = cursor.fetchone()["count"]

        position_id = int(session.get("position_id") or 0)

        # Get position name from session
        position_name = (session.get("position") or "").strip().lower()
        is_purchasing = (
            "purchasing" in position_name
        )  

        # Recent requests list
        # Purchasing: show ALL requests
        # other only show thier assign
        recent_sql = """
            SELECT
            r.request_id,
            r.request_type_id,
            r.wfor,
            r.filename,
            r.created_at,
            r.amount,
            u.email,
            d.dept_name,
            s.status_name,
            rt.type_name,
            r.stage_position_id,
            sp.position_name AS stage_position_name,

            ra.action AS my_action,

            CASE
                WHEN %(is_purchasing)s = 1 THEN s.status_name
                WHEN s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s THEN 'PENDING'
                WHEN ra.action IS NOT NULL THEN ra.action
                ELSE s.status_name
            END AS status_for_me,

            CASE
                WHEN (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s) THEN 1
                ELSE 0
            END AS can_act

            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN positions sp ON r.stage_position_id = sp.position_id

            LEFT JOIN (
            SELECT x.request_id, x.action
            FROM request_actions x
            JOIN (
                SELECT request_id, MAX(created_at) AS max_created
                FROM request_actions
                WHERE actor_position_id = %(pos_id)s
                GROUP BY request_id
            ) last ON last.request_id = x.request_id AND last.max_created = x.created_at
            WHERE x.actor_position_id = %(pos_id)s
            ) ra ON ra.request_id = r.request_id

            WHERE
            r.company_id = %(company_id)s
            AND (
                (%(is_purchasing)s = 1)
                OR (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s)
                OR (ra.request_id IS NOT NULL)
            )

            ORDER BY r.created_at ASC
            LIMIT 50
            """

        cursor.execute(
            recent_sql,
            {
                "pos_id": int(position_id or 0),
                "is_purchasing": 1 if is_purchasing else 0,
                "company_id": company_id,
            },
        )
        recent_requests = cursor.fetchall()
        apply_send_back_visibility(cursor, recent_requests)
        reminder_overdue_requests = process_position_pending_reminders(
            cursor,
            conn,
            company_id,
            position_id,
        )


        # Positions dropdown
        cursor.execute(
            "SELECT position_id, position_name FROM positions WHERE company_id = %s ORDER BY position_name ASC",
            (company_id,),
        )
        positions = cursor.fetchall()

        # Existing request types for management table
        cursor.execute("""
            SELECT 
                rt.request_type_id,
                rt.type_name,
                rt.template_filename,
                GROUP_CONCAT(DISTINCT pr.position_name ORDER BY rtr.order_no SEPARATOR ', ') AS reviewer_names,
                GROUP_CONCAT(DISTINCT pa.position_name ORDER BY rta.order_no SEPARATOR ', ') AS approver_names,
                GROUP_CONCAT(DISTINCT pr.position_id ORDER BY rtr.order_no SEPARATOR ',') AS reviewer_ids,
                GROUP_CONCAT(DISTINCT pa.position_id ORDER BY rta.order_no SEPARATOR ',') AS approver_ids
            FROM request_types rt
            LEFT JOIN request_type_reviewers rtr ON rt.request_type_id = rtr.request_type_id
            LEFT JOIN positions pr ON rtr.position_id = pr.position_id
            LEFT JOIN request_type_approvers rta ON rt.request_type_id = rta.request_type_id
            LEFT JOIN positions pa ON rta.position_id = pa.position_id
            WHERE rt.company_id = %s
            GROUP BY rt.request_type_id, rt.type_name, rt.template_filename
            ORDER BY rt.type_name ASC
        """, (company_id,))
        existing_types = cursor.fetchall()

        return render_template(
            "admin.html",
            approvals_today=approvals_today,
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            completed=completed,
            total_users=total_users,
            in_progress=in_progress,
            recent_requests=recent_requests,
            positions=positions,
            existing_types=existing_types,
            can_manage_request_types=can_manage_request_types_access,
            can_view_reports=can_view_reports_access,
            can_manage_budget=can_manage_budget_access,
            reminder_overdue_requests=reminder_overdue_requests,
            can_edit_amount_team=can_edit_amount_team,
        )

    except Exception as e:
        print(f"Error: {e}")
        return f"Database Error: {e}"
    finally:
        cursor.close()
        conn.close()


@app.route("/api/admin/live")
def api_admin_live():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = session.get("role")
    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        return jsonify({"success": False, "error": "Forbidden"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        position_id = int(session.get("position_id") or 0)
        position_name = (session.get("position") or "").strip().lower()
        is_purchasing = 1 if "purchasing" in position_name else 0

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'PENDING'
            AND r.stage_position_id = %s
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        pending_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            WHERE ra.actor_position_id = %s AND ra.action = 'APPROVED'
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        approved_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions ra
            JOIN requests r ON r.request_id = ra.request_id
            WHERE ra.actor_position_id = %s AND ra.action = 'REJECTED'
            AND r.company_id = %s
            """,
            (position_id, company_id),
        )
        rejected_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'IN PROGRESS'
            AND r.company_id = %s
            """,
            (company_id,),
        )
        in_progress = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'COMPLETED'
            AND r.company_id = %s
            """,
            (company_id,),
        )
        completed = cursor.fetchone()["count"]

        recent_sql = """
            SELECT
            r.request_id,
            r.request_type_id,
            COALESCE(r.wfor, '') AS wfor,
            r.filename,
            r.created_at,
            r.amount,
            u.email,
            d.dept_name,
            s.status_name,
            rt.type_name,
            r.stage_position_id,
            sp.position_name AS stage_position_name,

            ra.action AS my_action,

            CASE
                WHEN %(is_purchasing)s = 1 THEN s.status_name
                WHEN s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s THEN 'PENDING'
                WHEN ra.action IS NOT NULL THEN ra.action
                ELSE s.status_name
            END AS status_for_me,

            CASE
                WHEN (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s) THEN 1
                ELSE 0
            END AS can_act

            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN positions sp ON r.stage_position_id = sp.position_id

            LEFT JOIN (
            SELECT x.request_id, x.action
            FROM request_actions x
            JOIN (
                SELECT request_id, MAX(created_at) AS max_created
                FROM request_actions
                WHERE actor_position_id = %(pos_id)s
                GROUP BY request_id
            ) last ON last.request_id = x.request_id AND last.max_created = x.created_at
            WHERE x.actor_position_id = %(pos_id)s
            ) ra ON ra.request_id = r.request_id

            WHERE
            r.company_id = %(company_id)s
            AND (
                (%(is_purchasing)s = 1)
                OR (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s)
                OR (ra.request_id IS NOT NULL)
            )

            ORDER BY r.created_at ASC
            LIMIT 50
            """

        cursor.execute(
            recent_sql,
            {
                "pos_id": position_id,
                "is_purchasing": is_purchasing,
                "company_id": company_id,
            },
        )
        recent_requests = cursor.fetchall() or []
        apply_send_back_visibility(cursor, recent_requests)

        for row in recent_requests:
            created_at = row.get("created_at")
            if hasattr(created_at, "isoformat"):
                row["created_at"] = created_at.isoformat()

        return jsonify(
            {
                "success": True,
                "counts": {
                    "pending_count": pending_count,
                    "approved_count": approved_count,
                    "rejected_count": rejected_count,
                    "in_progress": in_progress,
                    "completed": completed,
                },
                "recent_requests": recent_requests,
                "is_purchasing": bool(is_purchasing),
            }
        )
    except Exception:
        logger.exception("api_admin_live failed")
        return jsonify({"success": False, "error": "Failed to load live data"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/admin/pin/status", methods=["GET"])
def admin_pin_status():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": True, "eligible": False}), 200

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        row = get_admin_pin_state(cursor, session["email"])
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404

        return jsonify(
            {
                "success": True,
                "eligible": True,
                **_build_admin_pin_state_payload(row),
            }
        )
    except Exception:
        logger.exception("admin_pin_status failed")
        return jsonify({"success": False, "error": "Failed to load PIN status"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/admin/pin/setup", methods=["POST"])
def admin_pin_setup():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    pin = str(data.get("pin") or "").strip()
    confirm_pin = str(data.get("confirm_pin") or "").strip()

    if email != (session.get("email") or "").strip().lower():
        return jsonify({"success": False, "error": "Email does not match your account."}), 403

    if not is_valid_admin_pin(pin):
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    if pin != confirm_pin:
        return jsonify({"success": False, "error": "PIN confirmation does not match."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        row = get_admin_pin_state(cursor, email)
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404

        if row.get("admin_pin_hash"):
            return jsonify({"success": False, "error": "PIN already exists. Use Change PIN in Settings."}), 400

        pin_hash = generate_password_hash(pin, method="pbkdf2:sha256", salt_length=16)
        cursor.execute(
            """
            UPDATE users
            SET admin_pin_hash=%s,
                admin_pin_failed_attempts=0,
                admin_pin_disabled=0
            WHERE user_id=%s
            """,
            (pin_hash, row["user_id"]),
        )
        conn.commit()

        clear_admin_pin_otp_session_flags()
        return jsonify({"success": True, "message": "PIN created successfully."})
    except Exception:
        conn.rollback()
        logger.exception("admin_pin_setup failed")
        return jsonify({"success": False, "error": "Failed to create PIN"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/admin/pin/request-otp", methods=["POST"])
@limiter.limit("5 per minute")
def admin_pin_request_otp():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    if email != (session.get("email") or "").strip().lower():
        return jsonify({"success": False, "error": "Email does not match your account."}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        row = get_admin_pin_state(cursor, email)
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404
        if not row.get("admin_pin_hash"):
            return jsonify({"success": False, "error": "No PIN found. Please create a PIN first."}), 400

        ok, msg = send_admin_pin_otp(cursor, conn, email)
        if not ok:
            status = 429 if "Please wait" in msg else 500
            return jsonify({"success": False, "error": msg}), status

        return jsonify({"success": True, "message": msg})
    except Exception:
        logger.exception("admin_pin_request_otp failed")
        return jsonify({"success": False, "error": "Failed to send OTP"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/admin/pin/verify-otp", methods=["POST"])
@limiter.limit("10 per minute")
def admin_pin_verify_otp():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    otp = str(data.get("otp") or "").strip()

    if email != (session.get("email") or "").strip().lower():
        return jsonify({"success": False, "error": "Email does not match your account."}), 403

    pending_email = (session.get("admin_pin_otp_pending_email") or "").strip().lower()
    pending_at = int(session.get("admin_pin_otp_pending_at") or 0)
    now_ts = int(time.time())

    if pending_email != email or pending_at <= 0:
        return jsonify({"success": False, "error": "Please request OTP first."}), 400

    if (now_ts - pending_at) > ADMIN_PIN_OTP_MAX_AGE_SECONDS:
        clear_admin_pin_otp_session_flags()
        return jsonify({"success": False, "error": "OTP session expired. Request a new OTP."}), 400

    message, ok = verify_signup_otp(email, otp, consume=True)
    if not ok:
        return jsonify({"success": False, "error": message or "Invalid OTP"}), 400

    session["admin_pin_otp_verified_email"] = email
    session["admin_pin_otp_verified_at"] = now_ts
    return jsonify({"success": True, "message": "OTP verified. You can now change your PIN."})


@app.route("/api/admin/pin/change", methods=["POST"])
def admin_pin_change():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    new_pin = str(data.get("new_pin") or "").strip()
    confirm_pin = str(data.get("confirm_pin") or "").strip()

    if email != (session.get("email") or "").strip().lower():
        return jsonify({"success": False, "error": "Email does not match your account."}), 403

    if not is_admin_pin_otp_verified(email):
        return jsonify({"success": False, "error": "Please verify OTP first."}), 400

    if not is_valid_admin_pin(new_pin):
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    if new_pin != confirm_pin:
        return jsonify({"success": False, "error": "PIN confirmation does not match."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        row = get_admin_pin_state(cursor, email)
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404

        pin_hash = generate_password_hash(new_pin, method="pbkdf2:sha256", salt_length=16)
        cursor.execute(
            """
            UPDATE users
            SET admin_pin_hash=%s,
                admin_pin_failed_attempts=0,
                admin_pin_disabled=0
            WHERE user_id=%s
            """,
            (pin_hash, row["user_id"]),
        )
        conn.commit()

        clear_admin_pin_otp_session_flags()
        return jsonify({"success": True, "message": "PIN updated successfully."})
    except Exception:
        conn.rollback()
        logger.exception("admin_pin_change failed")
        return jsonify({"success": False, "error": "Failed to change PIN"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/amount", methods=["POST"])
def admin_update_request_amount(request_id):
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    if not can_use_admin_pin(role):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    amount_raw = str(data.get("amount") or "").strip()
    pin = str(data.get("pin") or "").strip()

    if not amount_raw:
        return jsonify({"success": False, "error": "Amount is required."}), 400

    try:
        amount = Decimal(amount_raw)
    except (TypeError, ValueError, InvalidOperation):
        return jsonify({"success": False, "error": "Invalid amount value."}), 400

    if amount < 0:
        return jsonify({"success": False, "error": "Amount cannot be negative."}), 400

    if not is_valid_admin_pin(pin):
        return jsonify({"success": False, "error": "PIN must be exactly 4 digits."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_admin_pin_schema(cursor, conn)
        ensure_tenant_schema(cursor, conn)
        ensure_finance_amount_editor_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        actor_user_id = int(session.get("user_id") or 0)
        if company_id <= 0 or actor_user_id <= 0:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        if not is_finance_amount_editor(cursor, company_id, actor_user_id):
            return jsonify(
                {
                    "success": False,
                    "error": "Only Finance Amount Editor team can edit amount.",
                }
            ), 403

        pin_row = get_admin_pin_state(cursor, session["email"])
        if not pin_row:
            return jsonify({"success": False, "error": "User not found"}), 404

        pin_hash = pin_row.get("admin_pin_hash")
        failed_attempts = int(pin_row.get("admin_pin_failed_attempts") or 0)
        is_disabled = bool(int(pin_row.get("admin_pin_disabled") or 0))

        if not pin_hash:
            return jsonify({
                "success": False,
                "code": "PIN_NOT_SET",
                "error": "PIN is not set. Please create your 4-digit PIN first.",
            }), 400

        if is_disabled:
            return jsonify({
                "success": False,
                "code": "PIN_DISABLED",
                "error": "PIN is disabled. Reset your PIN in Settings to enable amount editing again.",
                "failed_attempts": failed_attempts,
                "remaining_attempts": 0,
            }), 423

        if not check_password_hash(pin_hash, pin):
            new_failed_attempts = min(ADMIN_PIN_MAX_FAILED_ATTEMPTS, failed_attempts + 1)
            disabled_now = 1 if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS else 0
            cursor.execute(
                """
                UPDATE users
                SET admin_pin_failed_attempts=%s,
                    admin_pin_disabled=%s
                WHERE user_id=%s
                """,
                (new_failed_attempts, disabled_now, pin_row["user_id"]),
            )
            conn.commit()

            remaining = max(0, ADMIN_PIN_MAX_FAILED_ATTEMPTS - new_failed_attempts)
            if new_failed_attempts >= ADMIN_PIN_MAX_FAILED_ATTEMPTS:
                return jsonify(
                    {
                        "success": False,
                        "code": "PIN_DISABLED",
                        "error": "PIN has been disabled after 5 failed attempts. Reset your PIN in Settings to enable amount editing again.",
                        "failed_attempts": new_failed_attempts,
                        "remaining_attempts": 0,
                    }
                ), 423

            if new_failed_attempts == ADMIN_PIN_WARNING_ATTEMPTS:
                return jsonify(
                    {
                        "success": False,
                        "code": "PIN_WARNING",
                        "error": "You entered PIN 3 times in a row with incorrect PIN. You have 2 more left and amount edit will be disabled. If you forgot your PIN, you can reset it in Settings.",
                        "failed_attempts": new_failed_attempts,
                        "remaining_attempts": remaining,
                    }
                ), 403

            return jsonify(
                {
                    "success": False,
                    "code": "PIN_INVALID",
                    "error": f"Incorrect PIN. You have {remaining} attempt(s) remaining.",
                    "failed_attempts": new_failed_attempts,
                    "remaining_attempts": remaining,
                }
            ), 403

        cursor.execute(
            """
            SELECT r.request_id, s.status_name
            FROM requests r
            JOIN request_status s ON s.status_id = r.status_id
            WHERE r.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        request_row = cursor.fetchone()
        if not request_row:
            return jsonify({"success": False, "error": "Request not found"}), 404

        status_name = str(request_row.get("status_name") or "").strip().upper()
        if status_name != "PENDING":
            return jsonify(
                {
                    "success": False,
                    "code": "NOT_PENDING",
                    "error": "Only pending request amounts can be edited.",
                }
            ), 400

        cursor.execute(
            """
            UPDATE users
            SET admin_pin_failed_attempts=0,
                admin_pin_disabled=0
            WHERE user_id=%s
            """,
            (pin_row["user_id"],),
        )
        cursor.execute(
            """
            UPDATE requests
            SET amount=%s
            WHERE request_id=%s
            """,
            (str(amount), request_id),
        )

        conn.commit()
        return jsonify(
            {
                "success": True,
                "message": "Amount updated successfully.",
                "request_id": request_id,
                "amount": amount,
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("admin_update_request_amount failed")
        return jsonify({"success": False, "error": "Failed to update amount"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/workflow", methods=["GET"])
def get_request_workflow(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position_name = (session.get("position") or "").strip().lower()
    if role not in ["AssistantAdmin", "Admin", "SuperAdmin"] and "purchasing" not in position_name:
        return jsonify({"error": "Forbidden"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        # get request basics
        cursor.execute(
            """
            SELECT request_id, request_type_id, stage_position_id
            FROM requests
            WHERE request_id = %s AND company_id = %s
        """,
            (request_id, company_id),
        )
        req = cursor.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        rev, app, _workflow = get_effective_workflow_positions(
            cursor,
            request_id=request_id,
            request_type_id=req["request_type_id"],
        )

        return jsonify(
            {
                "request_id": request_id,
                "stage_position_id": req["stage_position_id"],
                "reviewer_ids": rev,
                "approver_ids": app,
            }
        )

    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/workflow", methods=["POST"])
def update_request_workflow(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = session.get("role")
    if role not in ["AssistantAdmin", "Admin", "SuperAdmin"]:
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json() or {}
    reviewer_ids = data.get("reviewer_position_ids") or []
    approver_ids = data.get("approver_position_ids") or []
    stage_position_id = data.get("stage_position_id", None)

    if not isinstance(reviewer_ids, list) or not isinstance(approver_ids, list):
        return jsonify({"error": "Invalid payload"}), 400

    if len(approver_ids) == 0:
        return jsonify({"error": "At least one approver is required"}), 400

    # normalize ints
    try:
        reviewer_ids = [int(x) for x in reviewer_ids]
        approver_ids = [int(x) for x in approver_ids]
        stage_position_id = (
            int(stage_position_id) if stage_position_id is not None else None
        )
    except:
        return jsonify({"error": "IDs must be integers"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        # ensure request exists
        cursor.execute(
            "SELECT request_id FROM requests WHERE request_id=%s AND company_id=%s",
            (request_id, company_id),
        )
        if not cursor.fetchone():
            return jsonify({"error": "Request not found"}), 404

        all_position_ids = reviewer_ids + approver_ids
        if stage_position_id is not None:
            all_position_ids.append(stage_position_id)

        if all_position_ids:
            cursor.execute(
                "SELECT position_id FROM positions WHERE company_id=%s",
                (company_id,),
            )
            valid_position_ids = {int(row["position_id"]) for row in (cursor.fetchall() or [])}
            for pid in all_position_ids:
                if int(pid) not in valid_position_ids:
                    return jsonify({"error": "One or more workflow positions do not belong to your company"}), 400

        # overwrite per-request reviewer override
        cursor.execute(
            "DELETE FROM request_workflow_reviewers WHERE request_id=%s", (request_id,)
        )
        for i, pid in enumerate(reviewer_ids, start=1):
            cursor.execute(
                """
                INSERT INTO request_workflow_reviewers (request_id, position_id, order_no)
                VALUES (%s, %s, %s)
            """,
                (request_id, pid, i),
            )

        # overwrite per-request approver override
        cursor.execute(
            "DELETE FROM request_workflow_approvers WHERE request_id=%s", (request_id,)
        )
        for i, pid in enumerate(approver_ids, start=1):
            cursor.execute(
                """
                INSERT INTO request_workflow_approvers (request_id, position_id, order_no)
                VALUES (%s, %s, %s)
            """,
                (request_id, pid, i),
            )

        # optionally set current stage
        cursor.execute(
            """
            UPDATE requests
            SET stage_position_id = %s
            WHERE request_id = %s AND company_id = %s
        """,
            (stage_position_id, request_id, company_id),
        )

        conn.commit()
        coo_result = queue_coo_if_stage_is_coo(
            cursor,
            conn,
            request_id,
            stage_position_id,
            requested_by_email=(session.get("email") or ""),
        )
        return jsonify(
            {
                "success": True,
                "message": "Workflow updated successfully.",
                "coo": coo_result,
            }
        )

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route("/add_request_type", methods=["POST"])
def add_request_type():
    if "email" not in session:
        return redirect("/login")

    role = session.get("role")
    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        return redirect("/")

    type_name = (request.form.get("type_name") or "").strip()
    reviewer_ids = request.form.getlist("reviewer_position_ids[]")
    approver_ids = request.form.getlist("approver_position_ids[]")
    total_formula = (request.form.get("total_formula") or "").strip()
    map_fields_now = (request.form.get("map_fields_now") or "").strip().lower() in {"1", "true", "on", "yes"}

    # Template mode 
    template_mode = (request.form.get("template_mode") or "FILLABLE").upper()
    if template_mode not in ("FILLABLE", "DOWNLOAD"):
        template_mode = "FILLABLE"

    normalized_form_schema = None

    if not type_name:
        flash("Request type name is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    is_ahm_request_type = bool(re.search(r"\bahm\b", type_name, flags=re.IGNORECASE))

    if is_ahm_request_type and template_mode != "FILLABLE":
        flash("AHM request type must use Fillable Form mode.", "danger")
        return redirect(url_for("admin_dashboard"))

    # require at least one approver
    if not approver_ids or all((not x) for x in approver_ids):
        flash("At least one approver is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    # TEMPLATE FILE (PDF)
    tpl = request.files.get("template_file")
    template_filename = None
    template_blob = None

    if tpl and tpl.filename:
        if not allowed_file(tpl.filename):
            flash("Template must be PDF only.", "danger")
            return redirect(url_for("admin_dashboard"))

        template_filename = secure_filename(tpl.filename)
        template_blob = tpl.read()

        # Optional: basic PDF signature check
        if template_blob and not template_blob.startswith(b"%PDF-"):
            flash("Invalid PDF template file.", "danger")
            return redirect(url_for("admin_dashboard"))

    # If DOWNLOAD mode
    if template_mode == "DOWNLOAD" and not template_blob:
        flash("Download mode requires uploading a PDF template.", "danger")
        return redirect(url_for("admin_dashboard"))

    if template_mode == "FILLABLE" and not template_blob:
        flash("Fillable mode requires uploading the exact PDF template form.", "danger")
        return redirect(url_for("admin_dashboard"))

    if template_mode == "FILLABLE":
        try:
            normalized_form_schema = build_fillable_schema_from_pdf_template(
                template_blob,
                total_formula=total_formula,
            )
        except ValueError as exc:
            err_text = str(exc)
            fallback_markers = (
                "does not contain detectable fillable fields",
                "has no supported user-input fields",
                "appears to use XFA forms",
            )

            if any(marker in err_text for marker in fallback_markers):
                normalized_form_schema = get_default_request_form_schema()
                if total_formula:
                    normalized_form_schema["total_formula"] = _sanitize_total_formula(total_formula)

                flash(
                    "Uploaded PDF is not a standard fillable AcroForm. "
                    "Request type was created using a generic fallback form schema.",
                    "warning",
                )
            else:
                flash(err_text, "danger")
                return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if not can_manage_request_types(cursor):
            flash("You do not have permission to manage request types.", "danger")
            return redirect(url_for("admin_dashboard"))

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("No company context found.", "danger")
            return redirect(url_for("admin_dashboard"))

        normalized_reviewer_ids = []
        normalized_approver_ids = []
        try:
            normalized_reviewer_ids = [int(pos_id) for pos_id in reviewer_ids if str(pos_id).strip()]
            normalized_approver_ids = [int(pos_id) for pos_id in approver_ids if str(pos_id).strip()]
        except (TypeError, ValueError):
            flash("Invalid reviewer/approver selection.", "danger")
            return redirect(url_for("admin_dashboard"))

        selected_position_ids = normalized_reviewer_ids + normalized_approver_ids
        if selected_position_ids:
            cursor.execute(
                "SELECT position_id FROM positions WHERE company_id=%s",
                (company_id,),
            )
            valid_ids = {int(row["position_id"]) for row in (cursor.fetchall() or [])}
            for pos_id in selected_position_ids:
                if pos_id not in valid_ids:
                    flash("Selected reviewers/approvers must belong to your company.", "danger")
                    return redirect(url_for("admin_dashboard"))

        ensure_request_type_form_schema_table(cursor, conn)

        # Insert request type WITH template + mode
        cursor.execute(
            """
            INSERT INTO request_types (type_name, template_filename, template_file, template_mode, company_id)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (type_name, template_filename, template_blob, template_mode, company_id),
        )
        new_type_id = cursor.lastrowid

        if template_mode == "FILLABLE" and normalized_form_schema is not None:
            cursor.execute(
                """
                INSERT INTO request_type_form_schemas (request_type_id, schema_json)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                    schema_json = VALUES(schema_json),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (new_type_id, json.dumps(normalized_form_schema, ensure_ascii=True)),
            )

        # reviewers in the EXACT order selected
        for i, pos_id in enumerate(normalized_reviewer_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_reviewers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (new_type_id, pos_id, i),
                )

        # approvers in the EXACT order selected
        for i, pos_id in enumerate(normalized_approver_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_approvers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (new_type_id, pos_id, i),
                )

        conn.commit()
        flash(f'Request Type "{type_name}" created!', "success")

        if template_mode == "FILLABLE" and map_fields_now:
            return redirect(url_for("request_type_field_mapper_page", request_type_id=new_type_id))

    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin_dashboard"))

@app.route("/create_request", methods=["POST"])
def create_request():
    user_id = session.get("user_id")

    role_name = (session.get("role") or "").strip()
    position_name = (session.get("position") or "").strip()
    can_request_budget = can_use_secretary_budget_fields(role_name, position_name)

    
    if not user_id and session.get("email"):
        resolved_user_id = get_user_id_for_company(
            session.get("email"),
            int(session.get("company_id") or 0),
        )
        if resolved_user_id:
            session["user_id"] = resolved_user_id
            user_id = resolved_user_id

    if not user_id:
        # JSON for fetch
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return redirect("/login")

    user_id = int(user_id)
    request_type_id_raw = (request.form.get("request_type_id") or "").strip()
    template_data_json = (request.form.get("template_data_json") or "").strip()
    amount_raw = (
        request.form.get("template_total")
        or request.form.get("amount")
        or ""
    ).strip()
    total_amount_scope = str(request.form.get("total_apply_scope") or "first").strip().lower()
    if total_amount_scope not in {"first", "all", "specific"}:
        total_amount_scope = "first"

    total_amount_template_page = None
    if total_amount_scope == "specific":
        raw_total_page = (request.form.get("total_apply_template_page") or "").strip()
        if raw_total_page:
            try:
                parsed_total_page = int(raw_total_page)
                if parsed_total_page > 0:
                    total_amount_template_page = parsed_total_page
            except (TypeError, ValueError):
                total_amount_template_page = None
    request_purpose = (request.form.get("purpose") or "").strip()
    request_budget = normalize_request_budget(request.form.get("request_budget"))
    request_department = (session.get("dept") or "").strip()
    request_action = str(request.form.get("request_action") or "submit").strip().lower()
    is_draft = request_action == "draft"
    draft_request_id_raw = str(request.form.get("draft_request_id") or "").strip()
    draft_request_id = None
    if draft_request_id_raw:
        try:
            parsed_draft_request_id = int(draft_request_id_raw)
            if parsed_draft_request_id > 0:
                draft_request_id = parsed_draft_request_id
        except (TypeError, ValueError):
            draft_request_id = None
    wfor = request_purpose or request_budget
    file = request.files.get("file")

    if not request_type_id_raw:
        msg = "Request type is required."
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "danger")
        return redirect(request.referrer or "/udashboard")

    try:
        request_type_id = int(request_type_id_raw)
    except (TypeError, ValueError):
        msg = "Invalid request type selected."
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "danger")
        return redirect(request.referrer or "/udashboard")

    amount = None
    validated_template_payload_json = ""

    filename = None
    file_blob = None

    #  upload
    if file and file.filename:
        # PDF-only checks
        if not allowed_file(file.filename) or file.mimetype != "application/pdf":
            msg = "Supported file is PDF only. Please upload PDF file."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")

        filename = secure_filename(file.filename)
        file_blob = file.read()
                # Basic PDF signature check 
        if file_blob and not file_blob.startswith(b"%PDF-"):
            msg = "Invalid PDF file."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")


    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)
        ensure_request_type_form_schema_table(cursor, conn)
        ensure_request_form_submission_table(cursor, conn)
        ensure_budget_request_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            msg = "No company context found."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 403
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")

        requests_ok, requests_msg = check_company_request_capacity(cursor, company_id)
        if not requests_ok:
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": requests_msg}), 403
            flash(requests_msg, "danger")
            return redirect(request.referrer or "/udashboard")

        existing_draft_request_id = None
        existing_draft_filename = None
        existing_draft_attachment = None
        if draft_request_id is not None:
            cursor.execute(
                """
                SELECT r.request_id, r.filename, r.attachment
                FROM requests r
                JOIN request_status rs ON rs.status_id = r.status_id
                WHERE r.request_id = %s
                  AND r.user_id = %s
                  AND r.company_id = %s
                  AND UPPER(COALESCE(rs.status_name, '')) = 'DRAFT'
                LIMIT 1
                """,
                (draft_request_id, user_id, company_id),
            )
            existing_draft_row = cursor.fetchone() or {}
            if not existing_draft_row:
                msg = "Selected draft no longer exists or is already submitted."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

            existing_draft_request_id = int(existing_draft_row.get("request_id") or 0)
            existing_draft_filename = existing_draft_row.get("filename")
            existing_draft_attachment = existing_draft_row.get("attachment")

        if can_request_budget and not is_draft:
            if not request_budget:
                msg = "Request budget is required."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

            if not request_department:
                msg = "Your account has no assigned department. Please contact admin."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

            cursor.execute(
                "SELECT dept_name FROM departments WHERE dept_name = %s AND company_id = %s LIMIT 1",
                (request_department, company_id),
            )
            if not (cursor.fetchone() or {}).get("dept_name"):
                msg = "Invalid target department selected."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

        cursor.execute(
            """
            SELECT request_type_id, template_mode, template_filename, template_file
            FROM request_types
            WHERE request_type_id = %s AND company_id = %s
            LIMIT 1
            """,
            (request_type_id, company_id),
        )
        request_type_row = cursor.fetchone()
        if not request_type_row:
            msg = "Request type not found."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")

        template_mode = str(request_type_row.get("template_mode") or "").strip().upper()
        request_type_template_name = (request_type_row.get("template_filename") or "").strip()
        request_type_template_blob = request_type_row.get("template_file")

        if template_mode == "FILLABLE":
            if not request_type_template_blob and not is_draft:
                msg = "Representative template is missing for this fillable request type. Please contact the representative/admin."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

            if is_draft:
                if template_data_json:
                    try:
                        parsed_payload = json.loads(template_data_json)
                        validated_template_payload_json = json.dumps(parsed_payload, ensure_ascii=True)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        validated_template_payload_json = ""
                if amount_raw:
                    try:
                        amount = float(amount_raw)
                    except (TypeError, ValueError):
                        msg = "Invalid amount value."
                        if request.headers.get("X-Requested-With") == "fetch":
                            return jsonify({"success": False, "message": msg}), 400
                        flash(msg, "danger")
                        return redirect(request.referrer or "/udashboard")
            else:
                schema = get_request_type_fillable_schema(cursor, request_type_id)
                cleaned_payload, computed_total, has_total_sources, validation_error = validate_fillable_submission(
                    schema,
                    template_data_json,
                )
                if validation_error:
                    if request.headers.get("X-Requested-With") == "fetch":
                        return jsonify({"success": False, "message": validation_error}), 400
                    flash(validation_error, "danger")
                    return redirect(request.referrer or "/udashboard")

                validated_template_payload_json = json.dumps(cleaned_payload, ensure_ascii=True)

                if has_total_sources:
                    if amount_raw:
                        try:
                            amount = float(amount_raw)
                        except (TypeError, ValueError):
                            msg = "Invalid amount value."
                            if request.headers.get("X-Requested-With") == "fetch":
                                return jsonify({"success": False, "message": msg}), 400
                            flash(msg, "danger")
                            return redirect(request.referrer or "/udashboard")
                    else:
                        amount = float(computed_total)

                if request_type_template_blob and not file_blob:
                    file_blob = build_filled_pdf_from_submission(
                        request_type_template_blob,
                        schema,
                        cleaned_payload,
                        total_amount=computed_total if has_total_sources else None,
                        total_amount_scope=total_amount_scope,
                        total_amount_template_page=total_amount_template_page,
                    )
                    filename = request_type_template_name or f"request_type_{request_type_id}_template.pdf"

        if amount is None:
            if not amount_raw:
                amount = 0.0
            else:
                try:
                    amount = float(amount_raw)
                except (TypeError, ValueError):
                    msg = "Invalid amount value."
                    if request.headers.get("X-Requested-With") == "fetch":
                        return jsonify({"success": False, "message": msg}), 400
                    flash(msg, "danger")
                    return redirect(request.referrer or "/udashboard")

        if amount < 0:
            msg = "Amount cannot be negative."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")

        stage_position_id = None
        if not is_draft:
            # Find first REVIEWER
            cursor.execute("""
                SELECT position_id
                FROM request_type_reviewers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
                LIMIT 1
            """, (request_type_id,))
            reviewer = cursor.fetchone()

            if reviewer:
                stage_position_id = reviewer["position_id"]
            else:
                cursor.execute("""
                    SELECT position_id
                    FROM request_type_approvers
                    WHERE request_type_id = %s
                    ORDER BY order_no ASC
                    LIMIT 1
                """, (request_type_id,))
                approver = cursor.fetchone()
                stage_position_id = approver["position_id"] if approver else None

            if stage_position_id is None:
                msg = "No reviewers/approvers configured for this request type."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

        target_status_name = "DRAFT" if is_draft else "PENDING"
        cursor.execute(
            "SELECT status_id FROM request_status WHERE UPPER(status_name) = %s LIMIT 1",
            (target_status_name,),
        )
        status_row = cursor.fetchone() or {}
        status_id = status_row.get("status_id")

        if status_id is None and is_draft:
            cursor.execute(
                "INSERT INTO request_status (status_name) VALUES ('DRAFT')"
            )
            status_id = cursor.lastrowid

        if status_id is None:
            msg = f"{target_status_name.title()} status is not configured in DB."
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify({"success": False, "message": msg}), 500
            flash(msg, "danger")
            return redirect(request.referrer or "/udashboard")

        if not wfor:
            try:
                cursor.execute(
                    """
                    SELECT wfor
                    FROM request_types
                    WHERE request_type_id = %s AND company_id = %s
                    LIMIT 1
                    """,
                    (request_type_id, company_id),
                )
                request_type_wfor_row = cursor.fetchone() or {}
                wfor = (request_type_wfor_row.get("wfor") or "").strip()
            except Exception:
                try:
                    cursor.execute(
                        """
                        SELECT `for` AS wfor
                        FROM request_types
                        WHERE request_type_id = %s AND company_id = %s
                        LIMIT 1
                        """,
                        (request_type_id, company_id),
                    )
                    request_type_wfor_row = cursor.fetchone() or {}
                    wfor = (request_type_wfor_row.get("wfor") or "").strip()
                except Exception:
                    wfor = ""

        if not wfor:
            wfor = "General Request"

        if existing_draft_request_id and filename is None and file_blob is None:
            filename = existing_draft_filename
            file_blob = existing_draft_attachment

        if existing_draft_request_id:
            cursor.execute(
                """
                UPDATE requests
                SET
                    request_type_id = %s,
                    wfor = %s,
                    filename = %s,
                    attachment = %s,
                    amount = %s,
                    status_id = %s,
                    stage_position_id = %s
                WHERE request_id = %s AND user_id = %s AND company_id = %s
                """,
                (
                    request_type_id,
                    wfor,
                    filename,
                    file_blob,
                    amount,
                    status_id,
                    stage_position_id,
                    existing_draft_request_id,
                    user_id,
                    company_id,
                ),
            )
            request_id = existing_draft_request_id
        else:
            # Insert Request
            cursor.execute("""
                INSERT INTO requests (user_id, request_type_id, wfor, filename, attachment, amount, status_id, stage_position_id, company_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, request_type_id, wfor, filename, file_blob, amount, status_id, stage_position_id, company_id))

            request_id = cursor.lastrowid

        if can_request_budget and request_budget and request_department:
            cursor.execute(
                """
                INSERT INTO request_budget_metadata (request_id, budget_type, target_department, created_by_email)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    budget_type = VALUES(budget_type),
                    target_department = VALUES(target_department),
                    created_by_email = VALUES(created_by_email),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (request_id, request_budget, request_department, (session.get("email") or "").strip().lower()),
            )

        if validated_template_payload_json:
            cursor.execute(
                """
                INSERT INTO request_form_submissions (request_id, request_type_id, form_data_json)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    form_data_json = VALUES(form_data_json),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (request_id, request_type_id, validated_template_payload_json),
            )

        conn.commit()

        coo_result = {"queued": False, "notified": 0, "reason": "not_submitted"}
        if not is_draft:
            coo_result = queue_coo_if_stage_is_coo(
                cursor,
                conn,
                request_id,
                stage_position_id,
                requested_by_email=(session.get("email") or ""),
            )

        # return JSON for fetch
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify(
                {
                    "success": True,
                    "request_id": request_id,
                    "saved_as": "draft" if is_draft else "submitted",
                    "coo": coo_result,
                }
            ), 200

        flash("Request submitted successfully!", "success")
        return redirect("/udashboard")

    except Exception as exc:
        conn.rollback()
        logger.exception("create_request failed")
        msg = "Internal server error"
        status_code = 500
        if is_storage_full_exception(exc):
            msg = "Not enough storage space to save this request. Please free up server space and try again."
            status_code = 507
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": msg}), status_code
        flash(msg, "danger")
        return redirect(request.referrer or "/udashboard")
    finally:
        cursor.close()
        conn.close()


@app.route("/api/reports")
def reports_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        if not can_view_reports(cur):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cur.execute(
            "SELECT COUNT(*) AS c FROM requests WHERE company_id=%s AND WEEK(created_at)=WEEK(NOW())",
            (company_id,),
        )
        weekly = cur.fetchone()["c"]

        cur.execute(
            "SELECT COUNT(*) AS c FROM requests WHERE company_id=%s AND MONTH(created_at)=MONTH(NOW())",
            (company_id,),
        )
        monthly = cur.fetchone()["c"]

        cur.execute(
            "SELECT COUNT(*) AS c FROM requests WHERE company_id=%s AND YEAR(created_at)=YEAR(NOW())",
            (company_id,),
        )
        yearly = cur.fetchone()["c"]

        cur.execute(
            """
            SELECT t.type_name, COUNT(*) as total
            FROM requests r
            JOIN request_types t ON r.request_type_id=t.request_type_id
            WHERE r.company_id = %s
            GROUP BY t.type_name
            ORDER BY total DESC
            LIMIT 1
            """,
            (company_id,),
        )
        top = cur.fetchone()

        return jsonify({
            "success": True,
            "weekly_requests": weekly,
            "monthly_requests": monthly,
            "yearly_requests": yearly,
            "top_request_type": top["type_name"] if top else "None"
        })
    except Exception:
        logger.exception("reports_api failed")
        return jsonify({
            "success": False,
            "message": "Failed to load reports"
        }), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/budget/overview")
def budget_overview_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    dept = (session.get("dept") or "").strip()
    if not can_use_budget_reports(role, position, dept):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    scope_department = get_budget_scope_department(role, position, dept)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_budget_schema(cursor, conn)
        ensure_budget_request_schema(cursor, conn)
        ensure_department_budget_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        configured_total_budget = BUDGET_DEFAULT_TOTAL
        email = (session.get("email") or "").strip().lower()
        if email:
            cursor.execute(
                """
                SELECT total_budget
                FROM admin_budget_totals
                WHERE email = %s
                LIMIT 1
                """,
                (email,),
            )
            budget_row = cursor.fetchone() or {}
            if budget_row and budget_row.get("total_budget") is not None:
                configured_total_budget = parse_amount_decimal(budget_row.get("total_budget"))

        base_query = """
            SELECT
                r.created_at,
                COALESCE(rt.type_name, 'Uncategorized') AS category,
                COALESCE(meta.budget_type, r.wfor, '') AS budget_type,
                COALESCE(meta.target_department, d.dept_name, '') AS target_department,
                r.amount
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
            LEFT JOIN request_budget_metadata meta ON meta.request_id = r.request_id
            LEFT JOIN request_status rs ON r.status_id = rs.status_id
            WHERE r.company_id = %s
            AND YEAR(r.created_at) = YEAR(CURDATE())
            AND UPPER(COALESCE(rs.status_name, '')) IN ('APPROVED', 'IN PROGRESS', 'PENDING_USER', 'COMPLETED')
        """
        query_params = [company_id]
        if scope_department:
            base_query += """
            AND TRIM(COALESCE(meta.target_department, d.dept_name, '')) COLLATE utf8mb4_general_ci = TRIM(%s) COLLATE utf8mb4_general_ci
            """
            query_params.append(scope_department)

        base_query += """
            ORDER BY r.created_at ASC
        """

        cursor.execute(base_query, tuple(query_params))
        rows = cursor.fetchall() or []

        monthly_totals = [Decimal("0") for _ in range(12)]
        category_month_totals = {}
        student_total_cost = Decimal("0")
        department_total_cost = Decimal("0")

        for row in rows:
            created_at = row.get("created_at")
            if hasattr(created_at, "month"):
                month_index = int(created_at.month) - 1
            else:
                parsed = parse_budget_record_date(str(created_at or ""))
                month_index = parsed.month - 1 if parsed else -1

            if month_index < 0 or month_index > 11:
                continue

            amount = parse_amount_decimal(row.get("amount"))
            category = (row.get("category") or "Uncategorized").strip() or "Uncategorized"
            scope = (row.get("budget_type") or "").strip().lower()

            monthly_totals[month_index] += amount
            key = (month_index, category)
            category_month_totals[key] = category_month_totals.get(key, Decimal("0")) + amount

            if "student" in scope:
                student_total_cost += amount
            elif "department" in scope:
                department_total_cost += amount

        records = [
            {
                "month": month,
                "category": category,
                "amount": float(total),
            }
            for (month, category), total in sorted(
                category_month_totals.items(),
                key=lambda item: (item[0][0], item[0][1].lower()),
            )
        ]

        transfer_query = """
            SELECT created_at, COALESCE(budget_type_name, 'Department Budget') AS budget_type_name, amount, transaction_type
            FROM department_budget_ledger
            WHERE company_id = %s
              AND transaction_type IN ('TRANSFER_IN', 'TRANSFER_IN_STUDENT')
              AND YEAR(created_at) = YEAR(CURDATE())
        """
        transfer_params = [company_id]
        if scope_department:
            transfer_query += """
              AND (
                    TRIM(dept_name) COLLATE utf8mb4_general_ci = TRIM(%s) COLLATE utf8mb4_general_ci
                    OR transaction_type = 'TRANSFER_IN_STUDENT'
                  )
            """
            transfer_params.append(scope_department)

        cursor.execute(transfer_query, tuple(transfer_params))
        transfer_rows = cursor.fetchall() or []

        transfer_category_totals = {}
        student_transfer_total = Decimal("0")
        for row in transfer_rows:
            created_at = row.get("created_at")
            if hasattr(created_at, "month"):
                month_index = int(created_at.month) - 1
            else:
                parsed = parse_budget_record_date(str(created_at or ""))
                month_index = parsed.month - 1 if parsed else -1

            if month_index < 0 or month_index > 11:
                continue

            amount = parse_amount_decimal(row.get("amount"))
            category = (row.get("budget_type_name") or "Department Budget").strip() or "Department Budget"
            key = (month_index, category)
            transfer_category_totals[key] = transfer_category_totals.get(key, Decimal("0")) + amount

            tx_type = str(row.get("transaction_type") or "").strip().upper()
            if tx_type == "TRANSFER_IN_STUDENT" or "student" in category.lower():
                student_transfer_total += amount

        records.extend(
            {
                "month": month,
                "category": category,
                "amount": float(total),
            }
            for (month, category), total in sorted(
                transfer_category_totals.items(),
                key=lambda item: (item[0][0], item[0][1].lower()),
            )
        )

        total_cost = sum(monthly_totals, Decimal("0"))
        total_request_budget = total_cost
        student_department_total_cost = student_total_cost + department_total_cost
        student_available_total = (configured_total_budget + student_transfer_total) - student_total_cost
        if student_available_total < 0:
            student_available_total = Decimal("0")

        allocation_query = """
            SELECT
                d.dept_name,
                COALESCE(a.allocated_budget, 0) AS allocated_budget,
                COALESCE(a.consumed_budget, 0) AS consumed_budget,
                COALESCE(a.low_balance_threshold, 10000) AS low_balance_threshold
            FROM departments d
            LEFT JOIN department_budget_allocations a
                ON a.company_id = d.company_id AND a.dept_name = d.dept_name
            WHERE d.company_id = %s
        """
        allocation_params = [company_id]
        if scope_department:
            allocation_query += """
            AND TRIM(d.dept_name) COLLATE utf8mb4_general_ci = TRIM(%s) COLLATE utf8mb4_general_ci
            """
            allocation_params.append(scope_department)

        allocation_query += """
            ORDER BY d.dept_name ASC
        """

        cursor.execute(allocation_query, tuple(allocation_params))
        allocation_rows = cursor.fetchall() or []
        department_budgets = []
        department_allocated_total = Decimal("0")
        department_consumed_total = Decimal("0")
        department_available_total = Decimal("0")
        for item in allocation_rows:
            allocated_budget = parse_amount_decimal(item.get("allocated_budget"))
            consumed_budget = parse_amount_decimal(item.get("consumed_budget"))
            available_budget = allocated_budget - consumed_budget
            department_allocated_total += allocated_budget
            department_consumed_total += consumed_budget
            department_available_total += available_budget
            department_budgets.append(
                {
                    "department": item.get("dept_name"),
                    "allocated_budget": float(allocated_budget),
                    "consumed_budget": float(consumed_budget),
                    "available_budget": float(available_budget),
                    "low_balance_threshold": float(parse_amount_decimal(item.get("low_balance_threshold"))),
                }
            )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM budget_alerts
            WHERE company_id = %s AND is_resolved = 0
            """,
            (company_id,),
        )
        open_alert_count = int((cursor.fetchone() or {}).get("count") or 0)

        return jsonify(
            {
                "success": True,
                "year": datetime.datetime.now().year,
                "total_request_budget": float(total_request_budget),
                "total_budget": float(configured_total_budget),
                "total_cost": float(total_cost),
                "student_total_cost": float(student_total_cost),
                "department_total_cost": float(department_total_cost),
                "student_department_total_cost": float(student_department_total_cost),
                "student_transfer_total": float(student_transfer_total),
                "student_available_total": float(student_available_total),
                "monthly_totals": [float(total) for total in monthly_totals],
                "records": records,
                "department_budgets": department_budgets,
                "department_allocated_total": float(department_allocated_total),
                "department_consumed_total": float(department_consumed_total),
                "department_available_total": float(department_available_total),
                "open_budget_alert_count": open_alert_count,
            }
        )
    except Exception:
        logger.exception("budget_overview_api failed")
        return jsonify({"success": False, "message": "Failed to load budget overview"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/total", methods=["POST"])
def budget_total_update_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    position = (session.get("position") or "").strip()
    dept = (session.get("dept") or "").strip()
    if not can_use_budget_reports(role, position, dept):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    new_total = parse_amount_decimal(payload.get("total_budget"))
    if new_total < 0:
        return jsonify({"success": False, "message": "Budget total must be 0 or higher"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    try:
        ensure_budget_schema(cursor, conn)

        email = (session.get("email") or "").strip().lower()
        cursor.execute(
            """
            INSERT INTO admin_budget_totals (email, total_budget)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                total_budget = VALUES(total_budget),
                updated_at = CURRENT_TIMESTAMP
            """,
            (email, str(new_total)),
        )
        conn.commit()

        return jsonify(
            {
                "success": True,
                "message": "Budget total updated",
                "total_budget": float(new_total),
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("budget_total_update_api failed")
        return jsonify({"success": False, "message": "Failed to update budget total"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/departments", methods=["GET"])
def budget_departments_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_budget_schema(cursor, conn)

        role = (session.get("role") or "").strip()
        position = (session.get("position") or "").strip()
        dept = (session.get("dept") or "").strip()
        if not (can_use_budget_reports(role, position, dept) or can_manage_budget(cursor, role=role)):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cursor.execute(
            """
            SELECT
                d.dept_name,
                COALESCE(a.allocated_budget, 0) AS allocated_budget,
                COALESCE(a.consumed_budget, 0) AS consumed_budget,
                COALESCE(a.low_balance_threshold, 10000) AS low_balance_threshold
            FROM departments d
            LEFT JOIN department_budget_allocations a
                ON a.company_id = d.company_id AND a.dept_name = d.dept_name
            WHERE d.company_id = %s
            ORDER BY d.dept_name ASC
            """,
            (company_id,),
        )
        rows = cursor.fetchall() or []

        items = []
        for row in rows:
            allocated_budget = parse_amount_decimal(row.get("allocated_budget"))
            consumed_budget = parse_amount_decimal(row.get("consumed_budget"))
            available_budget = allocated_budget - consumed_budget
            items.append(
                {
                    "department": row.get("dept_name"),
                    "allocated_budget": float(allocated_budget),
                    "consumed_budget": float(consumed_budget),
                    "available_budget": float(available_budget),
                    "low_balance_threshold": float(parse_amount_decimal(row.get("low_balance_threshold"))),
                }
            )

        cursor.execute(
            """
            SELECT id, dept_name, request_id, alert_type, message, current_balance, threshold_value, created_at
            FROM budget_alerts
            WHERE company_id = %s AND is_resolved = 0
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (company_id,),
        )
        alerts = cursor.fetchall() or []

        for alert in alerts:
            alert["current_balance"] = float(parse_amount_decimal(alert.get("current_balance")))
            alert["threshold_value"] = float(parse_amount_decimal(alert.get("threshold_value")))

        return jsonify({"success": True, "items": items, "alerts": alerts})
    except Exception:
        logger.exception("budget_departments_api failed")
        return jsonify({"success": False, "message": "Failed to load department budgets"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/departments/allocate", methods=["POST"])
def budget_department_allocate_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    dept_name = _normalize_department_name(payload.get("department") or payload.get("dept_name"))
    amount = parse_amount_decimal(payload.get("amount"))
    threshold = payload.get("low_balance_threshold")
    threshold_value = parse_amount_decimal(threshold) if threshold is not None else None

    if not dept_name:
        return jsonify({"success": False, "message": "Department is required"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_budget_schema(cursor, conn)
        if not can_manage_budget(cursor):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cursor.execute(
            "SELECT dept_id FROM departments WHERE company_id = %s AND dept_name = %s LIMIT 1",
            (company_id, dept_name),
        )
        if not cursor.fetchone():
            return jsonify({"success": False, "message": "Department not found"}), 404

        allocation_row = _ensure_department_budget_row(cursor, company_id, dept_name)
        if not allocation_row:
            return jsonify({"success": False, "message": "Failed to initialize department allocation"}), 500

        allocated_budget = parse_amount_decimal(allocation_row.get("allocated_budget"))
        consumed_budget = parse_amount_decimal(allocation_row.get("consumed_budget"))
        low_balance_threshold = parse_amount_decimal(allocation_row.get("low_balance_threshold"))

        new_allocated_budget = allocated_budget + amount
        if new_allocated_budget < consumed_budget:
            return jsonify(
                {
                    "success": False,
                    "message": "Allocation cannot be less than already consumed budget",
                    "consumed_budget": float(consumed_budget),
                }
            ), 400

        if threshold_value is None:
            threshold_value = low_balance_threshold

        balance_before = allocated_budget - consumed_budget
        balance_after = new_allocated_budget - consumed_budget
        action_label = "ALLOCATION" if amount >= 0 else "ADJUSTMENT"

        cursor.execute(
            """
            UPDATE department_budget_allocations
            SET allocated_budget = %s,
                low_balance_threshold = %s
            WHERE company_id = %s AND dept_name = %s
            """,
            (str(new_allocated_budget), str(threshold_value), company_id, dept_name),
        )

        cursor.execute(
            """
            INSERT INTO department_budget_ledger
                (company_id, dept_name, transaction_type, amount, balance_before, balance_after, note, created_by_email)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                company_id,
                dept_name,
                action_label,
                str(amount),
                str(balance_before),
                str(balance_after),
                f"Manual budget update for {dept_name}",
                (session.get("email") or "").strip().lower(),
            ),
        )

        conn.commit()
        return jsonify(
            {
                "success": True,
                "department": dept_name,
                "allocated_budget": float(new_allocated_budget),
                "consumed_budget": float(consumed_budget),
                "available_budget": float(balance_after),
                "low_balance_threshold": float(threshold_value),
                "message": "Department budget updated",
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("budget_department_allocate_api failed")
        return jsonify({"success": False, "message": "Failed to update department budget"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/types", methods=["GET", "POST"])
def budget_types_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_budget_schema(cursor, conn)
        if not can_manage_budget(cursor):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        if request.method == "GET":
            cursor.execute(
                """
                SELECT id, type_name, is_active, created_at, updated_at
                FROM budget_types
                WHERE company_id = %s
                ORDER BY type_name ASC
                """,
                (company_id,),
            )
            return jsonify({"success": True, "items": cursor.fetchall() or []})

        payload = request.get_json(silent=True) or {}
        type_name = str(payload.get("type_name") or "").strip()
        if not type_name:
            return jsonify({"success": False, "message": "Budget type name is required"}), 400

        cursor.execute(
            "INSERT INTO budget_types (company_id, type_name, is_active) VALUES (%s, %s, 1)",
            (company_id, type_name),
        )
        conn.commit()
        return jsonify({"success": True, "message": "Budget type created"})
    except mysql.connector.Error as exc:
        conn.rollback()
        if getattr(exc, "errno", None) == 1062:
            return jsonify({"success": False, "message": "Budget type already exists"}), 409
        logger.exception("budget_types_api failed")
        return jsonify({"success": False, "message": "Failed to manage budget types"}), 500
    except Exception:
        conn.rollback()
        logger.exception("budget_types_api failed")
        return jsonify({"success": False, "message": "Failed to manage budget types"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/types/<int:type_id>", methods=["PUT", "DELETE"])
def budget_type_item_api(type_id):
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_budget_schema(cursor, conn)
        if not can_manage_budget(cursor):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cursor.execute(
            "SELECT id FROM budget_types WHERE id = %s AND company_id = %s LIMIT 1",
            (type_id, company_id),
        )
        if not cursor.fetchone():
            return jsonify({"success": False, "message": "Budget type not found"}), 404

        if request.method == "DELETE":
            cursor.execute("DELETE FROM budget_types WHERE id = %s AND company_id = %s", (type_id, company_id))
            conn.commit()
            return jsonify({"success": True, "message": "Budget type deleted"})

        payload = request.get_json(silent=True) or {}
        type_name = str(payload.get("type_name") or "").strip()
        if not type_name:
            return jsonify({"success": False, "message": "Budget type name is required"}), 400

        cursor.execute(
            "UPDATE budget_types SET type_name = %s WHERE id = %s AND company_id = %s",
            (type_name, type_id, company_id),
        )
        conn.commit()
        return jsonify({"success": True, "message": "Budget type updated"})
    except mysql.connector.Error as exc:
        conn.rollback()
        if getattr(exc, "errno", None) == 1062:
            return jsonify({"success": False, "message": "Budget type already exists"}), 409
        logger.exception("budget_type_item_api failed")
        return jsonify({"success": False, "message": "Failed to update budget type"}), 500
    except Exception:
        conn.rollback()
        logger.exception("budget_type_item_api failed")
        return jsonify({"success": False, "message": "Failed to update budget type"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/budget/transfer", methods=["POST"])
def budget_transfer_api():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    dept_name = _normalize_department_name(payload.get("department") or payload.get("dept_name"))
    amount = parse_amount_decimal(payload.get("amount"))
    budget_type_id = payload.get("budget_type_id")

    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than 0"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_budget_schema(cursor, conn)
        if not can_manage_budget(cursor):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        budget_type_name = "Department Budget"
        if budget_type_id not in (None, ""):
            try:
                budget_type_id_int = int(budget_type_id)
            except (TypeError, ValueError):
                return jsonify({"success": False, "message": "Invalid budget type"}), 400

            cursor.execute(
                "SELECT type_name FROM budget_types WHERE id = %s AND company_id = %s LIMIT 1",
                (budget_type_id_int, company_id),
            )
            budget_type_row = cursor.fetchone() or {}
            budget_type_name = str(budget_type_row.get("type_name") or "").strip()
            if not budget_type_name:
                return jsonify({"success": False, "message": "Budget type not found"}), 404

        is_student_transfer = "student" in budget_type_name.lower()
        if not is_student_transfer:
            if not dept_name:
                return jsonify({"success": False, "message": "Department is required for this budget type"}), 400
            cursor.execute(
                "SELECT dept_id FROM departments WHERE company_id = %s AND dept_name = %s LIMIT 1",
                (company_id, dept_name),
            )
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Department not found"}), 404

        ledger_dept_name = dept_name if dept_name else "STUDENT_POOL"

        allocated_budget = Decimal("0")
        consumed_budget = Decimal("0")
        low_balance_threshold = Decimal("0")
        new_allocated_budget = Decimal("0")
        balance_before = Decimal("0")
        balance_after = Decimal("0")

        if not is_student_transfer:
            allocation_row = _ensure_department_budget_row(cursor, company_id, dept_name)
            if not allocation_row:
                return jsonify({"success": False, "message": "Failed to initialize department allocation"}), 500

            allocated_budget = parse_amount_decimal(allocation_row.get("allocated_budget"))
            consumed_budget = parse_amount_decimal(allocation_row.get("consumed_budget"))
            low_balance_threshold = parse_amount_decimal(allocation_row.get("low_balance_threshold"))

            new_allocated_budget = allocated_budget + amount
            balance_before = allocated_budget - consumed_budget
            balance_after = new_allocated_budget - consumed_budget

            cursor.execute(
                """
                UPDATE department_budget_allocations
                SET allocated_budget = %s
                WHERE company_id = %s AND dept_name = %s
                """,
                (str(new_allocated_budget), company_id, dept_name),
            )

        note = (
            f"Virtual budget transfer ({budget_type_name}) to {dept_name}"
            if not is_student_transfer
            else f"Virtual student budget transfer ({budget_type_name})"
        )
        cursor.execute(
            """
            INSERT INTO department_budget_ledger
                (company_id, dept_name, transaction_type, budget_type_name, amount, balance_before, balance_after, note, created_by_email)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                company_id,
                ledger_dept_name,
                "TRANSFER_IN_STUDENT" if is_student_transfer else "TRANSFER_IN",
                budget_type_name,
                str(amount),
                str(balance_before),
                str(balance_after),
                note,
                (session.get("email") or "").strip().lower(),
            ),
        )

        conn.commit()
        return jsonify(
            {
                "success": True,
                "message": "Budget sent successfully",
                "department": dept_name,
                "budget_type": budget_type_name,
                "budget_scope": "student" if is_student_transfer else "department",
                "amount": float(amount),
                "allocated_budget": float(new_allocated_budget),
                "consumed_budget": float(consumed_budget),
                "available_budget": float(balance_after),
                "low_balance_threshold": float(low_balance_threshold),
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("budget_transfer_api failed")
        return jsonify({"success": False, "message": "Failed to send budget"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/reports/export")
def export_reports_csv():
    if "email" not in session:
        return Response("Unauthorized", status=401, mimetype="text/plain")

    selected_range = (request.args.get("range") or "this_week").strip().lower()
    selected_status = (request.args.get("status") or "all").strip().lower()
    requested_name = (request.args.get("name") or "").strip()
    allowed_ranges = {
        "this_week": "This Week",
        "this_month": "This Month",
        "three_months": "Last 3 Months",
        "six_months": "Last 6 Months",
        "this_year": "This Year",
    }
    allowed_statuses = {
        "all": ("REJECTED", "APPROVED", "COMPLETED"),
        "rejected": ("REJECTED",),
        "approved": ("APPROVED",),
        "completed": ("COMPLETED",),
    }

    if selected_range not in allowed_ranges:
        return jsonify({"success": False, "message": "Invalid export range"}), 400

    if selected_status not in allowed_statuses:
        return jsonify({"success": False, "message": "Invalid export status"}), 400

    if not requested_name:
        return jsonify({"success": False, "message": "Export file name is required"}), 400

    safe_name = re.sub(r"[^A-Za-z0-9._ -]+", "", requested_name).strip().strip(".")
    if not safe_name:
        return jsonify({"success": False, "message": "Invalid export file name"}), 400

    if safe_name.lower().endswith(".csv"):
        safe_name = safe_name[:-4].strip()
    if not safe_name:
        safe_name = "requests_export"

    where_map = {
        "this_week": (
            "r.created_at >= DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY) "
            "AND r.created_at < DATE_ADD(DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY), INTERVAL 7 DAY)"
        ),
        "this_month": "YEAR(r.created_at)=YEAR(CURDATE()) AND MONTH(r.created_at)=MONTH(CURDATE())",
        "three_months": "r.created_at >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)",
        "six_months": "r.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)",
        "this_year": "YEAR(r.created_at)=YEAR(CURDATE())",
    }

    status_values = allowed_statuses[selected_status]
    status_param = ",".join(status_values)

    export_query_map = {
        "this_week": """
            SELECT
                r.request_id,
                r.created_at,
                u.email,
                COALESCE(d.dept_name, '-') AS department,
                COALESCE(rt.type_name, '-') AS request_type,
                COALESCE(s.status_name, '-') AS status,
                COALESCE(p.position_name, '-') AS current_stage,
                COALESCE(r.filename, '-') AS filename
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.company_id = %s
            AND r.created_at >= DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY)
            AND r.created_at < DATE_ADD(DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY), INTERVAL 7 DAY)
            AND FIND_IN_SET(s.status_name, %s)
            ORDER BY r.created_at DESC
        """,
        "this_month": """
            SELECT
                r.request_id,
                r.created_at,
                u.email,
                COALESCE(d.dept_name, '-') AS department,
                COALESCE(rt.type_name, '-') AS request_type,
                COALESCE(s.status_name, '-') AS status,
                COALESCE(p.position_name, '-') AS current_stage,
                COALESCE(r.filename, '-') AS filename
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.company_id = %s
            AND YEAR(r.created_at)=YEAR(CURDATE()) AND MONTH(r.created_at)=MONTH(CURDATE())
            AND FIND_IN_SET(s.status_name, %s)
            ORDER BY r.created_at DESC
        """,
        "three_months": """
            SELECT
                r.request_id,
                r.created_at,
                u.email,
                COALESCE(d.dept_name, '-') AS department,
                COALESCE(rt.type_name, '-') AS request_type,
                COALESCE(s.status_name, '-') AS status,
                COALESCE(p.position_name, '-') AS current_stage,
                COALESCE(r.filename, '-') AS filename
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.company_id = %s
            AND r.created_at >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
            AND FIND_IN_SET(s.status_name, %s)
            ORDER BY r.created_at DESC
        """,
        "six_months": """
            SELECT
                r.request_id,
                r.created_at,
                u.email,
                COALESCE(d.dept_name, '-') AS department,
                COALESCE(rt.type_name, '-') AS request_type,
                COALESCE(s.status_name, '-') AS status,
                COALESCE(p.position_name, '-') AS current_stage,
                COALESCE(r.filename, '-') AS filename
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.company_id = %s
            AND r.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
            AND FIND_IN_SET(s.status_name, %s)
            ORDER BY r.created_at DESC
        """,
        "this_year": """
            SELECT
                r.request_id,
                r.created_at,
                u.email,
                COALESCE(d.dept_name, '-') AS department,
                COALESCE(rt.type_name, '-') AS request_type,
                COALESCE(s.status_name, '-') AS status,
                COALESCE(p.position_name, '-') AS current_stage,
                COALESCE(r.filename, '-') AS filename
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.company_id = %s
            AND YEAR(r.created_at)=YEAR(CURDATE())
            AND FIND_IN_SET(s.status_name, %s)
            ORDER BY r.created_at DESC
        """,
    }

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        if not can_view_reports(cur):
            return Response("Forbidden: missing report access permission", status=403, mimetype="text/plain")

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"success": False, "message": "No company context found"}), 403

        cur.execute(export_query_map[selected_range], (company_id, status_param))
        rows = cur.fetchall() or []

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Request ID",
                "Created At",
                "Email",
                "Department",
                "Request Type",
                "Status",
                "Current Stage",
                "Filename",
            ]
        )

        for row in rows:
            created_at = row.get("created_at")
            created_at_str = (
                created_at.strftime("%Y-%m-%d %H:%M:%S")
                if hasattr(created_at, "strftime")
                else str(created_at or "")
            )
            writer.writerow(
                [
                    row.get("request_id", ""),
                    created_at_str,
                    row.get("email", ""),
                    row.get("department", ""),
                    row.get("request_type", ""),
                    row.get("status", ""),
                    row.get("current_stage", ""),
                    row.get("filename", ""),
                ]
            )

        filename = f"{safe_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_data = output.getvalue()
        output.close()

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception:
        logger.exception("export_reports_csv failed")
        return jsonify({"success": False, "message": "Failed to export reports"}), 500
    finally:
        cur.close()
        conn.close()
    
# Download template


def _safe_int(value):
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _can_access_request_record(row, role, user_id, position_id):
    allowed_roles = {
        "Admin",
        "SuperAdmin",
        "AssistantAdmin",
        "Assistant",
        "GSDHead",
        "Dean",
        "Reviewer",
        "Approver",
    }

    if role in allowed_roles:
        return True

    # COO can review request attachments/submissions from special access pages.
    if is_coo_user(role, session.get("position")):
        return True

    request_owner_id = _safe_int(row.get("user_id"))
    request_stage_position_id = _safe_int(row.get("stage_position_id"))
    actor_user_id = _safe_int(user_id)
    actor_position_id = _safe_int(position_id)

    if actor_position_id is not None and request_stage_position_id == actor_position_id:
        return True

    if actor_user_id is not None and request_owner_id == actor_user_id:
        return True

    return False


def _humanize_submission_key(raw_key):
    key = re.sub(r"[_\-]+", " ", str(raw_key or "").strip())
    key = re.sub(r"\s+", " ", key).strip()
    return key.title() if key else "Field"


def _build_submission_fallback_pdf(
    request_id,
    request_type_name,
    requester_email,
    request_purpose,
    raw_form_json,
):
    from reportlab.lib.pagesizes import letter
    import textwrap

    buf = BytesIO()
    page_width, page_height = letter
    c = _rl_canvas.Canvas(buf, pagesize=letter)

    left_margin = 48
    right_margin = page_width - 48
    y = page_height - 56

    def draw_wrapped(text, font_name="Helvetica", font_size=10, indent=0, spacing=13):
        nonlocal y

        c.setFont(font_name, font_size)
        usable_width = max(120, right_margin - left_margin - indent)
        approx_char_width = max(4.5, font_size * 0.55)
        wrap_width = max(20, int(usable_width / approx_char_width))

        lines = textwrap.wrap(str(text or ""), width=wrap_width) or [""]
        for line in lines:
            if y < 56:
                c.showPage()
                y = page_height - 56
                c.setFont(font_name, font_size)
            c.drawString(left_margin + indent, y, line)
            y -= spacing

    draw_wrapped(f"Request Submission REQ#{request_id}", "Helvetica-Bold", 14, 0, 18)
    draw_wrapped(f"Request Type: {request_type_name or 'Request'}")
    draw_wrapped(f"Requester: {requester_email or '-'}")
    draw_wrapped(f"Purpose: {request_purpose or '-'}")
    draw_wrapped("")

    payload = {}
    if raw_form_json:
        try:
            candidate = json.loads(raw_form_json)
            if isinstance(candidate, dict):
                payload = candidate
        except Exception:
            payload = {}

    has_output = False

    fields = payload.get("fields")
    if isinstance(fields, dict):
        visible_fields = []
        for key, value in fields.items():
            txt = "" if value is None else str(value).strip()
            if txt:
                visible_fields.append((key, txt))

        if visible_fields:
            draw_wrapped("Fields", "Helvetica-Bold", 12, 0, 16)
            for key, value in visible_fields:
                draw_wrapped(f"{_humanize_submission_key(key)}: {value}", "Helvetica", 10, 8, 13)
            has_output = True

    tables = payload.get("tables")
    if isinstance(tables, dict):
        for table_key, rows in tables.items():
            if not isinstance(rows, list):
                continue

            normalized_rows = []
            for row_obj in rows:
                if not isinstance(row_obj, dict):
                    continue

                normalized = {}
                for raw_col, raw_val in row_obj.items():
                    col_key = str(raw_col or "").strip()
                    if not col_key:
                        continue
                    normalized[col_key] = "" if raw_val is None else str(raw_val).strip()

                if normalized:
                    normalized_rows.append(normalized)

            if not normalized_rows:
                continue

            column_keys = []
            for row_obj in normalized_rows:
                for col_key in row_obj.keys():
                    if col_key not in column_keys:
                        column_keys.append(col_key)

            draw_wrapped("")
            draw_wrapped(f"Table: {_humanize_submission_key(table_key)}", "Helvetica-Bold", 11, 0, 15)
            draw_wrapped(
                "Columns: " + ", ".join([_humanize_submission_key(col) for col in column_keys]),
                "Helvetica-Oblique",
                9,
                8,
                12,
            )

            for index, row_obj in enumerate(normalized_rows, start=1):
                parts = []
                for col_key in column_keys:
                    cell_val = row_obj.get(col_key, "")
                    if cell_val:
                        parts.append(f"{_humanize_submission_key(col_key)}: {cell_val}")
                row_text = " | ".join(parts) if parts else "(empty row)"
                draw_wrapped(f"Row {index}: {row_text}", "Helvetica", 9, 8, 12)

            has_output = True

    if not has_output:
        draw_wrapped("No structured form fields were submitted.", "Helvetica-Oblique", 10)

    c.save()
    return buf.getvalue()


def _load_template_pdf_bytes_for_request(cursor, request_id):
    cursor.execute(
        """
        SELECT
            r.attachment,
            r.filename,
            r.wfor,
            u.email,
            COALESCE(rt.type_name, 'Request') AS type_name,
            rt.template_filename,
            rt.template_file,
            rfs.form_data_json
        FROM requests r
        JOIN users u ON u.user_id = r.user_id
        LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
        LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
        WHERE r.request_id = %s
        LIMIT 1
        """,
        (request_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None, None

    filename = (row.get("filename") or "").strip()
    if row.get("attachment"):
        final_name = filename or f"request_{request_id}_attachment.pdf"
        if not final_name.lower().endswith(".pdf"):
            final_name = f"{final_name}.pdf"
        return row.get("attachment"), final_name

    if row.get("template_file"):
        template_name = (row.get("template_filename") or "").strip() or f"request_{request_id}_template.pdf"
        if not template_name.lower().endswith(".pdf"):
            template_name = f"{template_name}.pdf"
        return row.get("template_file"), template_name

    generated_pdf = _build_submission_fallback_pdf(
        request_id=request_id,
        request_type_name=row.get("type_name") or "Request",
        requester_email=row.get("email") or "",
        request_purpose=row.get("wfor") or "",
        raw_form_json=str(row.get("form_data_json") or "").strip(),
    )

    final_name = filename or f"request_{request_id}_submission.pdf"
    if not final_name.lower().endswith(".pdf"):
        final_name = f"{final_name}.pdf"
    return generated_pdf, final_name

@app.route("/download_attachment/<int:request_id>")
def download_attachment(request_id):
    if "email" not in session:
        return Response("Unauthorized", status=401, mimetype="text/plain")

    role = session.get("role")
    user_id = session.get("user_id")
    position_id = session.get("position_id")

    prefer_original = request.args.get("original") == "1"

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
                r.request_id,
                r.user_id,
                r.stage_position_id,
                r.request_type_id,
                r.filename,
                r.attachment,
                r.amount,
                r.wfor,
                u.email,
                COALESCE(rt.type_name, 'Request') AS type_name,
                rt.template_mode,
                rt.template_filename,
                rt.template_file,
                rfs.form_data_json,
                a.signed_pdf
            FROM requests r
            JOIN users u ON u.user_id = r.user_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
            LEFT JOIN request_annotations a ON a.request_id = r.request_id
            WHERE r.request_id = %s
        """,
            (request_id,),
        )
        row = cursor.fetchone()

        if not row:
            return Response("No attachment found", status=404, mimetype="text/plain")

        if not _can_access_request_record(row, role, user_id, position_id):
            return Response("Access Denied", status=403, mimetype="text/plain")

        generated_name = (row.get("filename") or "").strip() or f"request_{request_id}_attachment.pdf"
        if not generated_name.lower().endswith(".pdf"):
            generated_name = f"{generated_name}.pdf"

        template_mode = str(row.get("template_mode") or "").strip().upper()
        if template_mode == "FILLABLE":
            template_filename = (row.get("template_filename") or "").strip()
            if template_filename:
                generated_name = template_filename
                if not generated_name.lower().endswith(".pdf"):
                    generated_name = f"{generated_name}.pdf"

        regenerated_fillable_pdf = None
        try:
            template_blob = row.get("template_file")
            raw_form_json = str(row.get("form_data_json") or "").strip()
            request_type_id = _safe_int(row.get("request_type_id"))

            if template_mode == "FILLABLE" and template_blob and raw_form_json and request_type_id and (prefer_original or not row.get("signed_pdf")):
                parsed_payload = json.loads(raw_form_json)
                if isinstance(parsed_payload, dict):
                    ensure_request_type_form_schema_table(cursor, conn)
                    schema = get_request_type_fillable_schema(cursor, request_type_id)
                    regenerated_fillable_pdf = build_filled_pdf_from_submission(
                        template_blob,
                        schema,
                        parsed_payload,
                        total_amount=row.get("amount"),
                    )
        except Exception:
            logger.exception("download_attachment regeneration failed")

        pdf_bytes = None if prefer_original else row.get("signed_pdf")
        if not pdf_bytes and regenerated_fillable_pdf:
            pdf_bytes = regenerated_fillable_pdf
            try:
                cursor.execute(
                    """
                    UPDATE requests
                    SET attachment = %s,
                        filename = COALESCE(NULLIF(filename, ''), %s)
                    WHERE request_id = %s
                    """,
                    (pdf_bytes, generated_name, request_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                logger.exception("download_attachment persist regenerated PDF failed")

        if not pdf_bytes:
            pdf_bytes = row.get("attachment")

        if (not pdf_bytes) and row.get("template_file"):
            pdf_bytes = row.get("template_file")
            generated_name = (row.get("template_filename") or "").strip() or generated_name
            if not generated_name.lower().endswith(".pdf"):
                generated_name = f"{generated_name}.pdf"

        if not pdf_bytes:
            pdf_bytes = _build_submission_fallback_pdf(
                request_id=request_id,
                request_type_name=row.get("type_name") or "Request",
                requester_email=row.get("email") or "",
                request_purpose=row.get("wfor") or "",
                raw_form_json=str(row.get("form_data_json") or "").strip(),
            )
            if (not row.get("filename")) or (not str(row.get("filename")).strip()):
                generated_name = f"request_{request_id}_submission.pdf"

        # View in browser
        force_download = request.args.get("download") == "1"

        import mimetypes

        mime_type, _ = mimetypes.guess_type(generated_name)

        response = send_file(
            BytesIO(pdf_bytes),
            download_name=generated_name,
            mimetype=mime_type or "application/pdf",
            as_attachment=force_download,
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    finally:
        cursor.close()
        conn.close()


@app.route("/request_submission/<int:request_id>")
def request_submission(request_id):
    if "email" not in session:
        return redirect(url_for("login"))

    role = (session.get("role") or "").strip()
    user_id = session.get("user_id")
    position_id = session.get("position_id")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_request_form_submission_table(cursor, conn)

        cursor.execute(
            """
            SELECT
                r.request_id,
                r.user_id,
                r.stage_position_id,
                r.filename,
                r.wfor,
                u.email,
                COALESCE(rt.type_name, 'Request') AS type_name,
                rfs.form_data_json,
                CASE
                    WHEN r.attachment IS NOT NULL OR a.signed_pdf IS NOT NULL OR rfs.form_data_json IS NOT NULL OR rt.template_file IS NOT NULL THEN 1
                    ELSE 0
                END AS has_attachment
            FROM requests r
            JOIN users u ON u.user_id = r.user_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
            LEFT JOIN request_annotations a ON a.request_id = r.request_id
            WHERE r.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        row = cursor.fetchone()
        if not row:
            return Response("Request not found", status=404, mimetype="text/plain")

        if not _can_access_request_record(row, role, user_id, position_id):
            return Response("Access Denied", status=403, mimetype="text/plain")

        request_owner_id = _safe_int(row.get("user_id"))
        request_stage_position_id = _safe_int(row.get("stage_position_id"))
        actor_user_id = _safe_int(user_id)
        actor_position_id = _safe_int(position_id)

        is_admin_annotator = role in {"Admin", "SuperAdmin"}
        is_current_stage_actor = (
            actor_position_id is not None
            and request_stage_position_id is not None
            and actor_position_id == request_stage_position_id
        )
        is_request_owner = (
            actor_user_id is not None
            and request_owner_id is not None
            and actor_user_id == request_owner_id
        )
        can_open_annotate = is_admin_annotator or is_current_stage_actor or is_request_owner

        raw_form_json = str(row.get("form_data_json") or "").strip()
        parsed_payload = {}
        if raw_form_json:
            try:
                candidate = json.loads(raw_form_json)
                if isinstance(candidate, dict):
                    parsed_payload = candidate
            except Exception:
                parsed_payload = {}

        field_entries = []
        fields = parsed_payload.get("fields")
        if isinstance(fields, dict):
            for key, value in fields.items():
                text_value = "" if value is None else str(value).strip()
                if text_value:
                    field_entries.append(
                        {
                            "label": _humanize_submission_key(key),
                            "value": text_value,
                        }
                    )

        table_sections = []
        tables = parsed_payload.get("tables")
        if isinstance(tables, dict):
            for table_key, rows in tables.items():
                if not isinstance(rows, list):
                    continue

                normalized_rows = []
                for row_obj in rows:
                    if not isinstance(row_obj, dict):
                        continue
                    normalized = {}
                    for raw_col, raw_val in row_obj.items():
                        col_key = str(raw_col or "").strip()
                        if not col_key:
                            continue
                        normalized[col_key] = "" if raw_val is None else str(raw_val).strip()
                    if normalized:
                        normalized_rows.append(normalized)

                if not normalized_rows:
                    continue

                column_keys = []
                for row_obj in normalized_rows:
                    for col_key in row_obj.keys():
                        if col_key not in column_keys:
                            column_keys.append(col_key)

                display_rows = []
                for row_obj in normalized_rows:
                    display_rows.append([row_obj.get(col_key, "") for col_key in column_keys])

                table_sections.append(
                    {
                        "name": _humanize_submission_key(table_key),
                        "columns": [_humanize_submission_key(col) for col in column_keys],
                        "rows": display_rows,
                    }
                )

        has_form_data = bool(field_entries or table_sections)

        return render_template(
            "request_submission.html",
            request_id=request_id,
            request_type_name=row.get("type_name") or "Request",
            request_email=row.get("email") or "",
            request_purpose=row.get("wfor") or "",
            field_entries=field_entries,
            table_sections=table_sections,
            has_form_data=has_form_data,
            raw_form_json=raw_form_json if raw_form_json and not has_form_data else "",
            has_attachment=bool(row.get("has_attachment")),
            attachment_filename=row.get("filename") or "",
            attachment_view_url=url_for("download_attachment", request_id=request_id),
            attachment_download_url=url_for(
                "download_attachment",
                request_id=request_id,
                download=1,
            ),
            show_annotate_action=bool(row.get("has_attachment")) and can_open_annotate,
            annotate_url=url_for("annotate_page", request_id=request_id),
            annotate_button_label=(
                "Sign / Annotate PDF"
                if is_admin_annotator or is_current_stage_actor
                else "Open Annotation Viewer"
            ),
        )
    finally:
        cursor.close()
        conn.close()


@app.get("/api/request/<int:request_id>/annotations")
@login_required
def get_annotations(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    actor_user_id = session.get("user_id")
    actor_position_id = session.get("position_id")

    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    try:
        actor_position_id = int(actor_position_id) if actor_position_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_position_id = None

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT annotations_json FROM request_annotations WHERE request_id=%s",
            (request_id,),
        )
        row = cur.fetchone()
        if not row or not row.get("annotations_json"):
            return jsonify({"annotations": [], "has_annotations": False, "current_actor_has_annotations": False})

        annotations = json.loads(row["annotations_json"])
        if not isinstance(annotations, list):
            annotations = []

        current_actor_has_annotations = False
        for ann in annotations:
            if not isinstance(ann, dict):
                continue

            ann_user_id = ann.get("actor_user_id")
            ann_position_id = ann.get("actor_position_id")

            try:
                ann_user_id = int(ann_user_id) if ann_user_id not in (None, "") else None
            except (TypeError, ValueError):
                ann_user_id = None

            try:
                ann_position_id = int(ann_position_id) if ann_position_id not in (None, "") else None
            except (TypeError, ValueError):
                ann_position_id = None

            if actor_user_id is not None and ann_user_id == actor_user_id:
                current_actor_has_annotations = True
                break

            if actor_position_id is not None and ann_position_id == actor_position_id:
                current_actor_has_annotations = True
                break

        return jsonify(
            {
                "annotations": annotations,
                "has_annotations": len(annotations) > 0,
                "current_actor_has_annotations": current_actor_has_annotations,
                "actor_user_id": actor_user_id,
                "actor_position_id": actor_position_id,
                "actor_email": (session.get("email") or "").strip().lower() or None,
            }
        )
    finally:
        cur.close()
        conn.close()


@app.post("/api/request/<int:request_id>/annotations")
@csrf.exempt
def save_annotations(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    annotations = data.get("annotations") or []

    actor_user_id = session.get("user_id")
    actor_position_id = session.get("position_id")
    actor_email = (session.get("email") or "").strip().lower() or None

    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    try:
        actor_position_id = int(actor_position_id) if actor_position_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_position_id = None

    if not isinstance(annotations, list):
        return jsonify({"error": "Invalid annotations"}), 400

    #  limit count for safety
    if len(annotations) > 200:
        return jsonify({"error": "Too many items"}), 400

    def _normalize_optional_int(value):
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    def _annotation_owned_by_actor(ann):
        if not isinstance(ann, dict):
            return False

        ann_email = (ann.get("actor_email") or "").strip().lower()
        if actor_email and ann_email:
            return ann_email == actor_email

        ann_user_id = _normalize_optional_int(ann.get("actor_user_id"))
        if actor_user_id is not None and ann_user_id is not None:
            return ann_user_id == actor_user_id
        if (actor_user_id is not None) != (ann_user_id is not None):
            return False

        ann_position_id = _normalize_optional_int(ann.get("actor_position_id"))
        # Legacy fallback only when annotation has no actor email/user metadata.
        if (
            not ann_email
            and ann_user_id is None
            and actor_position_id is not None
            and ann_position_id is not None
        ):
            return ann_position_id == actor_position_id

        return False

    normalized_annotations = []
    for item in annotations:
        if not isinstance(item, dict):
            continue

        ann = dict(item)
        ann_id = ann.get("id")
        if ann_id in (None, ""):
            ann["id"] = f"ann-{int(time.time() * 1000)}-{len(normalized_annotations)}"
        else:
            ann["id"] = str(ann_id)

        if ann.get("actor_user_id") in (None, ""):
            ann["actor_user_id"] = actor_user_id
        if ann.get("actor_position_id") in (None, ""):
            ann["actor_position_id"] = actor_position_id
        if ann.get("actor_email") in (None, ""):
            ann["actor_email"] = actor_email

        normalized_annotations.append(ann)

    annotations = normalized_annotations

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT annotations_json FROM request_annotations WHERE request_id=%s",
            (request_id,),
        )
        existing_row = cur.fetchone()
        existing_annotations = []
        if existing_row and existing_row.get("annotations_json"):
            try:
                parsed = json.loads(existing_row["annotations_json"])
                if isinstance(parsed, list):
                    existing_annotations = [a for a in parsed if isinstance(a, dict)]
            except Exception:
                existing_annotations = []

        incoming_by_id = {}
        incoming_in_order = []
        for ann in annotations:
            ann_id = str(ann.get("id") or "")
            if not ann_id:
                continue
            incoming_by_id[ann_id] = ann
            incoming_in_order.append(ann_id)

        annotations_to_save = []
        protected_ids = set()

        for existing in existing_annotations:
            existing_id = existing.get("id")
            existing_id = str(existing_id) if existing_id not in (None, "") else None
            editable_by_actor = _annotation_owned_by_actor(existing)

            if not editable_by_actor:
                annotations_to_save.append(existing)
                if existing_id:
                    protected_ids.add(existing_id)
                continue

            if existing_id and existing_id in incoming_by_id:
                updated = dict(incoming_by_id.pop(existing_id))
                updated["actor_user_id"] = existing.get("actor_user_id")
                updated["actor_position_id"] = existing.get("actor_position_id")
                updated["actor_email"] = existing.get("actor_email")
                annotations_to_save.append(updated)
            # If an owned annotation is omitted by the actor, treat it as deleted.

        seen_new_ids = set()
        for ann_id in incoming_in_order:
            if ann_id in seen_new_ids:
                continue
            seen_new_ids.add(ann_id)

            ann = incoming_by_id.get(ann_id)
            if not ann:
                continue
            if ann_id in protected_ids:
                continue

            ann_to_add = dict(ann)
            ann_to_add["actor_user_id"] = actor_user_id
            ann_to_add["actor_position_id"] = actor_position_id
            ann_to_add["actor_email"] = actor_email
            annotations_to_save.append(ann_to_add)

        deduped_annotations = []
        seen_signatures = set()
        for ann in annotations_to_save:
            if not isinstance(ann, dict):
                continue

            ann_id = str(ann.get("id") or "").strip()
            ann_type = str(ann.get("type") or "").strip().lower()
            ann_page = int(_normalize_optional_int(ann.get("page")) or 0)
            ann_x = round(float(ann.get("x") or 0), 3)
            ann_y = round(float(ann.get("y") or 0), 3)
            ann_w = round(float(ann.get("w") or 0), 3)
            ann_h = round(float(ann.get("h") or 0), 3)
            ann_text = str(ann.get("text") or "").strip()
            ann_image = str(ann.get("imageDataUrl") or "")
            ann_actor_email = str(ann.get("actor_email") or "").strip().lower()
            ann_actor_user_id = _normalize_optional_int(ann.get("actor_user_id"))
            ann_actor_position_id = _normalize_optional_int(ann.get("actor_position_id"))

            signature = (
                ann_id,
                ann_type,
                ann_page,
                ann_x,
                ann_y,
                ann_w,
                ann_h,
                ann_text,
                ann_image,
                ann_actor_email,
                ann_actor_user_id,
                ann_actor_position_id,
            )
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            deduped_annotations.append(ann)

        annotations_to_save = deduped_annotations

        if len(annotations_to_save) > 200:
            return jsonify({"error": "Too many items"}), 400

        # Load base PDF
        template_pdf_bytes, _ = _load_template_pdf_bytes_for_request(cur, request_id)
        if not template_pdf_bytes:
            return jsonify({"error": "Original PDF not found"}), 404
        if annotations_to_save and not any(
            data.get("x") is not None and data.get("y") is not None
            for data in annotations_to_save
        ):
            return jsonify({"error": "Invalid annotation coordinates"}), 400

        # Ensure annotations row exists
        cur.execute(
            """
            INSERT INTO request_annotations (request_id) VALUES (%s)
            ON DUPLICATE KEY UPDATE request_id=request_id
        """,
            (request_id,),
        )

        # Convert annotation objects -> reportlab overlay draw instructions
        text_items = []
        image_items = []

        for it in annotations_to_save:
            t = (it.get("type") or "").strip().lower()
            page = int(it.get("page") or 0)
            x = float(it.get("x") or 0)
            y = float(it.get("y") or 0)

            if t == "text":
                text = (it.get("text") or "").strip()
                if not text:
                    continue
                font = int(it.get("font") or 12)
                w = float(it.get("w") or 0)
                h = float(it.get("h") or 0)
                text_items.append(
                    {
                        "page": page,
                        "x": x,
                        "y": y,
                        "w": w,
                        "h": h,
                        "text": text,
                        "font": font,
                    }
                )

            elif t == "image":
                b64 = (it.get("imageDataUrl") or "").strip()
                if not b64.startswith("data:image/"):
                    continue
                # width/height in PDF points
                w = float(it.get("w") or 120)
                h = float(it.get("h") or 50)
                img_bytes = base64.b64decode(b64.split(",", 1)[1])
                image_items.append(
                    {
                        "page": page,
                        "x": x,
                        "y": y,
                        "w": w,
                        "h": h,
                        "image_bytes": img_bytes,
                    }
                )

        overlay = make_overlay_pdf(template_pdf_bytes, text_items, image_items)
        signed_pdf = merge_overlay(template_pdf_bytes, overlay)

        cur.execute(
            """
            UPDATE request_annotations
            SET annotations_json=%s, signed_pdf=%s
            WHERE request_id=%s
        """,
            (json.dumps(annotations_to_save), signed_pdf, request_id),
        )

        conn.commit()
        return jsonify({"ok": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/annotate/<int:request_id>")
def annotate_page(request_id):
    if "email" not in session:
        return redirect("/login")

    role = session.get("role")
    user_id = session.get("user_id")
    position_id = session.get("position_id")

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT 
                r.request_id,
                r.user_id,
                r.company_id,
                r.stage_position_id,
                COALESCE(r.amount, 0) AS amount,
                r.filename,
                a.signed_pdf,
                s.status_name
            FROM requests r
            LEFT JOIN request_annotations a 
                ON a.request_id = r.request_id
            LEFT JOIN request_status s
                ON s.status_id = r.status_id
            WHERE r.request_id=%s
        """, (request_id,))
        row = cur.fetchone()
        if not row:
            return "Not found", 404

        signer_roles = {
            "Admin",
            "SuperAdmin",
            "AssistantAdmin",
            "Assistant",
            "GSDHead",
            "Dean",
            "Reviewer",
            "Approver",
        }

        current_stage = row.get("stage_position_id")
        try:
            current_stage = int(current_stage) if current_stage is not None else None
        except (TypeError, ValueError):
            current_stage = None

        actor_position = None
        try:
            actor_position = int(position_id) if position_id not in (None, "") else None
        except (TypeError, ValueError):
            actor_position = None

        allowed = False

        if role in signer_roles:
            allowed = True

        # Keep stage-based access for non-signer roles that may still be assigned.
        elif actor_position is not None and current_stage is not None and actor_position == current_stage:
            allowed = True

        # Requester can still open as read-only.
        elif row.get("user_id") == user_id:
            allowed = True

        if not allowed:
            return "Access Denied", 403

        ensure_finance_amount_editor_schema(cur, conn)
        request_company_id = int(row.get("company_id") or 0)
        can_edit_amount = is_finance_amount_editor(cur, request_company_id, user_id)

        status_name = str(row.get("status_name") or "").strip().upper()
        locked_final_statuses = {"REJECTED", "COMPLETED", "PENDING_USER"}
        is_current_stage_actor = (
            current_stage is not None and actor_position is not None and current_stage == actor_position
        )

        # Important: keep finalized requests read-only, but allow the currently
        # assigned next reviewer/approver to continue signing even if a prior
        # stage already produced signed_pdf.
        if status_name in locked_final_statuses:
            is_signed = True
        elif role in signer_roles:
            is_signed = False
        elif is_current_stage_actor:
            is_signed = False
        elif row.get("user_id") == user_id:
            is_signed = True
        else:
            is_signed = bool(row.get("signed_pdf"))

        return render_template(
            "annotate.html",
            request_id=request_id,
            filename=row.get("filename"),
            is_signed=is_signed,
            can_edit_amount=can_edit_amount,
            request_amount=float(parse_amount_decimal(row.get("amount"))),
        )
    finally:
        cur.close()
        conn.close()


@app.route("/api/annotate/<int:request_id>/amount", methods=["POST"])
@login_required
def annotate_update_request_amount(request_id):
    data = request.get_json(silent=True) or {}
    amount_raw = str(data.get("amount") or "").strip()
    if not amount_raw:
        return jsonify({"success": False, "error": "Amount is required."}), 400

    try:
        amount_value = parse_amount_input_decimal(amount_raw)
    except Exception:
        return jsonify({"success": False, "error": "Invalid amount value."}), 400

    if amount_value < 0:
        return jsonify({"success": False, "error": "Amount cannot be negative."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_finance_amount_editor_schema(cursor, conn)
        ensure_tenant_schema(cursor, conn)

        actor_user_id = int(session.get("user_id") or 0)
        if actor_user_id <= 0:
            return jsonify({"success": False, "error": "Unauthorized."}), 401

        cursor.execute(
            """
            SELECT
                r.request_id,
                r.company_id,
                COALESCE(s.status_name, '') AS status_name
            FROM requests r
            LEFT JOIN request_status s ON s.status_id = r.status_id
            WHERE r.request_id = %s
            LIMIT 1
            """,
            (request_id,),
        )
        request_row = cursor.fetchone() or {}
        if not request_row:
            return jsonify({"success": False, "error": "Request not found."}), 404

        company_id = int(request_row.get("company_id") or 0)
        if company_id <= 0:
            return jsonify({"success": False, "error": "Invalid company context."}), 400

        if not is_finance_amount_editor(cursor, company_id, actor_user_id):
            return jsonify({"success": False, "error": "Only Finance Amount Editor team can edit amount."}), 403

        status_name = str(request_row.get("status_name") or "").strip().upper()
        if status_name not in {"PENDING", "IN PROGRESS", "DRAFT"}:
            return jsonify({"success": False, "error": "Amount can only be edited while request is pending/in progress."}), 400

        cursor.execute(
            """
            UPDATE requests
            SET amount = %s
            WHERE request_id = %s
            """,
            (str(amount_value.quantize(Decimal("0.01"))), request_id),
        )
        cursor.execute(
            """
            INSERT INTO activity_logs (title, description, company_id, actor_email)
            VALUES (%s, %s, %s, %s)
            """,
            (
                "Request Amount Updated",
                f"{session.get('email')} updated amount for REQ#{request_id} to {float(amount_value):,.2f} via annotate page.",
                company_id,
                (session.get("email") or "").strip().lower() or None,
            ),
        )
        conn.commit()

        return jsonify(
            {
                "success": True,
                "message": "Amount updated successfully.",
                "request_id": request_id,
                "amount": float(amount_value.quantize(Decimal("0.01"))),
            }
        )
    except Exception:
        conn.rollback()
        logger.exception("annotate_update_request_amount failed")
        return jsonify({"success": False, "error": "Failed to update amount."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/annotate", methods=["POST"])
def annotate_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = session.get("role")
    actor_user_id = session.get("user_id")
    actor_company_id = session.get("company_id")

    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    try:
        actor_company_id = int(actor_company_id) if actor_company_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_company_id = None

    data = request.get_json() or {}
    who = (data.get("who") or "").strip().lower()
    note = (data.get("note") or "").strip()
    sig_b64 = (data.get("signature_png_base64") or "").strip()

    if who not in ("reviewer", "approver"):
        return jsonify({"error": "Invalid who"}), 400


    if role not in (
        "Admin",
        "SuperAdmin",
        "AssistantAdmin",
        "Dean",
        "Reviewer",
        "Approver",
    ):
        return jsonify({"error": "Forbidden"}), 403

    png_bytes = None
    if sig_b64:
        if not sig_b64.startswith("data:image/png;base64,"):
            return jsonify({"error": "Invalid signature image"}), 400
        png_bytes = base64.b64decode(sig_b64.split(",", 1)[1])

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_user_saved_signature_schema(cursor, conn)

        if png_bytes is not None and actor_user_id is not None:
            cursor.execute(
                """
                INSERT INTO user_saved_signatures (user_id, company_id, signature_png)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    company_id = VALUES(company_id),
                    signature_png = VALUES(signature_png),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (actor_user_id, actor_company_id, png_bytes),
            )

        # Load original PDF bytes
        template_pdf_bytes, _ = _load_template_pdf_bytes_for_request(cursor, request_id)
        if not template_pdf_bytes:
            return jsonify({"error": "Original PDF not found"}), 404

        # Ensure row exists
        cursor.execute(
            """
            INSERT INTO request_annotations (request_id) VALUES (%s)
            ON DUPLICATE KEY UPDATE request_id=request_id
        """,
            (request_id,),
        )

        now = datetime.datetime.now()

        if who == "reviewer":
            cursor.execute(
                """
                UPDATE request_annotations
                SET reviewer_note=%s,
                    reviewer_signed_at=%s,
                    reviewer_sig=COALESCE(%s, reviewer_sig)
                WHERE request_id=%s
            """,
                (
                    note or None,
                    now if (note or png_bytes) else None,
                    png_bytes,
                    request_id,
                ),
            )
        else:
            cursor.execute(
                """
                UPDATE request_annotations
                SET approver_note=%s,
                    approver_signed_at=%s,
                    approver_sig=COALESCE(%s, approver_sig)
                WHERE request_id=%s
            """,
                (
                    note or None,
                    now if (note or png_bytes) else None,
                    png_bytes,
                    request_id,
                ),
            )

        # Pull latest annotations to generate PDF
        cursor.execute(
            """
            SELECT reviewer_note, approver_note,
                reviewer_signed_at, approver_signed_at,
                reviewer_sig, approver_sig
            FROM request_annotations WHERE request_id=%s
        """,
            (request_id,),
        )
        a = cursor.fetchone() or {}

        text_items = []
        image_items = []

        if a.get("reviewer_note"):
            text_items.append(
                {"page": 0, "x": 120, "y": 55, "text": a["reviewer_note"], "font": 9}
            )
        if a.get("reviewer_signed_at"):
            text_items.append(
                {
                    "page": 0,
                    "x": 460,
                    "y": 40,
                    "text": a["reviewer_signed_at"].strftime("%Y-%m-%d"),
                    "font": 10,
                }
            )
        if a.get("reviewer_sig"):
            image_items.append(
                {
                    "page": 0,
                    "x": 260,
                    "y": 30,
                    "w": 140,
                    "h": 50,
                    "image_bytes": a["reviewer_sig"],
                }
            )

        # approver signature/date/note
        if a.get("approver_note"):
            text_items.append(
                {"page": 0, "x": 120, "y": 25, "text": a["approver_note"], "font": 9}
            )
        if a.get("approver_signed_at"):
            text_items.append(
                {
                    "page": 0,
                    "x": 460,
                    "y": 20,
                    "text": a["approver_signed_at"].strftime("%Y-%m-%d"),
                    "font": 10,
                }
            )
        if a.get("approver_sig"):
            image_items.append(
                {
                    "page": 0,
                    "x": 260,
                    "y": 10,
                    "w": 140,
                    "h": 50,
                    "image_bytes": a["approver_sig"],
                }
            )

        overlay = make_overlay_pdf(template_pdf_bytes, text_items, image_items)
        signed_pdf = merge_overlay(template_pdf_bytes, overlay)

        cursor.execute(
            """
            UPDATE request_annotations
            SET signed_pdf=%s
            WHERE request_id=%s
        """,
            (signed_pdf, request_id),
        )

        conn.commit()
        return jsonify({"ok": True})
    finally:
        cursor.close()
        conn.close()


@app.get("/api/annotations/my-signature")
@login_required
def get_my_saved_signature():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Allow admins, approvers, and reviewers to view saved signatures
    role = (session.get("role") or "").strip()
    allowed_roles = {"admin", "assistantadmin", "superadmin", "dean", "head", "approver", "reviewer", "coo", "sbo"}
    if role.lower() not in allowed_roles:
        return jsonify({"error": "Forbidden - signature feature not available for your role"}), 403

    actor_user_id = session.get("user_id")
    actor_company_id = session.get("company_id")

    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    try:
        actor_company_id = int(actor_company_id) if actor_company_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_company_id = None

    if actor_user_id is None:
        return jsonify({"has_signature": False})

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_user_saved_signature_schema(cursor, conn)
        cursor.execute(
            """
            SELECT signature_png
            FROM user_saved_signatures
            WHERE user_id = %s
              AND (%s IS NULL OR company_id = %s OR company_id IS NULL)
            LIMIT 1
            """,
            (actor_user_id, actor_company_id, actor_company_id),
        )
        row = cursor.fetchone() or {}
        signature_png = row.get("signature_png")

        if not signature_png:
            return jsonify({"has_signature": False})

        encoded = base64.b64encode(signature_png).decode("ascii")
        return jsonify(
            {
                "has_signature": True,
                "signature_png_base64": f"data:image/png;base64,{encoded}",
            }
        )
    finally:
        cursor.close()
        conn.close()


@app.post("/api/annotations/my-signature")
@login_required
def save_my_saved_signature():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Allow admins, approvers, and reviewers to save signatures
    role = (session.get("role") or "").strip()
    allowed_roles = {"admin", "assistantadmin", "superadmin", "dean", "head", "approver", "reviewer", "coo", "sbo"}
    if role.lower() not in allowed_roles:
        return jsonify({"success": False, "error": "Forbidden - signature feature not available for your role"}), 403

    actor_user_id = session.get("user_id")
    actor_company_id = session.get("company_id")

    try:
        actor_user_id = int(actor_user_id) if actor_user_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_user_id = None

    try:
        actor_company_id = int(actor_company_id) if actor_company_id not in (None, "") else None
    except (TypeError, ValueError):
        actor_company_id = None

    if actor_user_id is None:
        return jsonify({"success": False, "error": "Invalid user."}), 400

    # Accept multipart file upload 'signature' or JSON base64 in 'signature_png_base64'
    signature_bytes = None
    if "signature" in request.files:
        f = request.files.get("signature")
        try:
            signature_bytes = f.read()
        except Exception:
            signature_bytes = None
    else:
        data = request.get_json(silent=True) or {}
        b64 = data.get("signature_png_base64") or data.get("signature_base64")
        if b64 and isinstance(b64, str):
            # allow data url prefix
            if b64.startswith("data:"):
                try:
                    b64 = b64.split(",", 1)[1]
                except Exception:
                    pass
            try:
                signature_bytes = base64.b64decode(b64)
            except Exception:
                signature_bytes = None

    if not signature_bytes:
        return jsonify({"success": False, "error": "No signature provided."}), 400

    conn = get_connection()
    cursor = conn.cursor()
    try:
        ensure_user_saved_signature_schema(cursor, conn)
        cursor.execute(
            """
            INSERT INTO user_saved_signatures (user_id, company_id, signature_png)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE signature_png = VALUES(signature_png), company_id = VALUES(company_id)
            """,
            (int(actor_user_id), actor_company_id, signature_bytes),
        )
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Download Template Route
@app.route("/download_template/<int:type_id>")
def download_template(type_id):
    if "user_id" not in session:
        return redirect("/login")

    inline_mode = (request.args.get("inline") == "1")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT template_filename, template_file FROM request_types WHERE request_type_id = %s",
            (type_id,),
        )
        data = cursor.fetchone()

        if data and data["template_file"]:
            return send_file(
                BytesIO(data["template_file"]),
                download_name=data["template_filename"],
                as_attachment=not inline_mode,
            )
        else:
            flash("No template found.", "warning")
            return redirect(request.referrer)
    finally:
        cursor.close()
        conn.close()


@app.route("/delete_request_type/<int:id>")
def delete_request_type(id):
    if "email" not in session:
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if not can_manage_request_types(cursor):
            flash("You do not have permission to manage request types.", "danger")
            return redirect(url_for("admin_dashboard"))

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("No company context found.", "danger")
            return redirect("/admin")

        cursor.execute(
            "SELECT request_type_id FROM request_types WHERE request_type_id = %s AND company_id = %s LIMIT 1",
            (id, company_id),
        )
        if not cursor.fetchone():
            flash("Request type not found in your company.", "warning")
            return redirect("/admin")

        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (id,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (id,)
        )
        cursor.execute(
            "DELETE FROM request_types WHERE request_type_id = %s AND company_id = %s",
            (id, company_id),
        )
        conn.commit()
        flash("Request Type deleted.", "success")
    except Exception:
        conn.rollback()
        flash("Cannot delete: Type is in use.", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect("/admin")


@app.route("/edit_request_type", methods=["POST"])
def edit_request_type():
    if "email" not in session:
        return redirect("/login")

    type_id = request.form.get("type_id")
    new_name = request.form.get("type_name")
    reviewer_pos_ids = request.form.getlist("reviewer_position_ids[]")
    approver_pos_ids = request.form.getlist("approver_position_ids[]")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if not can_manage_request_types(cursor):
            flash("You do not have permission to manage request types.", "danger")
            return redirect(url_for("admin_dashboard"))

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("No company context found.", "danger")
            return redirect(url_for("admin_dashboard"))

        try:
            type_id_int = int(type_id)
        except (TypeError, ValueError):
            flash("Invalid request type ID.", "danger")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            "SELECT request_type_id FROM request_types WHERE request_type_id = %s AND company_id = %s LIMIT 1",
            (type_id_int, company_id),
        )
        if not cursor.fetchone():
            flash("Request type not found in your company.", "warning")
            return redirect(url_for("admin_dashboard"))

        normalized_reviewer_ids = []
        normalized_approver_ids = []
        try:
            normalized_reviewer_ids = [int(pos_id) for pos_id in reviewer_pos_ids if str(pos_id).strip()]
            normalized_approver_ids = [int(pos_id) for pos_id in approver_pos_ids if str(pos_id).strip()]
        except (TypeError, ValueError):
            flash("Invalid reviewer/approver selection.", "danger")
            return redirect(url_for("admin_dashboard"))

        selected_position_ids = normalized_reviewer_ids + normalized_approver_ids
        if selected_position_ids:
            cursor.execute(
                "SELECT position_id FROM positions WHERE company_id=%s",
                (company_id,),
            )
            valid_ids = {int(row["position_id"]) for row in (cursor.fetchall() or [])}
            for pos_id in selected_position_ids:
                if pos_id not in valid_ids:
                    flash("Selected reviewers/approvers must belong to your company.", "danger")
                    return redirect(url_for("admin_dashboard"))

        tpl = request.files.get("template_file")
        if tpl and tpl.filename:
            template_filename = secure_filename(tpl.filename)
            template_blob = tpl.read()
            cursor.execute(
                """
                UPDATE request_types
                SET template_filename = %s, template_file = %s
                WHERE request_type_id = %s AND company_id = %s
                """,
                (template_filename, template_blob, type_id_int, company_id),
            )

        # Update the Name
        cursor.execute(
            "UPDATE request_types SET type_name = %s WHERE request_type_id = %s AND company_id = %s",
            (new_name, type_id_int, company_id),
        )

        # reviewer/approver
        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (type_id_int,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (type_id_int,)
        )

        for i, pos_id in enumerate(normalized_reviewer_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_reviewers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (type_id_int, pos_id, i),
                )

        for i, pos_id in enumerate(normalized_approver_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_approvers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (type_id_int, pos_id, i),
                )

        conn.commit()
        flash("Request type updated successfully", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("admin_dashboard"))


#  IT DASHBOARD ROUTES

def ensure_department_management_schema(cursor, conn):
    # Table is managed externally by database migrations.
    return


@app.route("/IT")
@login_required
@role_required("IT", "SuperAdmin")
def it_dashboard():

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        ensure_activity_log_schema(cursor, conn)
        ensure_finance_amount_editor_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return "Forbidden", 403
        company_name = (session.get("company_name") or "").strip() or "Organization"

        cursor.execute(
                        """
                        SELECT COUNT(*) as count
                        FROM users
                        WHERE COALESCE(is_deleted, 0) = 0
                            AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
                            AND company_id = %s
                        """
                ,
                (company_id,)
                )
        result = cursor.fetchone()
        total_users = result["count"] if result else 0
        new_users_count = 5


        cursor.execute("SELECT dept_id, user_id FROM department_heads")
        explicit_head_rows = cursor.fetchall() or []
        explicit_head_user_by_dept = {
            int(row.get("dept_id")): int(row.get("user_id"))
            for row in explicit_head_rows
            if row.get("dept_id") is not None and row.get("user_id") is not None
        }
        query_users = """
            SELECT
                u.user_id,
                u.email,
                d.dept_name,
                r.role_name,
                p.position_name,
                COALESCE(u.is_banned, 0) AS is_banned,
                COALESCE(u.is_deleted, 0) AS is_deleted
            FROM users u
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN positions p ON u.position_id = p.position_id
                        WHERE COALESCE(u.is_deleted, 0) = 0
                            AND LOWER(COALESCE(u.email, '')) NOT LIKE '%@deleted.local'
                            AND u.company_id = %s
            ORDER BY u.user_id DESC
        """
        cursor.execute(query_users, (company_id,))
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM departments WHERE company_id = %s", (company_id,))
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM roles WHERE company_id = %s", (company_id,))
        roles = cursor.fetchall()
        
        # Get all positions
        cursor.execute("SELECT * FROM positions WHERE company_id = %s", (company_id,))
        positions = cursor.fetchall()

        department_profiles_by_id = {}
        for dept in departments:
            dept_id = dept.get("dept_id")
            dept_name = (dept.get("dept_name") or "Unnamed Department").strip()
            department_profiles_by_id[dept_id] = {
                "dept_id": dept_id,
                "dept_name": dept_name,
                "members": [],
                "head": None,
                "head_is_explicit": False,
                "total_requests": 0,
                "pending_requests": 0,
                "approved_requests": 0,
                "recent_requests": [],
            }

        cursor.execute(
            """
            SELECT
                d.dept_id,
                d.dept_name,
                u.user_id,
                u.email,
                COALESCE(r.role_name, '') AS role_name,
                COALESCE(p.position_name, '') AS position_name
            FROM departments d
            LEFT JOIN users u ON u.dept_id = d.dept_id
            LEFT JOIN roles r ON r.role_id = u.role_id
            LEFT JOIN positions p ON p.position_id = u.position_id
                WHERE d.company_id = %s
                  AND (u.user_id IS NULL
               OR (
                    COALESCE(u.is_deleted, 0) = 0
                    AND LOWER(COALESCE(u.email, '')) NOT LIKE '%@deleted.local'
                    ))
            ORDER BY d.dept_name ASC, u.email ASC
            """
                ,
                (company_id,)
        )
        member_rows = cursor.fetchall() or []

        head_keywords = ("head", "manager", "director", "dean", "chair", "chief")
        for row in member_rows:
            dept_id = row.get("dept_id")
            if dept_id not in department_profiles_by_id:
                dept_name = (row.get("dept_name") or "Unnamed Department").strip()
                department_profiles_by_id[dept_id] = {
                    "dept_id": dept_id,
                    "dept_name": dept_name,
                    "members": [],
                    "head": None,
                    "head_is_explicit": False,
                    "total_requests": 0,
                    "pending_requests": 0,
                    "approved_requests": 0,
                    "recent_requests": [],
                }

            user_id = row.get("user_id")
            if not user_id:
                continue

            member = {
                "user_id": user_id,
                "email": row.get("email") or "-",
                "role_name": row.get("role_name") or "-",
                "position_name": row.get("position_name") or "-",
                "display_name": (
                    ((row.get("email") or "").split("@")[0].replace(".", " ").replace("_", " ").title())
                    if row.get("email")
                    else "Unknown User"
                ),
            }
            profile = department_profiles_by_id[dept_id]
            profile["members"].append(member)

            explicit_head_user_id = explicit_head_user_by_dept.get(int(dept_id))
            if explicit_head_user_id is not None and int(member["user_id"]) == int(explicit_head_user_id):
                profile["head"] = member
                profile["head_is_explicit"] = True
                continue

            position_lower = (member["position_name"] or "").strip().lower()
            role_lower = (member["role_name"] or "").strip().lower()
            if (
                profile["head"] is None
                and not profile.get("head_is_explicit")
                and any(k in position_lower or k in role_lower for k in head_keywords)
            ):
                profile["head"] = member

        cursor.execute(
            """
            SELECT
                d.dept_id,
                d.dept_name,
                r.request_id,
                COALESCE(rt.type_name, 'Request') AS request_type_name,
                COALESCE(rs.status_name, 'Pending') AS status_name,
                r.created_at,
                COALESCE(r.amount, 0) AS amount,
                COALESCE(u.email, '-') AS requester_email
            FROM requests r
            LEFT JOIN users u ON u.user_id = r.user_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
            LEFT JOIN request_types rt ON rt.request_type_id = r.request_type_id
            LEFT JOIN request_status rs ON rs.status_id = r.status_id
            WHERE d.dept_id IS NOT NULL
                            AND COALESCE(u.company_id, r.company_id) = %s
            ORDER BY r.created_at DESC
            """
                        ,
                        (company_id,)
        )
        request_rows = cursor.fetchall() or []

        for row in request_rows:
            dept_id = row.get("dept_id")
            if dept_id not in department_profiles_by_id:
                dept_name = (row.get("dept_name") or "Unnamed Department").strip()
                department_profiles_by_id[dept_id] = {
                    "dept_id": dept_id,
                    "dept_name": dept_name,
                    "members": [],
                    "head": None,
                    "head_is_explicit": False,
                    "total_requests": 0,
                    "pending_requests": 0,
                    "approved_requests": 0,
                    "recent_requests": [],
                }

            profile = department_profiles_by_id[dept_id]
            profile["total_requests"] += 1

            status_name = (row.get("status_name") or "").strip().lower()
            if "pend" in status_name:
                profile["pending_requests"] += 1
            if "approv" in status_name:
                profile["approved_requests"] += 1

            if len(profile["recent_requests"]) < 5:
                profile["recent_requests"].append(
                    {
                        "request_id": row.get("request_id"),
                        "request_type_name": row.get("request_type_name") or "Request",
                        "status_name": row.get("status_name") or "Pending",
                        "created_at": row.get("created_at"),
                        "requester_email": row.get("requester_email") or "-",
                        "amount": row.get("amount") or 0,
                    }
                )

        department_profiles = sorted(
            department_profiles_by_id.values(),
            key=lambda p: (p.get("dept_name") or "").lower(),
        )

        cursor.execute(
            """
            SELECT
                u.user_id,
                u.dept_id,
                COALESCE(u.email, '') AS email,
                COALESCE(r.role_name, '') AS role_name,
                COALESCE(p.position_name, '') AS position_name,
                COALESCE(d.dept_name, '') AS current_dept_name
            FROM users u
            LEFT JOIN roles r ON r.role_id = u.role_id
            LEFT JOIN positions p ON p.position_id = u.position_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
            WHERE COALESCE(u.is_deleted, 0) = 0
              AND LOWER(COALESCE(u.email, '')) NOT LIKE '%@deleted.local'
                            AND u.company_id = %s
            ORDER BY u.email ASC
            """
                        ,
                        (company_id,)
        )
        active_user_rows = cursor.fetchall() or []
        cursor.execute(
                        """
                        SELECT
                                u.user_id,
                                COALESCE(u.email, '') AS email,
                                COALESCE(r.role_name, '-') AS role_name,
                                COALESCE(p.position_name, '-') AS position_name
                        FROM finance_amount_editors fe
                        JOIN users u ON u.user_id = fe.user_id
                        LEFT JOIN roles r ON r.role_id = u.role_id
                        LEFT JOIN positions p ON p.position_id = u.position_id
                        WHERE fe.company_id = %s
                            AND COALESCE(u.is_deleted, 0) = 0
                            AND LOWER(COALESCE(u.email, '')) NOT LIKE '%%@deleted.local'
                        ORDER BY u.email ASC
                        """,
                        (company_id,),
                )
        finance_amount_editor_members = cursor.fetchall() or []
        cursor.execute(
                        """
                        SELECT
                                u.user_id,
                                COALESCE(u.email, '') AS email,
                                COALESCE(r.role_name, '-') AS role_name,
                                COALESCE(p.position_name, '-') AS position_name
                        FROM users u
                        LEFT JOIN roles r ON r.role_id = u.role_id
                        LEFT JOIN positions p ON p.position_id = u.position_id
                        LEFT JOIN finance_amount_editors fe ON fe.company_id = u.company_id AND fe.user_id = u.user_id
                        WHERE u.company_id = %s
                            AND COALESCE(u.is_deleted, 0) = 0
                            AND COALESCE(u.is_banned, 0) = 0
                            AND LOWER(COALESCE(u.email, '')) NOT LIKE '%%@deleted.local'
                            AND fe.member_id IS NULL
                        ORDER BY u.email ASC
                        """,
                        (company_id,),
                )
        finance_amount_editor_candidates = cursor.fetchall() or []

        # IT Approval Team positions
        try:
            ensure_it_approval_team_schema(cursor, conn)
        except Exception:
            pass

        cursor.execute(
            """
            SELECT
                p.position_id,
                COALESCE(p.position_name, '') AS position_name
            FROM it_approval_positions ap
            JOIN positions p ON p.position_id = ap.position_id
            WHERE ap.company_id = %s
            ORDER BY p.position_name ASC
            """,
            (company_id,),
        )
        approval_team_positions = cursor.fetchall() or []

        cursor.execute(
            """
            SELECT position_id, position_name
            FROM positions
            WHERE company_id = %s
              AND position_id NOT IN (SELECT position_id FROM it_approval_positions WHERE company_id = %s)
            ORDER BY position_name ASC
            """,
            (company_id, company_id),
        )
        approval_team_candidates = cursor.fetchall() or []

        default_dev_email = (DEFAULT_DEV_EMAIL or "").strip().lower()
        company_user_emails = {
            str((row.get("email") or "")).strip().lower()
            for row in active_user_rows
            if str((row.get("email") or "")).strip()
            and str((row.get("email") or "")).strip().lower() != default_dev_email
        }

        def _log_belongs_to_company(log_row):
            log_company_id = log_row.get("company_id")
            try:
                if int(log_company_id or 0) == int(company_id):
                    return True
            except (TypeError, ValueError):
                pass

            text_blob = (
                f"{(log_row.get('title') or '')} {(log_row.get('description') or '')} "
                f"{(log_row.get('actor_email') or '')}"
            ).strip().lower()

            if not text_blob:
                return False

            if default_dev_email and default_dev_email in text_blob:
                return False

            if f"company_id={int(company_id)}" in text_blob:
                return True

            for email_value in company_user_emails:
                if email_value and email_value in text_blob:
                    return True

            return False

        for profile in department_profiles:
            profile["members_count"] = len(profile.get("members") or [])
            if profile.get("head") is None and profile["members_count"] > 0:
                profile["head"] = profile["members"][0]
            profile["available_users"] = []

            for row in active_user_rows:
                user_id = row.get("user_id")
                if not user_id:
                    continue

                current_dept_id = row.get("dept_id")
                if current_dept_id is not None and int(current_dept_id) == int(profile.get("dept_id") or 0):
                    continue

                email = row.get("email") or "-"
                profile["available_users"].append(
                    {
                        "user_id": user_id,
                        "email": email,
                        "display_name": email.split("@")[0].replace(".", " ").replace("_", " ").title() if email and email != "-" else "Unknown User",
                        "role_name": row.get("role_name") or "-",
                        "position_name": row.get("position_name") or "-",
                        "current_dept_name": row.get("current_dept_name") or "Unassigned",
                    }
                )

        notifications = []

        def _is_it_admin_notification(row):
            title = str((row or {}).get("title") or "").strip().lower()
            description = str((row or {}).get("description") or "").strip().lower()
            text_blob = f"{title} {description}".strip()
            if not text_blob:
                return False

            disallowed_tokens = (
                "req#",
                "request approved",
                "request rejected",
                "request completed",
                "request marked",
                "in progress",
                "pending",
                "login",
                "log in",
                "logout",
                "log out",
                "sign up",
                "signup",
            )
            if any(token in text_blob for token in disallowed_tokens):
                return False

            allowed_tokens = (
                "account created",
                "new account",
                "department created",
                "department deleted",
                "position created",
                "position deleted",
                "role created",
                "role updated",
                "role permissions updated",
                "permissions updated",
                "user moved",
                "user reassigned",
                "ban",
                "unban",
                "deleted account",
                "tenant",
                "organization",
                "subscription",
                "plan",
                "system broadcast",
                "system announcement",
                "broadcast:",
            )
            return any(token in text_blob for token in allowed_tokens)

        try:
            cursor.execute(
                """
                SELECT
                    n.message AS title,
                    n.message AS description,
                    n.created_at
                FROM notifications n
                JOIN users u ON u.user_id = n.user_id
                WHERE u.company_id = %s
                  AND (%s = '' OR LOWER(TRIM(u.email)) <> %s)
                ORDER BY n.created_at DESC
                LIMIT 200
                """,
                (company_id, default_dev_email, default_dev_email),
            )
            notification_rows = cursor.fetchall() or []
            filtered_rows = [row for row in notification_rows if _is_it_admin_notification(row)]
            notifications = list(reversed(filtered_rows[:15]))
        except Exception:
            cursor.execute(
                """
                SELECT log_id, title, description, created_at, company_id, actor_email
                FROM activity_logs
                ORDER BY created_at DESC
                LIMIT 500
                """
            )
            notification_rows = cursor.fetchall() or []
            notifications = [
                row
                for row in notification_rows
                if _log_belongs_to_company(row) and _is_it_admin_notification(row)
            ][:15]
            notifications = list(reversed(notifications))

        cursor.execute(
            """
            SELECT title, description, created_at
            , company_id, actor_email
            FROM activity_logs
            WHERE
                LOWER(COALESCE(title, '')) IN ('login', 'log in', 'sign up', 'signup', 'logout', 'log out')
                OR LOWER(COALESCE(description, '')) REGEXP 'login|log in|sign up|signup|logout|log out'
            ORDER BY created_at DESC
            LIMIT 200
            """
        )
        auth_log_rows = [row for row in (cursor.fetchall() or []) if _log_belongs_to_company(row)]

        activity_logs = []
        for row in auth_log_rows:
            title = (row.get("title") or "").strip()
            title_lower = title.lower()

            if "sign" in title_lower and "up" in title_lower:
                action_type = "Sign Up"
            elif "log" in title_lower and "out" in title_lower:
                action_type = "Logout"
            else:
                action_type = "Login"

            created_at = row.get("created_at")
            if hasattr(created_at, "strftime"):
                event_date = created_at.strftime("%Y-%m-%d")
                event_time = created_at.strftime("%I:%M:%S %p")
            else:
                created_at_text = str(created_at or "")
                created_parts = created_at_text.split(" ", 1)
                event_date = created_parts[0] if created_parts and created_parts[0] else "N/A"
                event_time = created_parts[1] if len(created_parts) > 1 else "N/A"

            description = row.get("description") or ""
            email_match = re.search(r"Email\s*:\s*([^|]+)", description, flags=re.IGNORECASE)
            where_match = re.search(r"(?:Where|Location|IP)\s*:\s*([^|]+)", description, flags=re.IGNORECASE)
            device_match = re.search(r"Device\s*:\s*([^|]+)", description, flags=re.IGNORECASE)

            activity_logs.append(
                {
                    "action_type": action_type,
                    "email": (email_match.group(1).strip() if email_match else "N/A"),
                    "event_date": event_date,
                    "event_time": event_time,
                    "location": (where_match.group(1).strip() if where_match else "N/A"),
                    "device": (device_match.group(1).strip() if device_match else "N/A"),
                }
            )

        cursor.execute(
            """
            SELECT
                r.request_id,
                COALESCE(sub.email, 'Unknown') AS submitted_by,
                r.created_at AS submitted_at,
                COALESCE(ra.action, '') AS action_name,
                COALESCE(ra.actor_email, 'Unknown') AS action_by,
                ra.created_at AS action_at
            FROM request_actions ra
            INNER JOIN requests r ON r.request_id = ra.request_id
            LEFT JOIN users sub ON sub.user_id = r.user_id
            WHERE
                COALESCE(sub.company_id, r.company_id) = %s
                AND (
                LOWER(COALESCE(ra.action, '')) LIKE '%approv%'
                OR LOWER(COALESCE(ra.action, '')) LIKE '%reject%'
                )
            ORDER BY ra.created_at DESC, ra.request_id DESC
            LIMIT 500
            """
            ,
            (company_id,)
        )
        audit_rows = cursor.fetchall() or []

        cursor.execute(
            """
            SELECT rp.role_id, rp.permission_key
            FROM role_permissions rp
            JOIN roles r ON r.role_id = rp.role_id
            WHERE r.company_id = %s
            """,
            (company_id,),
        )
        role_permission_rows = cursor.fetchall() or []
        role_permission_map = {}
        for row in role_permission_rows:
            role_id = int(row.get("role_id") or 0)
            if role_id <= 0:
                continue
            role_permission_map.setdefault(role_id, set()).add(str(row.get("permission_key") or "").strip())

        role_permission_map = {k: sorted(v) for k, v in role_permission_map.items()}

        audit_trails = []
        for row in audit_rows:
            submitted_at = row.get("submitted_at")
            action_at = row.get("action_at")
            action_name = (row.get("action_name") or "").strip().lower()
            is_rejected = "reject" in action_name
            is_approved = not is_rejected
            action_status = "Rejected" if is_rejected else "Approved"

            if hasattr(action_at, "strftime"):
                action_month = action_at.strftime("%Y-%m")
                action_timestamp = action_at.strftime("%Y-%m-%d %I:%M:%S %p")
            else:
                action_timestamp = str(action_at) if action_at else "N/A"
                action_month = action_timestamp[:7] if len(action_timestamp) >= 7 else ""

            audit_trails.append(
                {
                    "request_id": row.get("request_id"),
                    "action_status": action_status,
                    "action_month": action_month,
                    "action_timestamp": action_timestamp,
                    "submitted_by": row.get("submitted_by") or "N/A",
                    "submitted_at": submitted_at.strftime("%Y-%m-%d %I:%M:%S %p") if hasattr(submitted_at, "strftime") else (str(submitted_at) if submitted_at else "N/A"),
                    "approved_by": (row.get("action_by") if is_approved else "N/A") or "N/A",
                    "approved_at": (
                        action_at.strftime("%Y-%m-%d %I:%M:%S %p")
                        if is_approved and hasattr(action_at, "strftime")
                        else (str(action_at) if is_approved and action_at else "N/A")
                    ),
                    "rejected_by": (row.get("action_by") if is_rejected else "N/A") or "N/A",
                    "rejected_at": (
                        action_at.strftime("%Y-%m-%d %I:%M:%S %p")
                        if is_rejected and hasattr(action_at, "strftime")
                        else (str(action_at) if is_rejected and action_at else "N/A")
                    ),
                }
            )

        return render_template(
            "IT.html",
            users=users,
            total_users=total_users,
            new_users_count=new_users_count,
            departments=departments,
            department_profiles=department_profiles,
            roles=roles,
            positions=positions,
            notifications=notifications,
            activity_logs=activity_logs,
            audit_trails=audit_trails,
            company_name=company_name,
            tenant_permission_catalog=TENANT_PERMISSION_CATALOG,
            role_permission_map=role_permission_map,
            finance_amount_editor_members=finance_amount_editor_members,
            finance_amount_editor_candidates=finance_amount_editor_candidates,
            approval_team_positions=approval_team_positions,
            approval_team_candidates=approval_team_candidates,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/it/stats")
@login_required
@role_required("IT", "SuperAdmin")

def get_it_stats():
    """Return system stats for IT dashboard cards."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "Company context is missing"}), 403

        cursor.execute(
                        """
                        SELECT COUNT(*) as count
                        FROM users
                        WHERE COALESCE(is_deleted, 0) = 0
                            AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
                            AND company_id = %s
                        """
                        ,
                        (company_id,)
                )
        total_users = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM departments WHERE company_id = %s", (company_id,))
        total_depts = cursor.fetchone()["count"]

        active_sessions = None

        return jsonify({
            "total_users": total_users,
            "total_depts": total_depts,
            "active_sessions": active_sessions,
        })
    except Exception:
        logger.exception("get_it_stats failed")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/it/users", methods=["GET"])
@login_required
@role_required("IT", "SuperAdmin")

def get_all_users_for_admin():
    """Return all users for IT user management."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "Company context is missing"}), 403

        cursor.execute(
            """
            SELECT
                u.user_id,
                u.email,
                u.position_id,
                p.position_name,
                u.dept_id,
                d.dept_name,
                r.role_name,
                COALESCE(u.is_banned, 0) AS is_banned,
                COALESCE(u.is_deleted, 0) AS is_deleted
            FROM users u
            LEFT JOIN roles r ON r.role_id = u.role_id
            LEFT JOIN positions p ON p.position_id = u.position_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
                        WHERE COALESCE(u.is_deleted, 0) = 0
                            AND LOWER(COALESCE(u.email, '')) NOT LIKE '%@deleted.local'
                            AND u.company_id = %s
            ORDER BY u.user_id DESC
            """
            ,
            (company_id,)
        )
        rows = cursor.fetchall()
        return jsonify({"success": True, "data": rows})
    except Exception:
        logger.exception("get_all_users_for_admin failed")
        return jsonify({"success": False, "error": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/create_role", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def create_role():
    role_name = (request.form.get("role_name") or "").strip()
    selected_permissions = set(request.form.getlist("permissions"))
    allowed_permission_keys = {item[0] for item in TENANT_PERMISSION_CATALOG}
    selected_permissions = {p for p in selected_permissions if p in allowed_permission_keys}

    if not role_name:
        flash("Role name is required.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        seats_ok, seat_msg = check_company_user_seat_capacity(cursor, company_id)
        if not seats_ok:
            flash(seat_msg, "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT role_id FROM roles WHERE company_id = %s AND LOWER(TRIM(role_name)) = LOWER(TRIM(%s)) LIMIT 1",
            (company_id, role_name),
        )
        if cursor.fetchone():
            flash(f"Role '{role_name}' already exists.", "danger")
            return redirect(url_for("it_dashboard"))

        # Insert into Roles table
        cursor.execute("INSERT INTO roles (role_name, company_id) VALUES (%s, %s)", (role_name, company_id))
        new_role_id = int(cursor.lastrowid)

        for permission_key in sorted(selected_permissions):
            cursor.execute(
                "INSERT INTO role_permissions (role_id, permission_key) VALUES (%s, %s)",
                (new_role_id, permission_key),
            )

        # Log the Activity
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            ("Role Created", f"New system role '{role_name}' added in company_id={company_id}."),
        )

        conn.commit()
        flash(f"Role '{role_name}' created successfully!", "success")

    except mysql.connector.Error as err:
        conn.rollback()
        flash(f"Database Error: {err}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/create_position", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def create_position():
    position_name = (request.form.get("position_name") or "").strip()
    if not position_name:
        flash("Position name is required.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT position_id FROM positions WHERE company_id = %s AND LOWER(TRIM(position_name)) = LOWER(TRIM(%s)) LIMIT 1",
            (company_id, position_name),
        )
        if cursor.fetchone():
            flash(f"Position '{position_name}' already exists.", "danger")
            return redirect(url_for("it_dashboard"))

        # Insert into Positions table
        cursor.execute(
            "INSERT INTO positions (position_name, company_id) VALUES (%s, %s)",
            (position_name, company_id),
        )

        # Log the Activity
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            ("Position Created", f"New position '{position_name}' added."),
        )

        conn.commit()
        flash(f"Position '{position_name}' created successfully!", "success")

    except mysql.connector.Error as err:
        conn.rollback()
        flash(f"Database Error: {err}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/position/<int:position_id>/delete", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_delete_position(position_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_it_approval_team_schema(cursor, conn)
        ensure_finance_amount_editor_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT position_id, position_name FROM positions WHERE position_id = %s AND company_id = %s LIMIT 1",
            (position_id, company_id),
        )
        target = cursor.fetchone() or {}
        if not target:
            flash("Position not found.", "danger")
            return redirect(url_for("it_dashboard"))

        reference_checks = [
            ("users", "SELECT COUNT(*) AS count FROM users WHERE position_id = %s AND company_id = %s"),
            ("request_stage", "SELECT COUNT(*) AS count FROM requests WHERE stage_position_id = %s AND company_id = %s"),
            ("request_type_reviewers", "SELECT COUNT(*) AS count FROM request_type_reviewers rtr JOIN request_types rt ON rt.request_type_id = rtr.request_type_id WHERE rtr.position_id = %s AND rt.company_id = %s"),
            ("request_type_approvers", "SELECT COUNT(*) AS count FROM request_type_approvers rta JOIN request_types rt ON rt.request_type_id = rta.request_type_id WHERE rta.position_id = %s AND rt.company_id = %s"),
            ("it_approval_positions", "SELECT COUNT(*) AS count FROM it_approval_positions WHERE position_id = %s AND company_id = %s"),
            ("finance_amount_editors", "SELECT COUNT(*) AS count FROM finance_amount_editors WHERE user_id IN (SELECT user_id FROM users WHERE position_id = %s AND company_id = %s) AND company_id = %s"),
        ]

        used_by = []
        for label, query in reference_checks:
            if label == "finance_amount_editors":
                cursor.execute(query, (position_id, company_id, company_id))
            else:
                cursor.execute(query, (position_id, company_id))
            count_row = cursor.fetchone() or {}
            if int(count_row.get("count") or 0) > 0:
                used_by.append(label)

        if used_by:
            flash(
                "Cannot delete this position because it is still used by users, workflows, or teams.",
                "danger",
            )
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "DELETE FROM positions WHERE position_id = %s AND company_id = %s",
            (position_id, company_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Position Deleted",
                f"{session.get('email')} deleted position {target.get('position_name')} (position_id={position_id}).",
            ),
        )
        conn.commit()
        flash("Position deleted successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_delete_position failed")
        flash("Failed to delete position.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/role/<int:role_id>/permissions", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_update_role_permissions(role_id):
    selected_permissions = set(request.form.getlist("permissions"))
    allowed_permission_keys = {item[0] for item in TENANT_PERMISSION_CATALOG}
    selected_permissions = {p for p in selected_permissions if p in allowed_permission_keys}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT role_id, role_name FROM roles WHERE role_id=%s AND company_id=%s LIMIT 1", (role_id, company_id))
        role_row = cursor.fetchone()
        if not role_row:
            flash("Role not found for this organization.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("DELETE FROM role_permissions WHERE role_id=%s", (role_id,))
        for permission_key in sorted(selected_permissions):
            cursor.execute(
                "INSERT INTO role_permissions (role_id, permission_key) VALUES (%s, %s)",
                (role_id, permission_key),
            )

        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Role Permissions Updated",
                f"{session.get('email')} updated permissions for role '{role_row.get('role_name')}' (company_id={company_id}).",
            ),
        )
        conn.commit()
        flash("Role permissions updated.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_update_role_permissions failed")
        flash("Failed to update role permissions.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/api/request/<int:request_id>/status", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def update_request_status(request_id):
    
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    is_admin_role = role in {"AssistantAdmin", "Admin", "SuperAdmin"}

    actor_position_id_raw = session.get("position_id")
    actor_position_id_int = None
    try:
        if actor_position_id_raw not in (None, ""):
            actor_position_id_int = int(actor_position_id_raw)
    except (TypeError, ValueError):
        actor_position_id_int = None

    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or request.form.get("status") or "").strip()
    action_note_raw = data.get("message") or request.form.get("message") or data.get("comment") or request.form.get("comment")
    action_note = str(action_note_raw or "").strip()
    rejection_msg = action_note

    if not new_status:
        return jsonify({"error": "Missing status"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        cursor.execute(
            "SELECT stage_position_id, request_type_id FROM requests WHERE request_id = %s AND company_id = %s",
            (request_id, company_id),
        )
        auth_row = cursor.fetchone()
        if not auth_row:
            return jsonify({"error": "Request not found"}), 404

        current_stage_for_auth = auth_row.get("stage_position_id")
        req_type_for_auth = auth_row.get("request_type_id")
        if not is_admin_role:
            if actor_position_id_int is None:
                return jsonify({"error": "Forbidden"}), 403

            active_positions = []
            try:
                workflow_steps = get_effective_workflow_steps(
                    cursor,
                    request_id=request_id,
                    request_type_id=req_type_for_auth,
                )
                workflow_steps = _apply_conditional_high_value_workflow_steps(
                    cursor,
                    request_id,
                    workflow_steps,
                )
                approved_positions = _get_request_approved_positions(cursor, request_id)
                _active_idx, active_positions = _get_active_workflow_step_state(
                    workflow_steps,
                    current_stage_for_auth,
                    approved_positions,
                )
            except Exception:
                active_positions = []

            if active_positions:
                if actor_position_id_int not in active_positions:
                    return jsonify({"error": "Forbidden"}), 403
            else:
                if current_stage_for_auth is None or int(current_stage_for_auth) != actor_position_id_int:
                    return jsonify({"error": "Forbidden"}), 403

        new_status = (new_status or "").strip()
        if new_status.lower() in ("inprogress", "in_progress", "in progress"):
            new_status = "IN PROGRESS"
            
        # Get Status ID
        cursor.execute(
            "SELECT status_id FROM request_status WHERE status_name = %s",
            (new_status.upper(),),
        )
        status_row = cursor.fetchone()

        if not status_row:
            return jsonify({"error": "Invalid status"})

        status_id = status_row["status_id"]

        # Actor info (who clicked approve/reject)
        actor_user_id = session.get("user_id")
        actor_position_id = actor_position_id_int
        actor_email = session.get("email")

        # Request owner email (notification target)
        cursor.execute(
            """
            SELECT u.email AS requestor_email
            FROM requests r
            JOIN users u ON u.user_id = r.user_id
            WHERE r.request_id = %s AND r.company_id = %s
            """,
            (request_id, company_id),
        )
        _owner_row = cursor.fetchone() or {}
        requestor_email = (_owner_row.get("requestor_email") or "").strip()

        # IN PROGRESS
        if new_status.lower() == "in progress":
            in_progress_note = _truncate_request_action_message(cursor, action_note)
            cursor.execute(
                """
                UPDATE requests
                SET status_id = %s
                WHERE request_id = %s
                """,
                (status_id, request_id),
            )

            try:
                cursor.execute(
                    "INSERT INTO request_actions (request_id, actor_user_id, actor_position_id, actor_email, action, message) "
                    "VALUES (%s, %s, %s, %s, 'IN_PROGRESS', %s)",
                    (request_id, actor_user_id, actor_position_id, actor_email, in_progress_note),
                )
                cursor.execute(
                    "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                    (
                        "Marked In Progress",
                        f"REQ#{request_id} marked in progress by {actor_email or 'user'} (pos_id={actor_position_id}).",
                    ),
                )
            except Exception as _log_err:
                print("request_actions log error:", _log_err)

            try:
                render_mapped_signature_blocks_for_request(cursor, conn, request_id)
            except Exception:
                logger.exception("Failed to render mapped signatures for rejected request")

            conn.commit()
            return jsonify({"message": "Request marked as IN PROGRESS"})
        # If REJECTED mark rejected immediately
        
        if (new_status or "").lower() == "rejected":
            if not action_note:
                return jsonify({"error": "Rejection reason is required"}), 400

            approved_recipients = []
            request_type_name = "Request"
            rejection_reason_text = action_note
            rejection_msg = _truncate_request_action_message(cursor, action_note)

            cursor.execute(
                """
                UPDATE requests
                SET status_id = %s, rejection_message = %s
                WHERE request_id = %s
            """,
                (status_id, rejection_msg, request_id),
            )

            # log action 
            try:
                cursor.execute(
                    "INSERT INTO request_actions (request_id, actor_user_id, actor_position_id, actor_email, action, message) "
                    "VALUES (%s, %s, %s, %s, 'REJECTED', %s)",
                    (
                        request_id,
                        actor_user_id,
                        actor_position_id,
                        actor_email,
                        rejection_msg,
                    ),
                )
                cursor.execute(
                    "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                    (
                        "Request Rejected",
                        f"REQ#{request_id} rejected by {actor_email or 'user'} (pos_id={actor_position_id}).",
                    ),
                )
            except Exception as _log_err:
                print("request_actions log error:", _log_err)

            try:
                render_mapped_signature_blocks_for_request(cursor, conn, request_id)
            except Exception:
                logger.exception("Failed to render mapped signatures for approved request")

            # Notify everyone who already approved this request.
            try:
                cursor.execute(
                    """
                    SELECT DISTINCT COALESCE(ra.actor_email, u.email) AS email
                    FROM request_actions ra
                    LEFT JOIN users u ON u.user_id = ra.actor_user_id
                    WHERE ra.request_id = %s
                      AND ra.action = 'APPROVED'
                      AND COALESCE(ra.actor_email, u.email) IS NOT NULL
                """,
                    (request_id,),
                )
                recipient_rows = cursor.fetchall() or []

                seen_emails = set()
                actor_email_lower = (actor_email or "").strip().lower()

                for row in recipient_rows:
                    email = (row.get("email") or "").strip()
                    email_lower = email.lower()
                    if not email:
                        continue
                    if actor_email_lower and email_lower == actor_email_lower:
                        continue
                    if email_lower in seen_emails:
                        continue
                    seen_emails.add(email_lower)
                    approved_recipients.append(email)

                cursor.execute(
                    """
                    SELECT COALESCE(rt.type_name, 'Request') AS type_name
                    FROM requests r
                    LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
                    WHERE r.request_id = %s
                """,
                    (request_id,),
                )
                request_info = cursor.fetchone() or {}
                request_type_name = request_info.get("type_name") or "Request"
            except Exception as _notify_err:
                print("rejection notify preload error:", _notify_err)

            conn.commit()

            if requestor_email:
                try:
                    send_request_email_async(requestor_email, "REJECTED")
                except Exception as _owner_mail_err:
                    print("requestor reject email error:", _owner_mail_err)

            if approved_recipients:
                subject = f"Request Rejected Notice - REQ#{request_id}"
                body = f"""Good day,

                REQ#{request_id} ({request_type_name}) has been REJECTED by {actor_email or 'an approver/reviewer'}.
                Reason: {rejection_reason_text}

                You are receiving this because you previously approved this request.

                This is an automated message. Do not reply."""

                for recipient in approved_recipients:
                    try:
                        send_cc_email(recipient, subject, body)
                    except Exception as _send_err:
                        print("rejection notify email error:", _send_err)

            return jsonify({"message": "Request rejected successfully"})

        # If APPROVED advance to next reviewer/approver
        if (new_status or "").lower() == "approved":
            approved_note = _truncate_request_action_message(cursor, action_note)

            # log action (for per-position stats/history)
            try:
                cursor.execute(
                    "INSERT INTO request_actions (request_id, actor_user_id, actor_position_id, actor_email, action, message) "
                    "VALUES (%s, %s, %s, %s, 'APPROVED', %s)",
                    (request_id, actor_user_id, actor_position_id, actor_email, approved_note),
                )
                cursor.execute(
                    "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                    (
                        "Request Approved",
                        f"REQ#{request_id} approved by {actor_email or 'user'} (pos_id={actor_position_id}).",
                    ),
                )
            except Exception as _log_err:
                print("request_actions log error:", _log_err)

            cursor.execute(
                "SELECT request_type_id, stage_position_id FROM requests WHERE request_id = %s AND company_id = %s",
                (request_id, company_id),
            )
            req = cursor.fetchone()
            if not req:
                return jsonify({"error": "Request not found"})

            req_type_id = req["request_type_id"]
            current_stage = req["stage_position_id"]

            cursor.execute(
                "SELECT status_id FROM request_status WHERE status_name = 'PENDING'"
            )
            pending_row = cursor.fetchone()
            pending_status_id = pending_row["status_id"] if pending_row else 1

            def _build_full_approval_response(base_message="Request fully approved."):
                coo_queue_result = {"queued": False, "notified": 0, "reason": "not_queued"}
                try:
                    coo_queue_result = queue_coo_special_approval(
                        cursor,
                        conn,
                        request_id,
                        requested_by_email=(actor_email or ""),
                    )
                except Exception as _coo_queue_err:
                    print("coo queue error (workflow_steps):", _coo_queue_err)

                budget_result = {"processed": False, "reason": "not_budget_request", "alerts": []}
                try:
                    budget_result = apply_department_budget_deduction(
                        cursor,
                        conn,
                        request_id,
                        actor_email=actor_email,
                    )
                except Exception as _budget_err:
                    print("budget deduction error (workflow_steps):", _budget_err)

                if requestor_email:
                    try:
                        send_request_email_async(requestor_email, "APPROVED")
                    except Exception as _owner_mail_err:
                        print("requestor approved email error:", _owner_mail_err)

                if coo_queue_result.get("queued"):
                    base_message += " COO special approval was queued."
                elif coo_queue_result.get("reason") == "already_approved":
                    base_message += " COO special approval was already completed."
                elif coo_queue_result.get("reason") == "no_coo_recipient":
                    base_message += " No COO recipient was found for special approval notification."
                elif coo_queue_result.get("reason") == "email_delivery_failed":
                    base_message += " COO queue was created but email delivery failed. Use Special Access resend email."

                if budget_result.get("processed"):
                    if budget_result.get("already_processed"):
                        base_message += " Budget deduction was already recorded."
                    else:
                        base_message += (
                            f" Department budget deducted by {budget_result.get('amount', 0):,.2f}. "
                            f"Remaining balance: {budget_result.get('balance_after', 0):,.2f}."
                        )
                elif budget_result.get("reason") == "not_budget_request":
                    base_message += " No department budget deduction was required."

                budget_alerts = budget_result.get("alerts") or []
                if budget_alerts:
                    base_message += " Budget alert(s): " + " | ".join(str(a.get("message") or "").strip() for a in budget_alerts)

                base_message += " Budget disbursement processing still runs on completion by Purchasing or Representative."
                return jsonify(
                    {
                        "message": base_message,
                        "coo": coo_queue_result,
                        "budget": budget_result,
                        "xendit": {"processed": False, "reason": "release_actor_required"},
                    }
                )

            def _queue_coo_for_stage(stage_position_id):
                if not is_coo_position_id(cursor, stage_position_id):
                    return None
                try:
                    return queue_coo_special_approval(
                        cursor,
                        conn,
                        request_id,
                        requested_by_email=(actor_email or ""),
                    )
                except Exception as _coo_stage_queue_err:
                    print("coo queue error (stage transition):", _coo_stage_queue_err)
                    return {"queued": False, "notified": 0, "reason": "queue_error"}

            _reviewers, _approvers, workflow = get_effective_workflow_positions(
                cursor,
                request_id=request_id,
                request_type_id=req_type_id,
            )
            workflow = _apply_conditional_high_value_workflow(cursor, request_id, workflow)
            workflow_steps = get_effective_workflow_steps(
                cursor,
                request_id=request_id,
                request_type_id=req_type_id,
            )
            workflow_steps = _apply_conditional_high_value_workflow_steps(
                cursor,
                request_id,
                workflow_steps,
            )

            if current_stage is not None:
                current_stage = int(current_stage)

            if not workflow and not workflow_steps:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                    WHERE request_id = %s
                """,
                    (status_id, request_id),
                )

                coo_queue_result = {"queued": False, "notified": 0, "reason": "not_queued"}
                try:
                    coo_queue_result = queue_coo_special_approval(
                        cursor,
                        conn,
                        request_id,
                        requested_by_email=(actor_email or ""),
                    )
                except Exception as _coo_queue_err:
                    print("coo queue error (no workflow):", _coo_queue_err)

                budget_result = {"processed": False, "reason": "not_budget_request", "alerts": []}
                try:
                    budget_result = apply_department_budget_deduction(
                        cursor,
                        conn,
                        request_id,
                        actor_email=actor_email,
                    )
                except Exception as _budget_err:
                    print("budget deduction error (no workflow):", _budget_err)

                conn.commit()
                if requestor_email:
                    try:
                        send_request_email_async(requestor_email, "APPROVED")
                    except Exception as _owner_mail_err:
                        print("requestor approved email error:", _owner_mail_err)

                base_message = "Request approved (no workflow configured)."
                if coo_queue_result.get("queued"):
                    base_message += " COO special approval was queued."
                elif coo_queue_result.get("reason") == "already_approved":
                    base_message += " COO special approval was already completed."
                elif coo_queue_result.get("reason") == "no_coo_recipient":
                    base_message += " No COO recipient was found for special approval notification."
                elif coo_queue_result.get("reason") == "email_delivery_failed":
                    base_message += " COO queue was created but email delivery failed. Use Special Access resend email."

                if budget_result.get("processed"):
                    if budget_result.get("already_processed"):
                        base_message += " Budget deduction was already recorded."
                    else:
                        base_message += (
                            f" Department budget deducted by {budget_result.get('amount', 0):,.2f}. "
                            f"Remaining balance: {budget_result.get('balance_after', 0):,.2f}."
                        )
                elif budget_result.get("reason") == "not_budget_request":
                    base_message += " No department budget deduction was required."

                budget_alerts = budget_result.get("alerts") or []
                if budget_alerts:
                    base_message += " Budget alert(s): " + " | ".join(str(a.get("message") or "").strip() for a in budget_alerts)

                base_message += " Budget disbursement processing still runs on completion by Purchasing or Representative."
                return jsonify(
                    {
                        "message": base_message,
                        "coo": coo_queue_result,
                        "budget": budget_result,
                        "xendit": {"processed": False, "reason": "release_actor_required"},
                    }
                )

            if workflow_steps:
                approved_positions = _get_request_approved_positions(cursor, request_id)
                pre_idx, pre_pending_positions = _get_active_workflow_step_state(
                    workflow_steps,
                    current_stage,
                    approved_positions,
                )

                if pre_idx is None:
                    cursor.execute(
                        """
                        UPDATE requests
                        SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                        WHERE request_id = %s
                    """,
                        (status_id, request_id),
                    )
                    conn.commit()
                    return _build_full_approval_response("Request fully approved.")

                # Recompute after APPROVED action log above.
                approved_positions = _get_request_approved_positions(cursor, request_id)
                post_idx, post_pending_positions = _get_active_workflow_step_state(
                    workflow_steps,
                    current_stage,
                    approved_positions,
                )

                if post_idx is None:
                    cursor.execute(
                        """
                        UPDATE requests
                        SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                        WHERE request_id = %s
                    """,
                        (status_id, request_id),
                    )
                    conn.commit()
                    return _build_full_approval_response("Request fully approved.")

                next_stage_position = int(post_pending_positions[0]) if post_pending_positions else None
                if next_stage_position is None:
                    cursor.execute(
                        """
                        UPDATE requests
                        SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                        WHERE request_id = %s
                    """,
                        (status_id, request_id),
                    )
                    conn.commit()
                    return _build_full_approval_response("Request fully approved.")

                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (pending_status_id, next_stage_position, request_id),
                )
                conn.commit()

                coo_stage_result = _queue_coo_for_stage(next_stage_position)

                if post_idx == pre_idx:
                    message = "Approved. Waiting for other parallel approvers."
                    if coo_stage_result and coo_stage_result.get("queued"):
                        message += " COO special approval email link was queued."
                    return jsonify({"message": message, "coo": coo_stage_result})

                message = "Approved. Moved to next stage."
                if coo_stage_result and coo_stage_result.get("queued"):
                    message += " COO special approval email link was queued."
                return jsonify({"message": message, "coo": coo_stage_result})

            if not current_stage:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (pending_status_id, workflow[0], request_id),
                )
                conn.commit()
                coo_stage_result = _queue_coo_for_stage(workflow[0])
                message = "Request routed to first stage."
                if coo_stage_result and coo_stage_result.get("queued"):
                    message += " COO special approval email link was queued."
                return jsonify({"message": message, "coo": coo_stage_result})

            try:
                idx = workflow.index(current_stage)
            except ValueError:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (pending_status_id, workflow[0], request_id),
                )
                conn.commit()
                coo_stage_result = _queue_coo_for_stage(workflow[0])
                message = "Request stage reset to first stage."
                if coo_stage_result and coo_stage_result.get("queued"):
                    message += " COO special approval email link was queued."
                return jsonify({"message": message, "coo": coo_stage_result})

            if idx < len(workflow) - 1:
                next_stage = workflow[idx + 1]
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (pending_status_id, next_stage, request_id),
                )
                conn.commit()
                coo_stage_result = _queue_coo_for_stage(next_stage)
                message = "Approved. Moved to next stage."
                if coo_stage_result and coo_stage_result.get("queued"):
                    message += " COO special approval email link was queued."
                return jsonify({"message": message, "coo": coo_stage_result})
            else:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                    WHERE request_id = %s
                """,
                    (status_id, request_id),
                )
                conn.commit()
                if requestor_email:
                    try:
                        send_request_email_async(requestor_email, "APPROVED")
                    except Exception as _owner_mail_err:
                        print("requestor approved email error:", _owner_mail_err)

                base_message = "Request fully approved."
                coo_queue_result = {"queued": False, "notified": 0, "reason": "not_queued"}
                try:
                    coo_queue_result = queue_coo_special_approval(
                        cursor,
                        conn,
                        request_id,
                        requested_by_email=(actor_email or ""),
                    )
                except Exception as _coo_queue_err:
                    print("coo queue error:", _coo_queue_err)

                budget_result = {"processed": False, "reason": "not_budget_request", "alerts": []}
                try:
                    budget_result = apply_department_budget_deduction(
                        cursor,
                        conn,
                        request_id,
                        actor_email=actor_email,
                    )
                except Exception as _budget_err:
                    print("budget deduction error:", _budget_err)

                if coo_queue_result.get("queued"):
                    base_message += " COO special approval was queued."
                elif coo_queue_result.get("reason") == "already_approved":
                    base_message += " COO special approval was already completed."
                elif coo_queue_result.get("reason") == "no_coo_recipient":
                    base_message += " No COO recipient was found for special approval notification."
                elif coo_queue_result.get("reason") == "email_delivery_failed":
                    base_message += " COO queue was created but email delivery failed. Use Special Access resend email."

                if budget_result.get("processed"):
                    if budget_result.get("already_processed"):
                        base_message += " Budget deduction was already recorded."
                    else:
                        base_message += (
                            f" Department budget deducted by {budget_result.get('amount', 0):,.2f}. "
                            f"Remaining balance: {budget_result.get('balance_after', 0):,.2f}."
                        )
                elif budget_result.get("reason") == "not_budget_request":
                    base_message += " No department budget deduction was required."

                budget_alerts = budget_result.get("alerts") or []
                if budget_alerts:
                    base_message += " Budget alert(s): " + " | ".join(str(a.get("message") or "").strip() for a in budget_alerts)

                base_message += " Budget disbursement processing still runs on completion by Purchasing or Representative."
                return jsonify({
                    "message": base_message,
                    "coo": coo_queue_result,
                    "budget": budget_result,
                    "xendit": {"processed": False, "reason": "release_actor_required"},
                })

        # Fallback: set status as requested
        cursor.execute(
            """
            UPDATE requests 
            SET status_id = %s, rejection_message = %s 
            WHERE request_id = %s AND company_id = %s
        """,
            (status_id, rejection_msg, request_id, company_id),
        )

        conn.commit()
        return jsonify({"message": f"Request {new_status} successfully"})

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/send-back", methods=["POST"])
@login_required
def send_back_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    note = (data.get("message") or "").strip()
    if not note:
        return jsonify({"error": "Message is required."}), 400

    actor_user_id = session.get("user_id")
    actor_email = (session.get("email") or "").strip()
    actor_position_id = session.get("position_id")

    try:
        actor_position_id = int(actor_position_id)
    except Exception:
        return jsonify({"error": "Only reviewers/approvers can send back requests."}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        cursor.execute(
            """
            SELECT r.request_id, r.request_type_id, r.stage_position_id, s.status_name
            FROM requests r
            JOIN request_status s ON s.status_id = r.status_id
            WHERE r.request_id = %s AND r.company_id = %s
            LIMIT 1
        """,
            (request_id, company_id),
        )
        req = cursor.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        if (req.get("status_name") or "").upper() != "PENDING":
            return jsonify({"error": "Only pending requests can be sent back."}), 400

        current_stage = req.get("stage_position_id")
        if current_stage is None:
            return jsonify({"error": "Request has no active stage."}), 400

        current_stage = int(current_stage)
        if current_stage != actor_position_id:
            return jsonify({"error": "Only the current assigned stage can send this back."}), 403

        _reviewers, _approvers, workflow = get_effective_workflow_positions(
            cursor,
            request_id=request_id,
            request_type_id=req["request_type_id"],
        )

        if not workflow:
            return jsonify({"error": "Workflow is not configured for this request."}), 400

        try:
            idx = workflow.index(current_stage)
        except ValueError:
            return jsonify({"error": "Current stage is not part of this workflow."}), 400

        if idx <= 0:
            return jsonify({"error": "Request is already at the first workflow stage."}), 400

        target_stage = workflow[idx - 1]

        cursor.execute(
            "SELECT status_id FROM request_status WHERE status_name='PENDING' LIMIT 1"
        )
        pending_row = cursor.fetchone()
        pending_status_id = pending_row["status_id"] if pending_row else 1

        cursor.execute(
            "SELECT position_name FROM positions WHERE position_id=%s LIMIT 1",
            (target_stage,),
        )
        target_pos_row = cursor.fetchone() or {}
        if not target_pos_row:
            return jsonify({"error": "Target workflow stage is invalid. Please update workflow settings."}), 400
        target_position_name = target_pos_row.get("position_name") or f"Position {target_stage}"

        cursor.execute(
            """
            UPDATE requests
            SET status_id = %s,
                stage_position_id = %s
            WHERE request_id = %s AND company_id = %s
        """,
            (pending_status_id, target_stage, request_id, company_id),
        )

        action_message = f"Sent back to {target_position_name}. Note: {note}"

        # Keep send-back note compatible with legacy varchar(message) schemas.
        try:
            cursor.execute("SHOW COLUMNS FROM request_actions LIKE 'message'")
            msg_col = cursor.fetchone() or {}
            msg_type = str(msg_col.get("Type") or msg_col.get("type") or "")
            msg_len_match = re.search(r"varchar\((\d+)\)", msg_type, flags=re.IGNORECASE)
            if msg_len_match:
                max_len = int(msg_len_match.group(1))
                if len(action_message) > max_len:
                    action_message = action_message[:max_len]
        except Exception:
            pass

        action_candidates = ["SENT_BACK", "IN_PROGRESS"]

        # Prefer valid enum values when action column is enum in older databases.
        try:
            cursor.execute("SHOW COLUMNS FROM request_actions LIKE 'action'")
            action_col = cursor.fetchone() or {}
            action_type = str(action_col.get("Type") or action_col.get("type") or "")
            enum_values = re.findall(r"'([^']+)'", action_type)
            if enum_values:
                ordered = []
                for value in ["SENT_BACK", "IN_PROGRESS"]:
                    if value in enum_values and value not in ordered:
                        ordered.append(value)
                for value in enum_values:
                    if value not in ordered:
                        ordered.append(value)
                if ordered:
                    action_candidates = ordered
        except Exception:
            pass

        try:
            cursor.execute(
                """
                SELECT action
                FROM request_actions
                WHERE action IS NOT NULL
                ORDER BY action_id DESC
                LIMIT 10
                """
            )
            recent_rows = cursor.fetchall() or []
            for row in recent_rows:
                value = str(row.get("action") or "").strip()
                if value and value not in action_candidates:
                    action_candidates.append(value)
        except Exception:
            pass

        inserted_action = None
        last_insert_error = None

        for action_value in action_candidates:
            try:
                cursor.execute(
                    """
                    INSERT INTO request_actions
                    (request_id, actor_user_id, actor_position_id, actor_email, action, message)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        request_id,
                        actor_user_id,
                        actor_position_id,
                        actor_email,
                        action_value,
                        action_message,
                    ),
                )
                inserted_action = action_value
                break
            except mysql.connector.Error as action_err:
                last_insert_error = action_err

        if inserted_action is None:
            # Do not block state transition if legacy action schema refuses all values.
            logger.warning(
                "send_back_request log insert skipped; request_id=%s actor_position_id=%s error=%s",
                request_id,
                actor_position_id,
                str(last_insert_error),
            )

        conn.commit()
        return jsonify({
            "success": True,
            "message": f"Request sent back to {target_position_name}.",
        })
    except mysql.connector.Error as db_err:
        conn.rollback()
        logger.exception("send_back_request DB error")
        return jsonify({"error": f"Database error: {db_err}"}), 500
    except Exception:
        conn.rollback()
        logger.exception("send_back_request failed")
        return jsonify({"error": "Failed to send back request."}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/it/user/update", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")

def update_user_role():
    payload = request.get_json(silent=True) or {}
    user_id = payload.get("user_id")
    new_role = (payload.get("role") or "").strip()
    new_position_id = payload.get("position_id")
    new_dept_id = payload.get("dept_id")

    if not user_id or not new_role:
        return jsonify({"success": False, "error": "Missing user_id or role"}), 400

    # allow only known roles (adjust to your system)
    allowed_roles = {"User", "Reviewer", "Dean", "Admin", "AssistantAdmin", "SuperAdmin", "IT"}
    if new_role not in allowed_roles:
        return jsonify({"success": False, "error": "Invalid role"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET role=%s,
                position_id=%s,
                dept_id=%s
            WHERE user_id=%s
            """,
            (new_role, new_position_id, new_dept_id, int(user_id)),
        )
        conn.commit()
        return jsonify({"success": True})
    except Exception:
        conn.rollback()
        logger.exception("update_user_role failed")
        return jsonify({"success": False, "error": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/it/user/<int:user_id>/ban", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_ban_user(user_id):
    action = (request.form.get("action") or "ban").strip().lower()
    if action not in {"ban", "unban"}:
        flash("Invalid account action.", "danger")
        return redirect(url_for("it_dashboard"))

    ban_value = 1 if action == "ban" else 0

    actor_user_id = int(session.get("user_id") or 0)
    if actor_user_id == user_id and ban_value == 1:
        flash("You cannot ban your own account.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_user_account_control_schema(cursor, conn)

        cursor.execute(
            """
            SELECT user_id, email, COALESCE(is_banned, 0) AS is_banned, COALESCE(is_deleted, 0) AS is_deleted
            FROM users
            WHERE user_id=%s
            LIMIT 1
            """,
            (user_id,),
        )
        target = cursor.fetchone()
        if not target:
            flash("User account not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if int(target.get("is_deleted") or 0) == 1:
            flash("Cannot change ban status of a deleted account.", "warning")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "UPDATE users SET is_banned=%s WHERE user_id=%s",
            (ban_value, user_id),
        )

        title = "Account Banned" if ban_value == 1 else "Account Unbanned"
        verb = "banned" if ban_value == 1 else "unbanned"
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                title,
                f"{session.get('email')} {verb} account {target.get('email')} (user_id={user_id}).",
            ),
        )

        conn.commit()
        flash(f"Account {verb} successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_ban_user failed")
        flash("Failed to update account status.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/user/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_delete_user(user_id):
    actor_user_id = int(session.get("user_id") or 0)
    if actor_user_id == user_id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_user_account_control_schema(cursor, conn)

        cursor.execute(
            """
            SELECT user_id, email, COALESCE(is_deleted, 0) AS is_deleted
            FROM users
            WHERE user_id=%s
            LIMIT 1
            """,
            (user_id,),
        )
        target = cursor.fetchone()
        if not target:
            flash("User account not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if int(target.get("is_deleted") or 0) == 1:
            flash("Account is already deleted.", "warning")
            return redirect(url_for("it_dashboard"))

        tombstone_email = f"deleted+{user_id}+{int(time.time())}@deleted.local"

        cursor.execute(
            """
            UPDATE users
            SET is_deleted = 1,
                is_banned = 1,
                deleted_at = NOW(),
                email = %s
            WHERE user_id = %s
            """,
            (tombstone_email, user_id),
        )

        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Account Deleted",
                f"{session.get('email')} deleted account {target.get('email')} (user_id={user_id}).",
            ),
        )

        conn.commit()
        flash("Account deleted successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_delete_user failed")
        flash("Failed to delete account.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/department/<int:dept_id>/update", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_update_department(dept_id):
    dept_name = str(request.form.get("dept_name") or "").strip()
    if not dept_name:
        flash("Department name is required.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1",
            (dept_id, company_id),
        )
        existing = cursor.fetchone()
        if not existing:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id FROM departments WHERE company_id=%s AND LOWER(TRIM(dept_name))=LOWER(TRIM(%s)) AND dept_id<>%s LIMIT 1",
            (company_id, dept_name, dept_id),
        )
        duplicate = cursor.fetchone()
        if duplicate:
            flash("Department name already exists.", "warning")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "UPDATE departments SET dept_name=%s WHERE dept_id=%s",
            (dept_name, dept_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Department Updated",
                f"{session.get('email')} renamed department '{existing.get('dept_name')}' to '{dept_name}'.",
            ),
        )
        conn.commit()
        flash("Department updated successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_update_department failed")
        flash("Failed to update department.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/department/<int:dept_id>/head", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_set_department_head(dept_id):
    head_user_id_raw = str(request.form.get("head_user_id") or "").strip()

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1",
            (dept_id, company_id),
        )
        dept = cursor.fetchone()
        if not dept:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if not head_user_id_raw:
            cursor.execute("DELETE FROM department_heads WHERE dept_id=%s", (dept_id,))
            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "Department Head Updated",
                    f"{session.get('email')} cleared head assignment for department '{dept.get('dept_name')}'.",
                ),
            )
            conn.commit()
            flash("Department head cleared.", "success")
            return redirect(url_for("it_dashboard"))

        try:
            head_user_id = int(head_user_id_raw)
        except (TypeError, ValueError):
            flash("Invalid head selection.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            SELECT user_id, email
            FROM users
            WHERE user_id=%s
              AND dept_id=%s
                            AND company_id=%s
              AND COALESCE(is_deleted, 0)=0
              AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
            LIMIT 1
            """,
                        (head_user_id, dept_id, company_id),
        )
        head_user = cursor.fetchone()
        if not head_user:
            flash("Selected user must be an active member of this department.", "warning")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            INSERT INTO department_heads (dept_id, user_id)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE user_id=VALUES(user_id)
            """,
            (dept_id, head_user_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Department Head Updated",
                f"{session.get('email')} assigned {head_user.get('email')} as head of '{dept.get('dept_name')}'.",
            ),
        )
        conn.commit()
        flash("Department head updated successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_set_department_head failed")
        flash("Failed to update department head.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/department/<int:dept_id>/member/add", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_add_department_member(dept_id):
    user_id_raw = str(request.form.get("user_id") or "").strip()
    try:
        user_id = int(user_id_raw)
    except (TypeError, ValueError):
        flash("Invalid user selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1",
            (dept_id, company_id),
        )
        dept = cursor.fetchone()
        if not dept:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            SELECT
                user_id,
                email,
                dept_id,
                COALESCE(is_deleted, 0) AS is_deleted
            FROM users
                        WHERE user_id=%s
                            AND company_id=%s
            LIMIT 1
            """,
                        (user_id, company_id),
        )
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if int(user.get("is_deleted") or 0) == 1:
            flash("Cannot assign a deleted user.", "warning")
            return redirect(url_for("it_dashboard"))

        old_dept_id = user.get("dept_id")
        if old_dept_id is not None and int(old_dept_id) == int(dept_id):
            flash("User is already in this department.", "info")
            return redirect(url_for("it_dashboard"))

        cursor.execute("UPDATE users SET dept_id=%s WHERE user_id=%s", (dept_id, user_id))

        if old_dept_id is not None:
            cursor.execute(
                "DELETE FROM department_heads WHERE dept_id=%s AND user_id=%s",
                (old_dept_id, user_id),
            )

        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Department Member Added",
                f"{session.get('email')} assigned user {user.get('email')} to department '{dept.get('dept_name')}'.",
            ),
        )

        conn.commit()
        flash("User assigned to department successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_add_department_member failed")
        flash("Failed to assign user to department.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/department/<int:dept_id>/member/remove", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_remove_department_member(dept_id):
    user_id_raw = str(request.form.get("user_id") or "").strip()
    try:
        user_id = int(user_id_raw)
    except (TypeError, ValueError):
        flash("Invalid user selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1",
            (dept_id, company_id),
        )
        dept = cursor.fetchone()
        if not dept:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            SELECT
                user_id,
                email,
                dept_id,
                COALESCE(is_deleted, 0) AS is_deleted
            FROM users
                        WHERE user_id=%s
                            AND company_id=%s
            LIMIT 1
            """,
                        (user_id, company_id),
        )
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if int(user.get("is_deleted") or 0) == 1:
            flash("Cannot update a deleted user.", "warning")
            return redirect(url_for("it_dashboard"))

        current_dept_id = user.get("dept_id")
        if current_dept_id is None or int(current_dept_id) != int(dept_id):
            flash("User is not a member of this department.", "info")
            return redirect(url_for("it_dashboard"))

        cursor.execute("UPDATE users SET dept_id=NULL WHERE user_id=%s", (user_id,))
        cursor.execute(
            "DELETE FROM department_heads WHERE dept_id=%s AND user_id=%s",
            (dept_id, user_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Department Member Removed",
                f"{session.get('email')} removed user {user.get('email')} from department '{dept.get('dept_name')}'.",
            ),
        )

        conn.commit()
        flash("User removed from department successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_remove_department_member failed")
        flash("Failed to remove user from department. If dept_id is required in your database, reassign user to another department instead.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/finance-amount-team/member/add", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_add_finance_amount_editor_member():
    user_id_raw = str(request.form.get("user_id") or "").strip()
    try:
        user_id = int(user_id_raw)
    except (TypeError, ValueError):
        flash("Invalid user selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        ensure_finance_amount_editor_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            SELECT user_id, email, COALESCE(is_deleted, 0) AS is_deleted
            FROM users
            WHERE user_id = %s AND company_id = %s
            LIMIT 1
            """,
            (user_id, company_id),
        )
        user_row = cursor.fetchone() or {}
        if not user_row:
            flash("User not found.", "danger")
            return redirect(url_for("it_dashboard"))

        if int(user_row.get("is_deleted") or 0) == 1:
            flash("Cannot add deleted user.", "warning")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            """
            INSERT INTO finance_amount_editors (company_id, user_id, added_by_email)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE added_by_email = VALUES(added_by_email)
            """,
            (company_id, user_id, (session.get("email") or "").strip().lower() or None),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description, company_id, actor_email) VALUES (%s, %s, %s, %s)",
            (
                "Finance Amount Team Member Added",
                f"{session.get('email')} added {user_row.get('email')} to Finance Amount Editor team.",
                company_id,
                (session.get("email") or "").strip().lower() or None,
            ),
        )
        conn.commit()
        flash("Member added to Finance Amount Editor team.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_add_finance_amount_editor_member failed")
        flash("Failed to add team member.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/finance-amount-team/member/remove", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_remove_finance_amount_editor_member():
    user_id_raw = str(request.form.get("user_id") or "").strip()
    try:
        user_id = int(user_id_raw)
    except (TypeError, ValueError):
        flash("Invalid user selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_finance_amount_editor_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT COALESCE(email, '') AS email FROM users WHERE user_id = %s AND company_id = %s LIMIT 1",
            (user_id, company_id),
        )
        user_row = cursor.fetchone() or {}
        if not user_row:
            flash("User not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "DELETE FROM finance_amount_editors WHERE company_id = %s AND user_id = %s",
            (company_id, user_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description, company_id, actor_email) VALUES (%s, %s, %s, %s)",
            (
                "Finance Amount Team Member Removed",
                f"{session.get('email')} removed {user_row.get('email')} from Finance Amount Editor team.",
                company_id,
                (session.get("email") or "").strip().lower() or None,
            ),
        )
        conn.commit()
        flash("Member removed from Finance Amount Editor team.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_remove_finance_amount_editor_member failed")
        flash("Failed to remove team member.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))



@app.route("/it/approval-team/position/add", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_add_approval_team_position():
    pos_id_raw = str(request.form.get("position_id") or "").strip()
    try:
        pos_id = int(pos_id_raw)
    except (TypeError, ValueError):
        flash("Invalid position selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)
        ensure_it_approval_team_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT position_id FROM positions WHERE position_id = %s AND company_id = %s LIMIT 1",
            (pos_id, company_id),
        )
        if not cursor.fetchone():
            flash("Position not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "INSERT INTO it_approval_positions (company_id, position_id, added_by_email) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE added_by_email = VALUES(added_by_email)",
            (company_id, pos_id, (session.get("email") or "").strip().lower() or None),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description, company_id, actor_email) VALUES (%s, %s, %s, %s)",
            (
                "IT Approval Team Position Added",
                f"{session.get('email')} added position id {pos_id} to IT approval recipient list.",
                company_id,
                (session.get("email") or "").strip().lower() or None,
            ),
        )
        conn.commit()
        flash("Position added to approval recipient list.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_add_approval_team_position failed")
        flash("Failed to add position.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/approval-team/position/remove", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_remove_approval_team_position():
    pos_id_raw = str(request.form.get("position_id") or "").strip()
    try:
        pos_id = int(pos_id_raw)
    except (TypeError, ValueError):
        flash("Invalid position selection.", "danger")
        return redirect(url_for("it_dashboard"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_it_approval_team_schema(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "DELETE FROM it_approval_positions WHERE company_id = %s AND position_id = %s",
            (company_id, pos_id),
        )
        cursor.execute(
            "INSERT INTO activity_logs (title, description, company_id, actor_email) VALUES (%s, %s, %s, %s)",
            (
                "IT Approval Team Position Removed",
                f"{session.get('email')} removed position id {pos_id} from IT approval recipient list.",
                company_id,
                (session.get("email") or "").strip().lower() or None,
            ),
        )
        conn.commit()
        flash("Position removed from approval recipient list.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_remove_approval_team_position failed")
        flash("Failed to remove position.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/it/department/<int:dept_id>/delete", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_delete_department(dept_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1",
            (dept_id, company_id),
        )
        dept = cursor.fetchone()
        if not dept:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE dept_id=%s AND company_id=%s", (dept_id, company_id))
        member_count = int((cursor.fetchone() or {}).get("count") or 0)
        if member_count > 0:
            flash("Cannot delete department with assigned users. Reassign users first.", "warning")
            return redirect(url_for("it_dashboard"))

        cursor.execute("DELETE FROM department_heads WHERE dept_id=%s", (dept_id,))
        cursor.execute("DELETE FROM departments WHERE dept_id=%s", (dept_id,))
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            (
                "Department Deleted",
                f"{session.get('email')} deleted department '{dept.get('dept_name')}'.",
            ),
        )
        conn.commit()
        flash("Department deleted successfully.", "success")
    except Exception:
        conn.rollback()
        logger.exception("it_delete_department failed")
        flash("Failed to delete department.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))

@app.route("/create_user", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def create_user():
    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    dept_id = request.form["dept_id"]
    role_id = request.form["role_id"]
    position_id = request.form["position_id"]

    # Hash password using Argon2id (with fallback if unavailable).
    hashed_password = hash_user_password(password)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("Company context is missing.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT dept_id FROM departments WHERE dept_id=%s AND company_id=%s LIMIT 1", (dept_id, company_id))
        if not cursor.fetchone():
            flash("Invalid department for your organization.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT role_id FROM roles WHERE role_id=%s AND company_id=%s LIMIT 1", (role_id, company_id))
        if not cursor.fetchone():
            flash("Invalid role for your organization.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT position_id FROM positions WHERE position_id=%s AND company_id=%s LIMIT 1", (position_id, company_id))
        if not cursor.fetchone():
            flash("Invalid position for your organization.", "danger")
            return redirect(url_for("it_dashboard"))

        # Check if position is already assigned to an active user
        cursor.execute(
            """
            SELECT user_id FROM users
            WHERE position_id=%s AND company_id=%s
              AND COALESCE(is_deleted, 0) = 0
              AND COALESCE(is_banned, 0) = 0
            LIMIT 1
            """,
            (position_id, company_id)
        )
        if cursor.fetchone():
            flash("This position is already assigned to another user. One position can only be held by one user.", "danger")
            return redirect(url_for("it_dashboard"))

        #  Insert the New User
        query_user = """
            INSERT INTO users (email, password, dept_id, role_id, position_id, company_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(
            query_user, (email, hashed_password, dept_id, role_id, position_id, company_id)
        )

        #  Insert the Activity Log (The Notification)
        query_log = """
            INSERT INTO activity_logs (title, description) 
            VALUES (%s, %s)
        """
        log_title = "New Account Created"
        log_desc = f"Admin created a new account for {email}"

        cursor.execute(query_log, (log_title, log_desc))

        # Commit both changes at once
        conn.commit()
        flash("User created successfully!", "success")

    except mysql.connector.Error as e:
        conn.rollback()
        flash(f"Error creating user: {e}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/create_dept", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def create_dept():
    if request.method == "POST":
        dept_name = request.form["dept_name"]
        # dept_head = request.form.get('dept_head', '')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            ensure_tenant_schema(cursor, conn)
            _ensure_company_scoped_unique_name(cursor, "departments", "dept_name")
            company_id = ensure_session_company_context(cursor)
            if company_id <= 0:
                flash("Company context is missing.", "danger")
                return redirect(url_for("it_dashboard"))

            cursor.execute(
                "SELECT dept_id FROM departments WHERE company_id=%s AND LOWER(TRIM(dept_name)) = LOWER(TRIM(%s)) LIMIT 1",
                (company_id, dept_name),
            )
            if cursor.fetchone():
                flash(f"Department '{dept_name}' already exists.", "danger")
                return redirect(url_for("it_dashboard"))

            # Create the department. If a legacy global unique index on dept_name still exists,
            # repair it to company-scoped uniqueness and retry once.
            try:
                cursor.execute(
                    "INSERT INTO departments (dept_name, company_id) VALUES (%s, %s)",
                    (dept_name, company_id),
                )
            except mysql.connector.Error as insert_err:
                is_duplicate_name_error = (
                    getattr(insert_err, "errno", None) == 1062
                    and "dept_name" in str(insert_err).lower()
                )
                if not is_duplicate_name_error:
                    raise

                _ensure_company_scoped_unique_name(cursor, "departments", "dept_name")
                cursor.execute(
                    "INSERT INTO departments (dept_name, company_id) VALUES (%s, %s)",
                    (dept_name, company_id),
                )

            # Create the Log
            log_title = "Department Created"
            log_desc = f"New department '{dept_name}' added to the system."

            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (log_title, log_desc),
            )

            conn.commit()
            flash("Department added successfully!", "success")

        except mysql.connector.Error as e:
            conn.rollback()
            flash(f"Error adding department: {e}", "danger")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("it_dashboard"))


@app.route("/api/user-profile", methods=["GET"])
def api_user_profile():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"})

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch detailed profile info
        query = """
            SELECT u.email, d.dept_name, p.position_name, r.role_name
            FROM users u
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = %s
        """
        cursor.execute(query, (session["email"],))
        data = cursor.fetchone()
        if data:
            return jsonify(data)
        return jsonify({"error": "User not found"})
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request-types", methods=["GET"])
def api_request_types():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        cursor.execute(
            "SELECT request_type_id, type_name FROM request_types WHERE company_id = %s",
            (company_id,),
        )
        data = cursor.fetchall()
        return jsonify(data)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request-types/<int:request_type_id>/form-schema", methods=["GET", "POST"])
@csrf.exempt
def api_request_type_form_schema(request_type_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        session_email = str(session.get("email") or "").strip().lower()
        if not session_email:
            session_user_id = session.get("user_id")
            if session_user_id:
                cursor.execute(
                    """
                    SELECT
                        LOWER(TRIM(u.email)) AS email,
                        COALESCE(r.role_name, '') AS role_name
                    FROM users u
                    LEFT JOIN roles r ON r.role_id = u.role_id
                    WHERE u.user_id = %s
                    LIMIT 1
                    """,
                    (session_user_id,),
                )
                session_user = cursor.fetchone() or {}
                recovered_email = str(session_user.get("email") or "").strip().lower()
                if recovered_email:
                    session["email"] = recovered_email
                    session_email = recovered_email
                    if not str(session.get("role") or "").strip():
                        recovered_role = str(session_user.get("role_name") or "").strip()
                        if recovered_role:
                            session["role"] = recovered_role

        if not session_email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        ensure_request_type_form_schema_table(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cursor.execute(
            """
            SELECT request_type_id, type_name, template_mode, template_file
            FROM request_types
            WHERE request_type_id = %s AND company_id = %s
            LIMIT 1
            """,
            (request_type_id, company_id),
        )
        request_type = cursor.fetchone()
        if not request_type:
            return jsonify({"success": False, "error": "Request type not found"}), 404

        template_mode = str(request_type.get("template_mode") or "").strip().upper()
        if template_mode != "FILLABLE":
            return jsonify(
                {
                    "success": False,
                    "error": "This request type does not use a fillable form.",
                    "template_mode": template_mode,
                }
            ), 400

        if request.method == "POST":
            if not can_manage_request_types(cursor):
                return jsonify({"success": False, "error": "Forbidden"}), 403

            payload = request.get_json(silent=True) or {}
            raw_schema = payload.get("schema") if isinstance(payload, dict) else None
            if raw_schema is None:
                raw_schema = payload
            if raw_schema in (None, ""):
                raw_schema = {"version": 1, "total_formula": "", "blocks": []}

            try:
                normalized_schema = normalize_request_type_form_schema(raw_schema)
            except ValueError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

            cursor.execute(
                """
                INSERT INTO request_type_form_schemas (request_type_id, schema_json)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                    schema_json = VALUES(schema_json),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (request_type_id, json.dumps(normalized_schema, ensure_ascii=True)),
            )
            conn.commit()
            return jsonify({"success": True, "message": "Field mapping saved.", "schema": normalized_schema})

        schema = get_request_type_fillable_schema(cursor, request_type_id)
        template_fields = extract_template_field_names(request_type.get("template_file"))
        template_page_count = 1
        template_blob = request_type.get("template_file")
        if template_blob:
            try:
                template_page_count = max(1, len(_PdfReader(BytesIO(template_blob)).pages))
            except Exception:
                template_page_count = 1
        # Fetch company positions for mapper UI
        cursor.execute("SELECT position_id, position_name FROM positions WHERE company_id = %s ORDER BY position_name ASC", (company_id,))
        pos_rows = cursor.fetchall() or []
        positions = [{"position_id": r.get("position_id"), "position_name": r.get("position_name")} for r in pos_rows]

        return jsonify(
            {
                "success": True,
                "request_type_id": request_type_id,
                "type_name": request_type.get("type_name"),
                "template_mode": template_mode,
                "schema": schema,
                "template_fields": template_fields,
                "template_page_count": template_page_count,
                "positions": positions,
            }
        )
    except Exception:
        logger.exception("api_request_type_form_schema failed")
        return jsonify({"success": False, "error": "Failed to load form schema"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request-types/<int:request_type_id>/filled-preview", methods=["POST"])
def api_request_type_filled_preview(request_type_id):
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    raw_form_payload = payload.get("payload") if isinstance(payload, dict) else {}
    if not isinstance(raw_form_payload, dict):
        raw_form_payload = {}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_request_type_form_schema_table(cursor, conn)

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        cursor.execute(
            """
            SELECT request_type_id, template_mode, template_filename, template_file
            FROM request_types
            WHERE request_type_id = %s AND company_id = %s
            LIMIT 1
            """,
            (request_type_id, company_id),
        )
        row = cursor.fetchone() or {}
        if not row:
            return jsonify({"success": False, "error": "Request type not found"}), 404

        template_blob = row.get("template_file")
        if not template_blob:
            return jsonify({"success": False, "error": "Template PDF is missing"}), 404

        template_mode = str(row.get("template_mode") or "").strip().upper()
        if template_mode != "FILLABLE":
            filename = (row.get("template_filename") or "").strip() or f"request_type_{request_type_id}_preview.pdf"
            if not filename.lower().endswith(".pdf"):
                filename = f"{filename}.pdf"

            resp = send_file(
                BytesIO(template_blob),
                mimetype="application/pdf",
                as_attachment=False,
                download_name=filename,
            )
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
            return resp

        schema = get_request_type_fillable_schema(cursor, request_type_id)
        cleaned_payload, computed_total, has_total_sources = _build_preview_fill_payload_and_total(
            schema,
            raw_form_payload,
        )

        pdf_bytes = build_filled_pdf_from_submission(
            template_blob,
            schema,
            cleaned_payload,
            total_amount=computed_total if has_total_sources else None,
        )

        filename = (row.get("template_filename") or "").strip() or f"request_type_{request_type_id}_preview.pdf"
        if not filename.lower().endswith(".pdf"):
            filename = f"{filename}.pdf"

        resp = send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=False,
            download_name=filename,
        )
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    except Exception:
        logger.exception("api_request_type_filled_preview failed")
        return jsonify({"success": False, "error": "Failed to generate template preview"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/request-type-form-builder", methods=["GET"])
@login_required
def request_type_form_builder_page():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if not can_manage_request_types(cursor):
            flash("You do not have permission to manage request types.", "danger")
            return redirect(url_for("admin_dashboard"))
    finally:
        cursor.close()
        conn.close()

    return render_template("request_type_form_builder.html")


@app.route("/request-type-field-mapper/<int:request_type_id>", methods=["GET"])
@login_required
def request_type_field_mapper_page(request_type_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if not can_manage_request_types(cursor):
            flash("You do not have permission to manage request types.", "danger")
            return redirect(url_for("admin_dashboard"))

        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            flash("No company context found.", "danger")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            SELECT request_type_id, type_name, template_mode
            FROM request_types
            WHERE request_type_id = %s AND company_id = %s
            LIMIT 1
            """,
            (request_type_id, company_id),
        )
        row = cursor.fetchone()
        if not row:
            flash("Request type not found.", "danger")
            return redirect(url_for("admin_dashboard"))

        if str(row.get("template_mode") or "").strip().upper() != "FILLABLE":
            flash("Field mapper is available only for fillable request types.", "warning")
            return redirect(url_for("admin_dashboard"))

        return render_template(
            "request_type_field_mapper.html",
            request_type_id=request_type_id,
            request_type_name=row.get("type_name") or "Request Type",
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/requests", methods=["GET", "POST"])
def api_requests():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)
        company_id = ensure_session_company_context(cursor)
        if company_id <= 0:
            cursor.close()
            conn.close()
            return jsonify({"error": "No company context found"}), 403

        user_id = get_user_id_for_company(session.get("email"), company_id)
        if not user_id:
            cursor.close()
            conn.close()
            return jsonify({"error": "User ID not found"}), 404
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 500

    # Fetch All Requests
    if request.method == "GET":
        try:
            query = """
                    SELECT 
                        r.request_id,
                        rt.type_name,
                        r.wfor,
                        r.filename,
                        r.amount,
                        rs.status_name,
                        r.stage_position_id,
                        p.position_name,
                        CASE
                        WHEN rs.status_name = 'APPROVED' AND r.stage_position_id IS NULL THEN '-'
                        WHEN rs.status_name = 'REJECTED' THEN '-'
                        WHEN r.stage_position_id IS NULL AND rs.status_name = 'PENDING' THEN 'Waiting for Assignment'

                        ELSE p.position_name
                        END AS current_stage_label,
                        r.rejection_message,
                        r.created_at
                    FROM requests r
                    JOIN request_types rt ON r.request_type_id = rt.request_type_id
                    JOIN request_status rs ON r.status_id = rs.status_id
                    LEFT JOIN positions p ON r.stage_position_id = p.position_id
                    WHERE r.user_id = %s
                      AND r.company_id = %s
                    ORDER BY r.created_at DESC
                    """

            cursor.execute(query, (user_id, company_id))
            requests_data = cursor.fetchall()
            return jsonify(requests_data)
        except Exception as e:
            return jsonify({"error": str(e)})
        finally:
            cursor.close()
            conn.close()

    # Create New Request
    if request.method == "POST":
        try:
            role_name = (session.get("role") or "").strip()
            position_name = (session.get("position") or "").strip()
            can_request_budget = can_use_secretary_budget_fields(role_name, position_name)
            requests_ok, requests_msg = check_company_request_capacity(cursor, company_id)
            if not requests_ok:
                return jsonify({"error": requests_msg}), 403

            # Handle JSON
            req_type_id_raw = (request.form.get("request_type_id") or "").strip()
            template_data_json = (request.form.get("template_data_json") or "").strip()
            amount_raw = (
                request.form.get("template_total")
                or request.form.get("amount")
                or ""
            ).strip()
            total_amount_scope = str(request.form.get("total_apply_scope") or "first").strip().lower()
            if total_amount_scope not in {"first", "all", "specific"}:
                total_amount_scope = "first"

            total_amount_template_page = None
            if total_amount_scope == "specific":
                raw_total_page = (request.form.get("total_apply_template_page") or "").strip()
                if raw_total_page:
                    try:
                        parsed_total_page = int(raw_total_page)
                        if parsed_total_page > 0:
                            total_amount_template_page = parsed_total_page
                    except (TypeError, ValueError):
                        total_amount_template_page = None
            request_budget = normalize_request_budget(request.form.get("request_budget"))
            request_department = (session.get("dept") or "").strip()
            request_action = str(request.form.get("request_action") or "submit").strip().lower()
            is_draft = request_action == "draft"
            wfor = request_budget

            if not req_type_id_raw:
                return jsonify({"error": "Request Type ID is required"}), 400

            try:
                req_type_id = int(req_type_id_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid Request Type ID"}), 400

            # Handle File
            if "attachment" in request.files:
                file = request.files["attachment"]
                filename = secure_filename(file.filename)
                file_data = file.read()
            else:
                # Fallback if no file uploaded
                filename = request.form.get("filename")
                file_data = None

            ensure_request_type_form_schema_table(cursor, conn)
            ensure_request_form_submission_table(cursor, conn)
            ensure_budget_request_schema(cursor, conn)

            if can_request_budget and not is_draft:
                if not request_budget:
                    return jsonify({"error": "Request budget is required"}), 400

                if not request_department:
                    return jsonify({"error": "Your account has no assigned department. Please contact admin."}), 400

                cursor.execute(
                    "SELECT dept_name FROM departments WHERE dept_name = %s AND company_id = %s LIMIT 1",
                    (request_department, company_id),
                )
                if not (cursor.fetchone() or {}).get("dept_name"):
                    return jsonify({"error": "Invalid target department selected"}), 400

            cursor.execute(
                """
                SELECT request_type_id, template_mode, template_filename, template_file
                FROM request_types
                WHERE request_type_id = %s AND company_id = %s
                LIMIT 1
                """,
                (req_type_id, company_id),
            )
            request_type = cursor.fetchone()
            if not request_type:
                return jsonify({"error": "Request type not found"}), 400

            template_mode = str(request_type.get("template_mode") or "").strip().upper()
            request_type_template_name = (request_type.get("template_filename") or "").strip()
            request_type_template_blob = request_type.get("template_file")
            amount = None
            validated_template_payload_json = ""

            if template_mode == "FILLABLE":
                if not request_type_template_blob and not is_draft:
                    return jsonify({"error": "Representative template is missing for this fillable request type."}), 400

                if is_draft:
                    if template_data_json:
                        try:
                            parsed_payload = json.loads(template_data_json)
                            validated_template_payload_json = json.dumps(parsed_payload, ensure_ascii=True)
                        except (TypeError, ValueError, json.JSONDecodeError):
                            validated_template_payload_json = ""
                    if amount_raw:
                        try:
                            amount = float(amount_raw)
                        except (TypeError, ValueError):
                            return jsonify({"error": "Invalid amount value"}), 400
                else:
                    schema = get_request_type_fillable_schema(cursor, req_type_id)
                    cleaned_payload, computed_total, has_total_sources, validation_error = validate_fillable_submission(
                        schema,
                        template_data_json,
                    )
                    if validation_error:
                        return jsonify({"error": validation_error}), 400

                    validated_template_payload_json = json.dumps(cleaned_payload, ensure_ascii=True)
                    if has_total_sources:
                        if amount_raw:
                            try:
                                amount = float(amount_raw)
                            except (TypeError, ValueError):
                                return jsonify({"error": "Invalid amount value"}), 400
                        else:
                            amount = float(computed_total)

                    if request_type_template_blob:
                        file_data = build_filled_pdf_from_submission(
                            request_type_template_blob,
                            schema,
                            cleaned_payload,
                            total_amount=computed_total if has_total_sources else None,
                            total_amount_scope=total_amount_scope,
                            total_amount_template_page=total_amount_template_page,
                        )
                        filename = request_type_template_name or f"request_type_{req_type_id}_template.pdf"

            if amount is None:
                if not amount_raw:
                    if is_draft:
                        amount = 0.0
                    else:
                        return jsonify({"error": "Amount is required"}), 400
                else:
                    try:
                        amount = float(amount_raw)
                    except (TypeError, ValueError):
                        return jsonify({"error": "Invalid amount value"}), 400

            if amount < 0:
                return jsonify({"error": "Amount cannot be negative"}), 400

            stage_position_id = None
            if not is_draft:
                # Find Approver
                cursor.execute(
                    """
                    SELECT position_id FROM request_type_approvers 
                    WHERE request_type_id = %s ORDER BY id ASC LIMIT 1
                """,
                    (req_type_id,),
                )
                approver = cursor.fetchone()

                if not approver:
                    return (
                        jsonify({"error": "No approver configured for this request type"}),
                        400,
                    )

                stage_position_id = approver["position_id"]

            target_status_name = "DRAFT" if is_draft else "PENDING"
            cursor.execute(
                "SELECT status_id FROM request_status WHERE UPPER(status_name)=%s LIMIT 1",
                (target_status_name,),
            )
            status_row = cursor.fetchone() or {}
            status_id = status_row.get("status_id")

            if status_id is None and is_draft:
                cursor.execute("INSERT INTO request_status (status_name) VALUES ('DRAFT')")
                status_id = cursor.lastrowid

            if status_id is None:
                return jsonify({"error": f"{target_status_name.title()} status not configured in DB"}), 500

            if not wfor:
                try:
                    cursor.execute(
                        """
                        SELECT wfor
                        FROM request_types
                        WHERE request_type_id = %s AND company_id = %s
                        LIMIT 1
                        """,
                            (req_type_id, company_id),
                    )
                    request_type_row = cursor.fetchone() or {}
                    wfor = (request_type_row.get("wfor") or "").strip()
                except Exception:
                    try:
                        cursor.execute(
                            """
                            SELECT `for` AS wfor
                            FROM request_types
                            WHERE request_type_id = %s AND company_id = %s
                            LIMIT 1
                            """,
                            (req_type_id, company_id),
                        )
                        request_type_row = cursor.fetchone() or {}
                        wfor = (request_type_row.get("wfor") or "").strip()
                    except Exception:
                        wfor = ""

            if not wfor:
                wfor = "General Request"

            cursor.execute(
                """
                INSERT INTO requests (request_type_id, user_id, wfor, filename, attachment, amount, status_id, stage_position_id, company_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """,
                (
                    req_type_id,
                    user_id,
                    wfor,
                    filename,
                    file_data,
                    amount,
                    status_id,
                    stage_position_id,
                    company_id,
                ),
            )

            request_id = cursor.lastrowid

            if can_request_budget and request_budget and request_department:
                cursor.execute(
                    """
                    INSERT INTO request_budget_metadata (request_id, budget_type, target_department, created_by_email)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        budget_type = VALUES(budget_type),
                        target_department = VALUES(target_department),
                        created_by_email = VALUES(created_by_email),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (request_id, request_budget, request_department, (session.get("email") or "").strip().lower()),
                )
            if validated_template_payload_json:
                cursor.execute(
                    """
                    INSERT INTO request_form_submissions (request_id, request_type_id, form_data_json)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        form_data_json = VALUES(form_data_json),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (request_id, req_type_id, validated_template_payload_json),
                )

            conn.commit()
            return jsonify({"message": "Draft request saved successfully" if is_draft else "Request created successfully", "saved_as": "draft" if is_draft else "submitted"}), 201

        except Exception as e:
            print(f"Error creating request: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

@app.route("/api/request/<int:request_id>/complete", methods=["POST"])
def mark_request_completed(request_id):

    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get request owner + current status
        cursor.execute("""
            SELECT r.user_id, s.status_name
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.request_id=%s
        """, (request_id,))
        req = cursor.fetchone()

        if not req:
            return jsonify({"error": "Request not found"}), 404

        user_id = session.get("user_id")

        # ONLY OWNER CAN COMPLETE
        if req["user_id"] != user_id:
            return jsonify({"error": "Only requester can complete"}), 403

        #  must be IN PROGRESS first
        if (req["status_name"] or "").upper() != "IN PROGRESS":
            return jsonify({"error": "Request not in progress"}), 400

        # get COMPLETED status id
        cursor.execute("""
            SELECT status_id FROM request_status
            WHERE status_name='COMPLETED'
        """)
        status_id = cursor.fetchone()["status_id"]

        # update request
        cursor.execute("""
            UPDATE requests
            SET status_id=%s,
                stage_position_id=NULL
            WHERE request_id=%s
        """, (status_id, request_id))

        # activity log
        cursor.execute("""
            INSERT INTO request_actions
            (request_id, actor_user_id, actor_position_id, actor_email, action)
            VALUES (%s,%s,%s,%s,'COMPLETED')
        """, (
            request_id,
            session.get("user_id"),
            session.get("position_id"),
            session.get("email"),
        ))

        conn.commit()

        return jsonify({"message": "Request marked as COMPLETED"})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/api/request/<int:request_id>/admin-complete", methods=["POST"])
def admin_complete_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = (session.get("role") or "").strip()
    pos_name = (session.get("position") or "").strip().lower()
    is_purchasing = ("purchasing" in pos_name)
    actor_can_release_budget = can_release_budget_on_completion(role, session.get("position"))

    # allow Admin/AssistantAdmin/SuperAdmin + Purchasing
    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"] and not is_purchasing:
        return jsonify({"error": "Forbidden"}), 403

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # must be IN PROGRESS
        cur.execute("""
            SELECT r.request_id, s.status_name
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.request_id = %s
            LIMIT 1
        """, (request_id,))
        req = cur.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        if (req["status_name"] or "").upper() != "IN PROGRESS":
            return jsonify({"error": "Request must be IN PROGRESS first"}), 400


        # get PENDING_USER status id
        cur.execute("""
            SELECT status_id FROM request_status
            WHERE status_name = 'PENDING_USER'
            LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Status PENDING_USER not configured"}), 500
        pending_id = row["status_id"]

        # update request -> waiting for user confirmation
        cur.execute("""
            UPDATE requests
            SET status_id=%s
            WHERE request_id=%s
        """, (pending_id, request_id))

        cur.execute("""
            UPDATE requests
            SET status_id=%s,
                stage_position_id=NULL
            WHERE request_id=%s
        """, (pending_id, request_id))
        # insert admin completion marker
        cur.execute("""
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'ADMIN_COMPLETED', NULL)
        """, (
            request_id,
            session.get("user_id"),
            session.get("position_id"),
            session.get("email"),
        ))

        # optional activity log (same style you use elsewhere)
        try:
            cur.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (
                    "Admin Completed",
                    f"REQ#{request_id} marked admin-completed by {session.get('email')} (pos_id={session.get('position_id')}).",
                ),
            )
        except Exception:
            pass

        xendit_result = {"processed": False, "reason": "release_actor_required"}
        message = "Admin marked completed. Waiting for user confirmation."

        if actor_can_release_budget:
            xendit_result = process_budget_request_xendit(cur, conn, request_id)
            if xendit_result.get("already_processed"):
                message += " Budget was already processed previously."
            elif xendit_result.get("processed"):
                message += " Budget was processed via Xendit."
            elif xendit_result.get("reason") == "xendit_not_configured":
                message += " Xendit is not configured in this environment."
            elif xendit_result.get("reason") == "not_budget_request":
                message += " No budget transaction was required."
            else:
                message += " Budget transaction needs manual follow-up."
        else:
            message += " Budget processing requires Purchasing or Representative completion."

        conn.commit()
        return jsonify({"message": message, "xendit": xendit_result})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()
        
        
@app.route("/api/request/<int:request_id>/user-complete", methods=["POST"])
def user_complete_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = get_user_id(session["email"])

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # check owner + current status
        cur.execute("""
            SELECT r.user_id, s.status_name
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE r.request_id = %s
            LIMIT 1
        """, (request_id,))
        req = cur.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        if req["user_id"] != user_id:
            return jsonify({"error": "Only requester can complete"}), 403

        if (req["status_name"] or "").upper() != "PENDING_USER":
            return jsonify({"error": "Request is not waiting for user confirmation"}), 400
        # require admin-completed marker
        cur.execute("""
            SELECT 1
            FROM request_actions
            WHERE request_id = %s AND action = 'ADMIN_COMPLETED'
            LIMIT 1
        """, (request_id,))
        if not cur.fetchone():
            return jsonify({"error": "Admin has not marked completed yet"}), 400

        # set final COMPLETED status
        cur.execute("""
            SELECT status_id
            FROM request_status
            WHERE status_name = 'COMPLETED'
            LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "COMPLETED status missing in DB"}), 400
        completed_id = row["status_id"]

        cur.execute("""
            UPDATE requests
            SET status_id = %s, stage_position_id = NULL
            WHERE request_id = %s
        """, (completed_id, request_id))

        # log
        cur.execute("""
            INSERT INTO request_actions
                (request_id, actor_user_id, actor_position_id, actor_email, action, message)
            VALUES (%s, %s, %s, %s, 'COMPLETED', NULL)
        """, (
            request_id,
            session.get("user_id"),
            session.get("position_id"),
            session.get("email"),
        ))

        conn.commit()
        return jsonify({"message": "Request COMPLETED"})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/request/<int:request_id>/submit-draft", methods=["POST"])
def submit_draft_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role_name = (session.get("role") or "").strip()
    position_name = (session.get("position") or "").strip()
    can_request_budget = can_use_secretary_budget_fields(role_name, position_name)

    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cur, conn)
        ensure_saas_owner_schema(cur, conn)
        ensure_request_type_form_schema_table(cur, conn)
        ensure_request_form_submission_table(cur, conn)
        ensure_budget_request_schema(cur, conn)

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        user_id = get_user_id_for_company(session.get("email"), company_id)
        if not user_id:
            return jsonify({"error": "User ID not found"}), 404

        cur.execute(
            """
            SELECT
                r.request_id,
                r.user_id,
                r.request_type_id,
                r.wfor,
                r.filename,
                r.attachment,
                r.amount,
                rs.status_name
            FROM requests r
            JOIN request_status rs ON rs.status_id = r.status_id
            WHERE r.request_id = %s AND r.company_id = %s
            LIMIT 1
            """,
            (request_id, company_id),
        )
        draft_row = cur.fetchone() or {}
        if not draft_row:
            return jsonify({"error": "Draft request not found"}), 404

        if int(draft_row.get("user_id") or 0) != int(user_id):
            return jsonify({"error": "Only requester can submit this draft"}), 403

        if str(draft_row.get("status_name") or "").strip().upper() != "DRAFT":
            return jsonify({"error": "Only draft requests can be submitted with this action"}), 400

        request_type_id = int(draft_row.get("request_type_id") or 0)
        if request_type_id <= 0:
            return jsonify({"error": "Invalid request type for this draft"}), 400

        cur.execute(
            """
            SELECT request_type_id, template_mode, template_filename, template_file
            FROM request_types
            WHERE request_type_id = %s AND company_id = %s
            LIMIT 1
            """,
            (request_type_id, company_id),
        )
        request_type_row = cur.fetchone() or {}
        if not request_type_row:
            return jsonify({"error": "Request type not found"}), 400

        template_mode = str(request_type_row.get("template_mode") or "").strip().upper()
        request_type_template_name = (request_type_row.get("template_filename") or "").strip()
        request_type_template_blob = request_type_row.get("template_file")

        filename = draft_row.get("filename")
        file_blob = draft_row.get("attachment")
        amount = float(draft_row.get("amount") or 0)
        wfor = str(draft_row.get("wfor") or "").strip()

        request_budget = ""
        request_department = ""
        if can_request_budget:
            cur.execute(
                """
                SELECT budget_type, target_department
                FROM request_budget_metadata
                WHERE request_id = %s
                LIMIT 1
                """,
                (request_id,),
            )
            metadata_row = cur.fetchone() or {}
            request_budget = normalize_request_budget(metadata_row.get("budget_type"))
            request_department = str(metadata_row.get("target_department") or "").strip()

            if not request_budget or not request_department:
                return jsonify({"error": "Draft is missing request budget details. Edit draft and add Request Budget + Target Department."}), 400

            cur.execute(
                "SELECT dept_name FROM departments WHERE dept_name = %s AND company_id = %s LIMIT 1",
                (request_department, company_id),
            )
            if not (cur.fetchone() or {}).get("dept_name"):
                return jsonify({"error": "Draft target department is no longer valid."}), 400

        validated_template_payload_json = ""
        if template_mode == "FILLABLE":
            if not request_type_template_blob:
                return jsonify({"error": "Representative template is missing for this fillable request type."}), 400

            cur.execute(
                """
                SELECT form_data_json
                FROM request_form_submissions
                WHERE request_id = %s AND request_type_id = %s
                LIMIT 1
                """,
                (request_id, request_type_id),
            )
            submission_row = cur.fetchone() or {}
            template_data_json = str(submission_row.get("form_data_json") or "").strip()

            schema = get_request_type_fillable_schema(cur, request_type_id)
            cleaned_payload, computed_total, has_total_sources, validation_error = validate_fillable_submission(
                schema,
                template_data_json,
            )
            if validation_error:
                return jsonify({"error": validation_error}), 400

            validated_template_payload_json = json.dumps(cleaned_payload, ensure_ascii=True)

            if has_total_sources:
                amount = float(computed_total)

            file_blob = build_filled_pdf_from_submission(
                request_type_template_blob,
                schema,
                cleaned_payload,
                total_amount=computed_total if has_total_sources else None,
            )
            filename = request_type_template_name or f"request_type_{request_type_id}_template.pdf"

        if amount < 0:
            return jsonify({"error": "Amount cannot be negative"}), 400

        stage_position_id = None
        cur.execute(
            """
            SELECT position_id
            FROM request_type_reviewers
            WHERE request_type_id = %s
            ORDER BY order_no ASC
            LIMIT 1
            """,
            (request_type_id,),
        )
        reviewer = cur.fetchone()

        if reviewer:
            stage_position_id = reviewer["position_id"]
        else:
            cur.execute(
                """
                SELECT position_id
                FROM request_type_approvers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
                LIMIT 1
                """,
                (request_type_id,),
            )
            approver = cur.fetchone()
            stage_position_id = approver["position_id"] if approver else None

        if stage_position_id is None:
            return jsonify({"error": "No reviewers/approvers configured for this request type."}), 400

        cur.execute(
            "SELECT status_id FROM request_status WHERE UPPER(status_name) = 'PENDING' LIMIT 1"
        )
        pending_row = cur.fetchone() or {}
        pending_status_id = pending_row.get("status_id")
        if pending_status_id is None:
            return jsonify({"error": "PENDING status is not configured in DB."}), 500

        if not wfor:
            wfor = request_budget
        if not wfor:
            try:
                cur.execute(
                    """
                    SELECT wfor
                    FROM request_types
                    WHERE request_type_id = %s AND company_id = %s
                    LIMIT 1
                    """,
                    (request_type_id, company_id),
                )
                request_type_wfor_row = cur.fetchone() or {}
                wfor = (request_type_wfor_row.get("wfor") or "").strip()
            except Exception:
                try:
                    cur.execute(
                        """
                        SELECT `for` AS wfor
                        FROM request_types
                        WHERE request_type_id = %s AND company_id = %s
                        LIMIT 1
                        """,
                        (request_type_id, company_id),
                    )
                    request_type_wfor_row = cur.fetchone() or {}
                    wfor = (request_type_wfor_row.get("wfor") or "").strip()
                except Exception:
                    wfor = ""

        if not wfor:
            wfor = "General Request"

        cur.execute(
            """
            UPDATE requests
            SET
                wfor = %s,
                filename = %s,
                attachment = %s,
                amount = %s,
                status_id = %s,
                stage_position_id = %s
            WHERE request_id = %s AND company_id = %s
            """,
            (
                wfor,
                filename,
                file_blob,
                amount,
                pending_status_id,
                stage_position_id,
                request_id,
                company_id,
            ),
        )

        if validated_template_payload_json:
            cur.execute(
                """
                INSERT INTO request_form_submissions (request_id, request_type_id, form_data_json)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    form_data_json = VALUES(form_data_json),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (request_id, request_type_id, validated_template_payload_json),
            )

        conn.commit()

        coo_result = queue_coo_if_stage_is_coo(
            cur,
            conn,
            request_id,
            stage_position_id,
            requested_by_email=(session.get("email") or ""),
        )
        return jsonify(
            {
                "success": True,
                "message": "Draft submitted successfully.",
                "coo": coo_result,
            }
        ), 200

    except Exception as exc:
        conn.rollback()
        logger.exception("submit_draft_request failed")
        return jsonify({"error": "Failed to submit draft request."}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/request/<int:request_id>/draft-data", methods=["GET"])
def get_draft_request_data(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cur, conn)
        ensure_saas_owner_schema(cur, conn)
        ensure_request_form_submission_table(cur, conn)
        ensure_budget_request_schema(cur, conn)

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"error": "No company context found"}), 403

        user_id = get_user_id_for_company(session.get("email"), company_id)
        if not user_id:
            return jsonify({"error": "User ID not found"}), 404

        cur.execute(
            """
            SELECT
                r.request_id,
                r.user_id,
                r.request_type_id,
                r.wfor,
                r.amount,
                rs.status_name,
                rfs.form_data_json,
                rbm.budget_type,
                rbm.target_department
            FROM requests r
            JOIN request_status rs ON rs.status_id = r.status_id
            LEFT JOIN request_form_submissions rfs ON rfs.request_id = r.request_id
            LEFT JOIN request_budget_metadata rbm ON rbm.request_id = r.request_id
            WHERE r.request_id = %s AND r.company_id = %s
            LIMIT 1
            """,
            (request_id, company_id),
        )
        row = cur.fetchone() or {}
        if not row:
            return jsonify({"error": "Draft request not found"}), 404

        if int(row.get("user_id") or 0) != int(user_id):
            return jsonify({"error": "Only requester can access this draft"}), 403

        if str(row.get("status_name") or "").strip().upper() != "DRAFT":
            return jsonify({"error": "Only draft requests can be continued"}), 400

        return jsonify(
            {
                "success": True,
                "request_id": int(row.get("request_id") or 0),
                "request_type_id": int(row.get("request_type_id") or 0),
                "purpose": str(row.get("wfor") or "").strip(),
                "amount": float(row.get("amount") or 0),
                "template_data_json": str(row.get("form_data_json") or "").strip(),
                "request_budget": normalize_request_budget(row.get("budget_type")),
                "request_department": str(row.get("target_department") or "").strip(),
            }
        ), 200

    except Exception:
        logger.exception("get_draft_request_data failed")
        return jsonify({"error": "Failed to load draft request details."}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/request/<int:request_id>/cc-recipients", methods=["GET"])
@login_required
def get_cc_recipients(request_id):
    """Fetch approvers and reviewers for a specific request, excluding deleted users."""
    role = session.get("role")
    company_id = session.get("company_id")
    
    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        return jsonify({"error": "Forbidden"}), 403
    
    if not company_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # First, get the request and its request_type
        cursor.execute(
            """
            SELECT r.request_id, r.request_type_id
            FROM requests r
            WHERE r.request_id = %s AND r.user_id IN (
                SELECT user_id FROM users WHERE company_id = %s
            )
            LIMIT 1
            """,
            (request_id, company_id),
        )
        req = cursor.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        request_type_id = req.get("request_type_id")
        if not request_type_id:
            return jsonify({"recipients": []}), 200

        # Get all unique approvers for this request type
        cursor.execute(
            """
            SELECT DISTINCT u.email, u.user_id
            FROM request_type_approvers rta
            JOIN positions p ON rta.position_id = p.position_id
            JOIN users u ON p.position_id = u.position_id
            WHERE rta.request_type_id = %s
              AND p.company_id = %s
              AND u.company_id = %s
              AND COALESCE(u.is_deleted, 0) = 0
              AND COALESCE(u.is_banned, 0) = 0
            ORDER BY u.email ASC
            """,
            (request_type_id, company_id, company_id),
        )
        approver_emails = [row["email"] for row in cursor.fetchall()]

        # Get all unique reviewers for this request type
        cursor.execute(
            """
            SELECT DISTINCT u.email, u.user_id
            FROM request_type_reviewers rtr
            JOIN positions p ON rtr.position_id = p.position_id
            JOIN users u ON p.position_id = u.position_id
            WHERE rtr.request_type_id = %s
              AND p.company_id = %s
              AND u.company_id = %s
              AND COALESCE(u.is_deleted, 0) = 0
              AND COALESCE(u.is_banned, 0) = 0
            ORDER BY u.email ASC
            """,
            (request_type_id, company_id, company_id),
        )
        reviewer_emails = [row["email"] for row in cursor.fetchall()]

        # Merge and deduplicate
        all_emails = list(set(approver_emails + reviewer_emails))
        all_emails.sort()

        return jsonify({"recipients": all_emails}), 200

    except Exception as e:
        logger.exception("get_cc_recipients failed")
        return jsonify({"error": "Failed to fetch recipients"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/request/<int:request_id>/cc", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def cc_completed_request(request_id):
    role = session.get("role")
    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        return jsonify({"error": "Forbidden"})

    data = request.get_json() or {}
    to_emails = data.get("to_emails") or []
    note = (data.get("note") or "").strip()

    # validate list
    if not isinstance(to_emails, list) or len(to_emails) == 0:
        return jsonify({"error": "Select at least one recipient"})

    # normalize
    to_emails = [str(e).strip().lower() for e in to_emails if str(e).strip()]
    if len(to_emails) == 0:
        return jsonify({"error": "Select at least one recipient"})

    # allow any domain as long as email format is valid
    email_pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    invalid_emails = [e for e in to_emails if not email_pattern.match(e)]
    if invalid_emails:
        return jsonify({"error": f"Invalid recipient email(s): {', '.join(invalid_emails)}"}), 400

    if len(to_emails) > 100:
        return jsonify({"error": "Too many recipients. Maximum is 100."}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:

        # fetch request + attachment blob
        cursor.execute(
            """
            SELECT
                r.request_id,
                r.filename,
                r.attachment,
                a.signed_pdf,
                r.created_at,
                rs.status_name,
                r.stage_position_id,
                rt.type_name,
                u.email AS requester_email,
                d.dept_name
            FROM requests r
            JOIN request_status rs ON r.status_id = rs.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_annotations a ON a.request_id = r.request_id
            WHERE r.request_id = %s
            LIMIT 1
        """,
            (request_id,),
        )
        req = cursor.fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        # Only completed approved: APPROVED + stage_position_id IS NULL
        if (req["status_name"] or "").upper() != "APPROVED" or req[
            "stage_position_id"
        ] is not None:
            return jsonify({"error": "CC allowed only for completed APPROVED requests"})

        # Prefer annotated/signed PDF when available; fallback to original upload.
        attachment_blob = req.get("signed_pdf") or req.get("attachment")
        if not attachment_blob:
            return jsonify({"error": "This request has no uploaded attachment"})

        subject = f"CC: Completed Approved Request REQ#{req['request_id']}"
        body = (
            f"Good day,\n\n"
            f"This is a CC notification for a completed approved request.\n\n"
            f"Request ID: REQ#{req['request_id']}\n"
            f"Requester: {req.get('requester_email')}\n"
            f"Department: {req.get('dept_name')}\n"
            f"Request Type: {req.get('type_name')}\n"
            f"Attachment: {req.get('filename')}\n"
            f"Status: {req.get('status_name')}\n"
            f"Created At: {req.get('created_at')}\n\n"
            f"Note:\n{note if note else '-'}\n\n"
            f"This is an automated message. Do not reply."
            
        )

        sent, failed = [], []

        for email in to_emails:
            ok = send_cc_email_with_blob(
                receiver=email,
                subject=subject,
                body=body,
                filename=req.get("filename") or f"request_{request_id}_attachment",
                file_blob=attachment_blob,
            )
            (sent if ok else failed).append(email)

        if failed and sent:
            return jsonify(
                {"message": "CC partially sent", "sent": sent, "failed": failed}
            )

        if failed and not sent:
            return jsonify({"error": "Failed to send CC to all recipients"})

        return jsonify(
            {"message": f"CC sent to {len(sent)} recipient(s)", "sent": sent}
        )

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()


# Changed password
# Not yet in Front End will Implement Soon 
@app.route("/change_password", methods=["POST"])
def change_password():
    if "email" not in session:
        return redirect("/login")

    current_pass = request.form.get("current_password")
    new_pass = request.form.get("new_password")
    email = session["email"]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and verify_user_password(user["password"], current_pass):
            new_hash = hash_user_password(new_pass)
            cursor.execute(
                "UPDATE users SET password=%s WHERE email=%s", (new_hash, email)
            )
            conn.commit()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("udashboard"))


# delte account route
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "email" not in session:
        return redirect("/login")
    email = session["email"]

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Delete related data first
        cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))

        # Get user_id for request deletion
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        uid_row = cursor.fetchone()
        if uid_row:
            uid = uid_row["user_id"] if isinstance(uid_row, dict) else uid_row[0]
            cursor.execute("DELETE FROM requests WHERE user_id=%s", (uid,))
            cursor.execute("DELETE FROM users WHERE email=%s", (email,))
            conn.commit()
            session.clear()
            return redirect("/")
    except Exception as e:
        print("Delete error:", e)
        return redirect("/udashboard")
    finally:
        cursor.close()
        conn.close()

@app.route("/api/reports/chartdata")
def report_chart_data():
    if "email" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        if not can_view_reports(cur):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        company_id = ensure_session_company_context(cur)
        if company_id <= 0:
            return jsonify({"success": False, "error": "No company context found"}), 403

        # Monthly totals
        cur.execute("""
            SELECT DATE_FORMAT(created_at,'%b') AS month,
            COUNT(*) AS total
            FROM requests
            WHERE company_id = %s AND YEAR(created_at)=YEAR(NOW())
            GROUP BY MONTH(created_at)
            ORDER BY MONTH(created_at)
        """, (company_id,))

        rows = cur.fetchall()

        months=[r["month"] for r in rows]
        totals=[r["total"] for r in rows]


        # Request types
        cur.execute("""
            SELECT t.type_name,COUNT(*) as total
            FROM requests r
            JOIN request_types t ON r.request_type_id=t.request_type_id
            WHERE r.company_id = %s
            GROUP BY t.type_name
        """, (company_id,))

        types=cur.fetchall()

        type_names=[r["type_name"] for r in types]
        type_totals=[r["total"] for r in types]

        return jsonify({
            "success": True,
            "months":months,
            "monthTotals":totals,
            "types":type_names,
            "typeTotals":type_totals
        })
    except Exception:
        logger.exception("report_chart_data failed")
        return jsonify({
            "success": False,
            "message": "Failed to load chart data",
            "months": [],
            "monthTotals": [],
            "types": [],
            "typeTotals": []
        }), 500
    finally:
        cur.close()
        conn.close()

# Auth Routes (Signup/Login)
# Web Sign up
@app.route("/signup", methods=["GET", "POST"])
def signup():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    ensure_tenant_schema(cursor, conn)
    cursor.execute("SELECT company_id, company_name, company_slug FROM organizations WHERE is_active = 1 ORDER BY company_name ASC")
    companies = cursor.fetchall() or []
    selected_company_slug = (
        request.values.get("company_slug")
        or request.values.get("company")
        or ""
    ).strip().lower()
    if not selected_company_slug and companies:
        selected_company_slug = str(companies[0].get("company_slug") or "").strip().lower()

    def _departments_for_company_slug(company_slug):
        normalized_slug = (company_slug or "").strip().lower()
        if not normalized_slug:
            return []

        conn_local = get_connection()
        cursor_local = conn_local.cursor(dictionary=True)
        try:
            ensure_tenant_schema(cursor_local, conn_local)
            cursor_local.execute(
                "SELECT company_id FROM organizations WHERE company_slug = %s LIMIT 1",
                (normalized_slug,),
            )
            company_row = cursor_local.fetchone() or {}
            selected_company_id = int(company_row.get("company_id") or 0)
            if selected_company_id <= 0:
                return []

            cursor_local.execute(
                "SELECT dept_name FROM departments WHERE company_id = %s ORDER BY dept_name",
                (selected_company_id,),
            )
            return cursor_local.fetchall() or []
        finally:
            cursor_local.close()
            conn_local.close()

    departments = _departments_for_company_slug(selected_company_slug)
    selected_dept_name = (request.values.get("dept") or "").strip()
    cursor.close()
    conn.close()

    if request.method == "POST":
        if not session.get("otp_verified"):
            return render_template(
                "signup.html",
                message="Please verify OTP first",
                departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )

        e = request.form["email"].strip().lower()
        p = request.form["pass"]
        cp = request.form["cpass"]
        dept_name = request.form.get("dept", "").strip()
        company_slug = (request.form.get("company_slug") or "").strip().lower()
        selected_company_slug = company_slug or selected_company_slug
        departments = _departments_for_company_slug(selected_company_slug)
        selected_dept_name = dept_name

        if not company_slug:
            return render_template(
                "signup.html",
                message="Please select your company",
                departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )

        if not dept_name:
            return render_template(
                "signup.html",
                message="Please Select your Department",
                departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )
        if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", e):
            return render_template(
                "signup.html", message="Invalid email address", departments=departments
                , companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )
        if not is_allowed_system_email(e):
            return render_template(
                "signup.html",
                message=EMAIL_DOMAIN_HELPER_MESSAGE,
                departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )
        if (
            len(p) < 6
            or not any(c.isdigit() for c in p)
            or not any(c.isupper() for c in p)
        ):
            return render_template(
                "signup.html",
                message="Password: 6+ chars, 1 digit, 1 uppercase",
                departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )
        if p != cp:
            return render_template(
                "signup.html", message="Passwords do not match", departments=departments
                , companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            ensure_tenant_schema(cursor, conn)

            cursor.execute(
                "SELECT company_id, company_name FROM organizations WHERE company_slug = %s AND is_active = 1 LIMIT 1",
                (company_slug,),
            )
            company_row = cursor.fetchone() or {}
            company_id = int(company_row.get("company_id") or 0)
            company_name = (company_row.get("company_name") or "").strip()
            if company_id <= 0:
                return render_template(
                    "signup.html",
                    message="Invalid company selected",
                    departments=departments,
                    companies=companies,
                    selected_company_slug=selected_company_slug,
                    selected_dept_name=selected_dept_name,
                )

            if not _is_allowed_email_for_company(cursor, e, company_id=company_id):
                return render_template(
                    "signup.html",
                    message="Email domain is not allowed for this company",
                    departments=departments,
                    companies=companies,
                    selected_company_slug=selected_company_slug,
                    selected_dept_name=selected_dept_name,
                )

            cursor.execute("SELECT user_id FROM users WHERE email=%s", (e,))
            if cursor.fetchone():
                return render_template(
                    "signup.html",
                    message="Email already used please login",
                    departments=departments,
                    companies=companies,
                    selected_company_slug=selected_company_slug,
                    selected_dept_name=selected_dept_name,
                )

            ensure_saas_owner_schema(cursor, conn)
            seats_ok, seat_msg = check_company_user_seat_capacity(cursor, company_id)
            if not seats_ok:
                return render_template(
                    "signup.html",
                    message=seat_msg,
                    departments=departments,
                    companies=companies,
                    selected_company_slug=selected_company_slug,
                    selected_dept_name=selected_dept_name,
                )

            cursor.execute(
                "SELECT dept_id FROM departments WHERE dept_name=%s AND company_id = %s",
                (dept_name, company_id),
            )
            dept = cursor.fetchone()
            if not dept:
                return render_template(
                    "signup.html", message="Invalid department", departments=departments,
                    companies=companies,
                    selected_company_slug=selected_company_slug,
                    selected_dept_name=selected_dept_name,
                )
            dept_id = dept["dept_id"]

            # Default Role/Position
            cursor.execute("SELECT role_id FROM roles WHERE role_name='User' AND company_id=%s", (company_id,))
            role_row = cursor.fetchone()
            role_id = role_row["role_id"] if role_row else 1

            cursor.execute(
                "SELECT position_id FROM positions WHERE position_name='None' AND company_id=%s",
                (company_id,),
            )
            pos_row = cursor.fetchone()
            position_id = pos_row["position_id"] if pos_row else 1

            hp = hash_user_password(p)

            cursor.execute(
                "INSERT INTO users (email, password, dept_id, role_id, position_id, company_id) VALUES (%s,%s,%s,%s,%s,%s)",
                (e, hp, dept_id, role_id, position_id, company_id),
            )
            created_user_id = cursor.lastrowid
            conn.commit()

            log_auth_activity("Sign Up", e)

            session["email"] = e
            session["user_id"] = created_user_id
            session["dept"] = dept_name
            session["role"] = "User"
            session["role_id"] = role_id
            session["position"] = "None"
            session["position_id"] = position_id
            session["company_id"] = company_id
            session["company_name"] = company_name
            session.pop("otp_verified", None)

            return redirect("/udashboard")

        except Exception as ex:
            print("Signup error:", ex)
            return render_template(
                "signup.html", message="Something went wrong", departments=departments,
                companies=companies,
                selected_company_slug=selected_company_slug,
                selected_dept_name=selected_dept_name,
            )
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template(
        "signup.html",
        departments=departments,
        companies=companies,
        selected_company_slug=selected_company_slug,
        selected_dept_name=selected_dept_name,
    )


@app.route("/company/register", methods=["GET", "POST"])
def company_register():
    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip()
        admin_email = (request.form.get("admin_email") or "").strip().lower()
        password = request.form.get("pass") or ""
        confirm = request.form.get("cpass") or ""
        first_department = (request.form.get("first_department") or "General").strip() or "General"

        if not company_name:
            return render_template("company_register.html", message="Company name is required")
        if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", admin_email):
            return render_template("company_register.html", message="Invalid admin email")
        if not is_allowed_system_email(admin_email):
            return render_template("company_register.html", message=EMAIL_DOMAIN_HELPER_MESSAGE)
        if password != confirm:
            return render_template("company_register.html", message="Passwords do not match")
        if len(password) < 6 or not any(c.isdigit() for c in password) or not any(c.isupper() for c in password):
            return render_template("company_register.html", message="Password: 6+ chars, 1 digit, 1 uppercase")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            ensure_tenant_schema(cursor, conn)
            # Keep onboarding resilient even if app started before index migration logic.
            _ensure_company_scoped_unique_name(cursor, "roles", "role_name")
            _ensure_company_scoped_unique_name(cursor, "positions", "position_name")

            base_slug = _slugify_company_name(company_name)
            slug = base_slug
            suffix = 2
            while True:
                cursor.execute("SELECT company_id FROM organizations WHERE company_slug=%s LIMIT 1", (slug,))
                if not cursor.fetchone():
                    break
                slug = f"{base_slug}-{suffix}"
                suffix += 1

            cursor.execute(
                "INSERT INTO organizations (company_name, company_slug) VALUES (%s, %s)",
                (company_name, slug),
            )
            company_id = int(cursor.lastrowid)

            cursor.execute("INSERT INTO departments (dept_name, company_id) VALUES (%s, %s)", (first_department, company_id))
            dept_id = int(cursor.lastrowid)

            for role_name in ("SuperAdmin", "IT", "Admin", "AssistantAdmin", "User", "Reviewer", "Dean", "SBO"):
                cursor.execute(
                    "INSERT IGNORE INTO roles (role_name, company_id) VALUES (%s, %s)",
                    (role_name, company_id),
                )

            for position_name in ("Administrator", "IT", "None"):
                cursor.execute(
                    "INSERT IGNORE INTO positions (position_name, company_id) VALUES (%s, %s)",
                    (position_name, company_id),
                )

            cursor.execute("SELECT role_id FROM roles WHERE role_name='SuperAdmin' AND company_id=%s LIMIT 1", (company_id,))
            role_row = cursor.fetchone() or {}
            superadmin_role_id = int(role_row.get("role_id") or 0)

            cursor.execute("SELECT position_id FROM positions WHERE position_name='IT' AND company_id=%s LIMIT 1", (company_id,))
            pos_row = cursor.fetchone() or {}
            it_position_id = int(pos_row.get("position_id") or 0)

            if superadmin_role_id <= 0 or it_position_id <= 0:
                conn.rollback()
                return render_template("company_register.html", message="Failed to create tenant defaults")

            hashed_password = hash_user_password(password)
            cursor.execute(
                """
                INSERT INTO users (email, password, dept_id, role_id, position_id, company_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (admin_email, hashed_password, dept_id, superadmin_role_id, it_position_id, company_id),
            )
            admin_user_id = int(cursor.lastrowid)

            ensure_default_role_permissions(cursor, company_id)
            conn.commit()

            session["email"] = admin_email
            session["user_id"] = admin_user_id
            session["role"] = "SuperAdmin"
            session["role_id"] = superadmin_role_id
            session["position"] = "IT"
            session["position_id"] = it_position_id
            session["dept"] = first_department
            session["company_id"] = company_id
            session["company_name"] = company_name
            return redirect(url_for("it_dashboard"))
        except Exception:
            conn.rollback()
            logger.exception("company_register failed")
            return render_template("company_register.html", message="Failed to register company")
        finally:
            cursor.close()
            conn.close()

    return render_template("company_register.html")


# web login
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def login():
    template_ctx = {"dev_exception_email": DEV_EXCEPTION_EMAIL, "saas_exception_email": DEFAULT_SAAS_EMAIL}
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        password = request.form["pass"]

        if not is_allowed_system_email(e):
            return render_template("login.html", message=EMAIL_DOMAIN_HELPER_MESSAGE, **template_ctx)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            ensure_tenant_schema(cursor, conn)
            ensure_user_account_control_schema(cursor, conn)

            cursor.execute(
                """
                SELECT u.user_id, u.email, u.password, r.role_name, r.role_id,
                p.position_name, p.position_id, d.dept_name,
                COALESCE(u.company_id, 0) AS company_id,
                COALESCE(o.company_name, '') AS company_name,
                COALESCE(o.is_active, 1) AS company_is_active,
                COALESCE(u.is_banned, 0) AS is_banned,
                COALESCE(u.is_deleted, 0) AS is_deleted
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                JOIN positions p ON u.position_id = p.position_id
                LEFT JOIN departments d ON u.dept_id = d.dept_id
                LEFT JOIN organizations o ON o.company_id = u.company_id
                WHERE u.email = %s
            """,
                (e,),
            )
            user = cursor.fetchone()

            if user and int(user.get("is_deleted") or 0) == 1:
                return render_template("login.html", message="Account has been deleted. Please contact IT.", **template_ctx)

            if user and int(user.get("is_banned") or 0) == 1:
                return render_template("login.html", message="Account is banned. Please contact IT.", **template_ctx)

            if user and int(user.get("company_is_active") or 0) != 1:
                return render_template(
                    "login.html",
                    message="Your organization is currently paused. Please contact Dev or SaaS Owner.",
                    **template_ctx,
                )

            if user and verify_user_password(user["password"], password):
                if needs_password_rehash(user.get("password")):
                    try:
                        refreshed_hash = hash_user_password(password)
                        cursor.execute(
                            "UPDATE users SET password=%s WHERE user_id=%s",
                            (refreshed_hash, user["user_id"]),
                        )
                        conn.commit()
                    except Exception:
                        conn.rollback()
                        logger.exception("Password rehash on login failed")

                session["email"] = user["email"]
                session["user_id"] = user["user_id"]
                session["role"] = user["role_name"]
                session["role_id"] = user.get("role_id")
                session["position"] = user["position_name"]
                session["position_id"] = user["position_id"]
                session["dept"] = user["dept_name"]
                session["company_id"] = int(user.get("company_id") or 0)
                session["company_name"] = (user.get("company_name") or "").strip()

                log_auth_activity("Login", user["email"])
                return redirect("/")
            
            else:
                # Allow SAAS owner login via env credential when no DB user is present
                # If SAAS_PASSWORD is not set, allow the SAAS_EMAIL to sign in as SaaSOwner
                saas_password_set = bool(str(DEFAULT_SAAS_PASSWORD or "").strip())
                if DEFAULT_SAAS_EMAIL and e == DEFAULT_SAAS_EMAIL and (not saas_password_set or password == DEFAULT_SAAS_PASSWORD):
                    session["email"] = e
                    session["user_id"] = 0
                    session["role"] = "SaaSOwner"
                    session["role_id"] = None
                    session["position"] = ""
                    session["position_id"] = None
                    session["dept"] = ""
                    session["company_id"] = 0
                    session["company_name"] = ""
                    log_auth_activity("Login", e)
                    flash("Login Successful", "success")
                    return redirect("/saas-admin")

                jsonify({"message": "Login attempt failed"})
                return render_template("login.html", message="Invalid credentials", **template_ctx)
                
        finally:
            cursor.close()
            conn.close()
    return render_template("login.html", message=request.args.get("message"), **template_ctx)


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        generic_msg = "If the email exists, a reset link has been sent."

        if not email:
            return render_template(
                "forgot_password.html",
                message="Please enter your email address",
                success=False,
            )

        if not is_allowed_system_email(email):
            return render_template(
                "forgot_password.html",
                message=EMAIL_DOMAIN_HELPER_MESSAGE,
                success=False,
            )

        user_exists = False
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
            user_exists = bool(cursor.fetchone())
        finally:
            cursor.close()
            conn.close()

        if user_exists:
            token = create_password_reset_token(email)
            reset_link = url_for("reset_password", token=token, _external=True)
            subject = "Password Reset Request"
            body = (
                "Good day,\n\n"
                "A password reset was requested for your account.\n"
                "Open the link below to set a new password:\n\n"
                f"{reset_link}\n\n"
                "If you did not request this, you can safely ignore this email.\n\n"
                "This is an automated message. Do not reply."
            )
            send_cc_email(email, subject, body)

        return render_template(
            "forgot_password.html",
            message=generic_msg,
            success=True,
        )

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = verify_password_reset_token(token)
    except SignatureExpired:
        return render_template(
            "reset_password.html",
            message="Reset link has expired. Request a new one.",
            token_valid=False,
        )
    except BadSignature:
        return render_template(
            "reset_password.html",
            message="Invalid reset link. Request a new one.",
            token_valid=False,
        )

    if request.method == "POST":
        new_pass = request.form.get("pass") or ""
        confirm_pass = request.form.get("cpass") or ""

        if (
            len(new_pass) < 6
            or not any(c.isdigit() for c in new_pass)
            or not any(c.isupper() for c in new_pass)
        ):
            return render_template(
                "reset_password.html",
                message="Password: 6+ chars, 1 digit, 1 uppercase",
                token_valid=True,
            )

        if new_pass != confirm_pass:
            return render_template(
                "reset_password.html",
                message="Passwords do not match",
                token_valid=True,
            )

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            new_hash = hash_user_password(new_pass)
            cursor.execute("UPDATE users SET password=%s WHERE email=%s", (new_hash, email))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

        return redirect(
            url_for("login", message="Password reset successful. Please log in.")
        )

    return render_template("reset_password.html", token_valid=True)


@app.route("/api/mobile/departments", methods=["GET"])
@csrf.exempt
def mobile_departments():
    company_slug = (request.args.get("company_slug") or "").strip().lower()

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if company_slug:
            cursor.execute(
                """
                SELECT d.dept_name
                FROM departments d
                JOIN organizations o ON o.company_id = d.company_id
                WHERE o.company_slug = %s AND o.is_active = 1
                ORDER BY d.dept_name
            """,
                (company_slug,),
            )
        else:
            cursor.execute("SELECT dept_name FROM departments ORDER BY dept_name")
        rows = cursor.fetchall() or []
        departments = [row["dept_name"] for row in rows if row.get("dept_name")]
        return jsonify({"departments": departments})
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/send-otp", methods=["POST", "OPTIONS"])
@csrf.exempt
@limiter.limit("5 per minute")
def mobile_send_otp():
    if request.method == "OPTIONS":
        return ("", 200)

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not is_allowed_system_email(email):
        return jsonify({"error": EMAIL_DOMAIN_HELPER_MESSAGE}), 400
    message, ok = request_signup_otp(email)

    if not ok:
        return jsonify({"error": message}), 400

    return jsonify({"message": message}), 200


@app.route("/api/mobile/verify-otp", methods=["POST", "OPTIONS"])
@csrf.exempt
@limiter.limit("10 per minute")
def mobile_verify_otp():
    if request.method == "OPTIONS":
        return ("", 200)

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()
    if not is_allowed_system_email(email):
        return jsonify({"error": EMAIL_DOMAIN_HELPER_MESSAGE}), 400
    message, ok = verify_signup_otp(email, otp, consume=True)

    if not ok:
        return jsonify({"error": message}), 400

    signup_otp_token = create_mobile_signup_otp_token(email)
    return jsonify({"message": message, "signup_otp_token": signup_otp_token}), 200


# Mobile API Endpoints (Connected to flutter)
@app.route("/api/mobile/signup", methods=["POST", "OPTIONS"])
@csrf.exempt
def mobile_signup():
    if request.method == "OPTIONS":
        return ("", 200)

    data = request.get_json(silent=True) or {}
    e = (data.get("email") or "").strip().lower()
    p = data.get("password") or ""
    cp = (
        data.get("confirmpassword")
        or data.get("confirm_password")
        or data.get("cpass")
        or ""
    )
    dept_name = (
        data.get("department")
        or data.get("departments")
        or data.get("dept")
        or ""
    ).strip()
    signup_otp_token = (
        data.get("signup_otp_token")
        or data.get("otp_verification_token")
        or data.get("verification_token")
        or ""
    ).strip()
    company_slug = (
        data.get("company_slug")
        or data.get("company")
        or ""
    ).strip().lower()

    if not e or not p or not cp or not dept_name or not signup_otp_token or not company_slug:
        return jsonify({"error": "Please fill all fields"}), 400

    if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", e):
        return jsonify({"error": "Invalid email address"}), 400

    try:
        verified_email = verify_mobile_signup_otp_token(signup_otp_token)
    except SignatureExpired:
        return jsonify({"error": "Verified OTP session expired. Please verify OTP again."}), 400
    except BadSignature:
        return jsonify({"error": "Invalid OTP verification session. Please verify OTP again."}), 400

    if verified_email.strip().lower() != e:
        return jsonify({"error": "OTP was verified for a different email."}), 400

    if len(p) < 6 or not any(c.isdigit() for c in p) or not any(c.isupper() for c in p):
        return jsonify({"error": "Password: 6+ chars, 1 digit, 1 uppercase"}), 400

    if p != cp:
        return jsonify({"error": "Passwords do not match"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_tenant_schema(cursor, conn)
        ensure_saas_owner_schema(cursor, conn)
        cursor.execute(
            "SELECT company_id FROM organizations WHERE company_slug=%s AND is_active=1 LIMIT 1",
            (company_slug,),
        )
        company_row = cursor.fetchone() or {}
        company_id = int(company_row.get("company_id") or 0)
        if company_id <= 0:
            return jsonify({"error": "Invalid company selected"}), 400

        if not _is_allowed_email_for_company(cursor, e, company_id=company_id):
            return jsonify({"error": "Email domain is not allowed for this company"}), 400

        cursor.execute("SELECT user_id FROM users WHERE email=%s", (e,))
        if cursor.fetchone():
            return jsonify({"error": "Email already used, please login"}), 409

        seats_ok, seat_msg = check_company_user_seat_capacity(cursor, company_id)
        if not seats_ok:
            return jsonify({"error": seat_msg}), 403

        cursor.execute(
            "SELECT dept_id FROM departments WHERE dept_name=%s AND company_id=%s",
            (dept_name, company_id),
        )
        dept = cursor.fetchone()
        if not dept:
            return jsonify({"error": "Invalid department"}), 400
        dept_id = dept["dept_id"]

        cursor.execute("SELECT role_id FROM roles WHERE role_name='User' AND company_id=%s", (company_id,))
        role_row = cursor.fetchone()
        role_id = role_row["role_id"] if role_row else 1

        cursor.execute("SELECT position_id FROM positions WHERE position_name='None' AND company_id=%s", (company_id,))
        pos_row = cursor.fetchone()
        position_id = pos_row["position_id"] if pos_row else 1

        hp = hash_user_password(p)
        cursor.execute(
            "INSERT INTO users (email, password, dept_id, role_id, position_id, company_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (e, hp, dept_id, role_id, position_id, company_id),
        )
        conn.commit()

        return jsonify({"message": "Account created successfully"}), 201

    except Exception as ex:
        conn.rollback()
        print("Mobile signup error:", ex)
        return jsonify({"error": "Something went wrong"}), 500
    finally:
        cursor.close()
        conn.close()
    
    
@app.route("/api/mobile/login", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute")
def mobile_login():
    data = request.get_json(silent=True) or {}
    e = (data.get("email") or "").strip().lower()
    pw = data.get("password") or ""
    company_slug = (
        data.get("company_slug")
        or data.get("company")
        or ""
    ).strip().lower()

    if not e or not pw:
        return jsonify({"error": "Email and password required"}), 400

    if not is_allowed_system_email(e):
        return jsonify({"error": EMAIL_DOMAIN_HELPER_MESSAGE}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
                        SELECT u.user_id, u.email, u.password, r.role_name,
                        p.position_name, d.dept_name,
                        COALESCE(u.company_id, 0) AS company_id,
                        COALESCE(o.company_slug, '') AS company_slug,
                        COALESCE(o.is_active, 1) AS company_is_active
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
                        LEFT JOIN organizations o ON o.company_id = u.company_id
            WHERE u.email = %s
                            AND (%s = '' OR o.company_slug = %s)
            """,
                        (e, company_slug, company_slug),
        )
        user = cursor.fetchone()

        if not user or not verify_user_password(user["password"], pw):
            return jsonify({"error": "Invalid credentials"}), 401

        if int(user.get("company_is_active") or 0) != 1:
            return jsonify({"error": "Your organization is currently paused. Please contact Dev or SaaS Owner."}), 403

        if needs_password_rehash(user.get("password")):
            try:
                refreshed_hash = hash_user_password(pw)
                cursor.execute(
                    "UPDATE users SET password=%s WHERE user_id=%s",
                    (refreshed_hash, user["user_id"]),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                logger.exception("Password rehash on mobile login failed")

        if user["role_name"] != "User":
            return jsonify({"error": "User role only"}), 403

        token = create_token_with_claims(
            user["email"],
            company_id=user.get("company_id"),
            role=user.get("role_name"),
        )

        return jsonify({
            "token": token,
            "user": {
                "email": user["email"],
                "dept_name": user.get("dept_name"),
                "position_name": user.get("position_name"),
                "role_name": user.get("role_name"),
                "company_id": int(user.get("company_id") or 0),
                "company_slug": user.get("company_slug"),
            },
        }), 200

    finally:
        cursor.close()
        conn.close()

@app.route("/api/user_notifications", methods=["GET", "OPTIONS"])
@require_token
def user_notifications():

    if request.method == "OPTIONS":
        return ("", 200)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    user_id = get_user_id(request.user_email)

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    cursor.execute("""
        SELECT message, created_at
        FROM notifications
        WHERE user_id = %s
        ORDER BY created_at ASC
    """, (user_id,))

    notifications = cursor.fetchall()

    return jsonify({
        "notifications": notifications
    })

@app.route("/api/mobile/user-profile", methods=["GET"])
@require_token
def mobile_user_profile():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.email, d.dept_name, p.position_name, r.role_name
            FROM users u
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = %s
              AND (%s = 0 OR COALESCE(u.company_id, 0) = %s)
        """,
            (
                request.user_email,
                int(getattr(request, "user_company_id", 0) or 0),
                int(getattr(request, "user_company_id", 0) or 0),
            ),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "User not found"})
        if row["role_name"] != "User":
            return jsonify({"error": "User role only"})
        return jsonify(row)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/requests", methods=["GET"])
@require_token
def mobile_requests():
    user_id = get_user_id_for_company(
        request.user_email,
        int(getattr(request, "user_company_id", 0) or 0),
    )
    if not user_id:
        return jsonify({"error": "User ID not found"})

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT 
                r.request_id,
                rt.type_name,
                r.filename,
                rs.status_name,
                p.position_name,
                r.rejection_message,
                r.created_at
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status rs ON r.status_id = rs.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """,
            (user_id,),
        )
        return jsonify(cursor.fetchall())
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/notifications", methods=["GET"])
@require_token
def mobile_notifications():
    user_id = get_user_id_for_company(
        request.user_email,
        int(getattr(request, "user_company_id", 0) or 0),
    )
    if not user_id:
        return jsonify([])

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT r.request_id, r.filename, rt.type_name, s.status_name, 
            r.rejection_message, r.created_at, p.position_name as current_stage
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """,
            (user_id,),
        )

        rows = cursor.fetchall()
        notifications = []
        for req in rows:
            status_lower = (req["status_name"] or "").lower()
            notif = {
                "id": req["request_id"],
                "title": f"Update on {req['type_name']}",
                "time": req["created_at"].strftime("%b %d, %H:%M"),
                "type": "pending",
                "message": f"New request submitted. Currently being reviewed by: {req['current_stage']}",
            }
            if status_lower == "approved":
                notif["type"] = "success"
                notif["message"] = (
                    f"Your request for {req['filename']} has been fully approved."
                )
            elif status_lower == "rejected":
                notif["type"] = "error"
                notif["message"] = f"Rejected: {req['rejection_message']}"
            notifications.append(notif)

        broadcast_rows = fetch_system_broadcast_rows(cursor, limit=80)
        for row in reversed(broadcast_rows):
            created_at = row.get("created_at")
            if hasattr(created_at, "strftime"):
                display_time = created_at.strftime("%b %d, %H:%M")
            else:
                display_time = ""

            notifications.append(
                {
                    "id": row.get("id"),
                    "title": row.get("title") or "System Broadcast",
                    "time": display_time,
                    "type": "info",
                    "message": row.get("description") or "",
                }
            )

        return jsonify(notifications)
    finally:
        cursor.close()
        conn.close()


def _parse_sse_since_datetime(raw_value):
    text = str(raw_value or "").strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.datetime.fromisoformat(text)
    except Exception:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return parsed


def _get_latest_notification_timestamp(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """,
            (user_id,),
        )
        row = cursor.fetchone() or {}
        created_at = row.get("created_at")
        if isinstance(created_at, datetime.datetime):
            if created_at.tzinfo is not None:
                created_at = created_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return created_at
        return None
    finally:
        cursor.close()
        conn.close()


def _notification_stream_generator(user_id, initial_since=None, poll_interval_seconds=2, timeout_seconds=120):
    since_dt = initial_since
    deadline = time.time() + timeout_seconds

    yield "event: ready\ndata: {}\n\n"

    while time.time() < deadline:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        rows = []
        try:
            if since_dt is None:
                cursor.execute(
                    """
                    SELECT message, created_at
                    FROM notifications
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                """,
                    (user_id,),
                )
                latest_only = cursor.fetchall() or []
                rows = list(reversed(latest_only))
            else:
                cursor.execute(
                    """
                    SELECT message, created_at
                    FROM notifications
                    WHERE user_id = %s AND created_at > %s
                    ORDER BY created_at ASC
                    LIMIT 200
                """,
                    (user_id, since_dt),
                )
                rows = cursor.fetchall() or []
        except Exception:
            logger.exception("SSE notification stream query failed")
            yield "event: error\ndata: {\"error\":\"stream_query_failed\"}\n\n"
            break
        finally:
            cursor.close()
            conn.close()

        emitted = False
        for row in rows:
            created_at = row.get("created_at")
            if isinstance(created_at, datetime.datetime):
                normalized_created_at = created_at
                if normalized_created_at.tzinfo is not None:
                    normalized_created_at = normalized_created_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
                since_dt = normalized_created_at
                created_iso = normalized_created_at.isoformat()
            else:
                created_iso = ""

            payload = {
                "message": str(row.get("message") or "").strip(),
                "created_at": created_iso,
            }
            yield f"event: notification\\ndata: {json.dumps(payload)}\\n\\n"
            emitted = True

        if not emitted:
            yield ": keep-alive\n\n"

        time.sleep(poll_interval_seconds)

    yield "event: end\ndata: {}\n\n"


def _build_notification_sse_response(user_id):
    since_raw = request.args.get("since")
    interval_raw = request.args.get("interval", "2")
    timeout_raw = request.args.get("timeout", "120")

    try:
        interval_seconds = int(interval_raw)
    except Exception:
        interval_seconds = 2
    interval_seconds = max(1, min(interval_seconds, 10))

    try:
        timeout_seconds = int(timeout_raw)
    except Exception:
        timeout_seconds = 120
    timeout_seconds = max(30, min(timeout_seconds, 600))

    since_dt = _parse_sse_since_datetime(since_raw)
    if since_dt is None:
        since_dt = _get_latest_notification_timestamp(user_id)

    return Response(
        stream_with_context(
            _notification_stream_generator(
                user_id=user_id,
                initial_since=since_dt,
                poll_interval_seconds=interval_seconds,
                timeout_seconds=timeout_seconds,
            )
        ),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _build_openapi_spec():
    base_url = (request.url_root or "").rstrip("/") if has_request_context() else ""

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Requesting and Approval SaaS API",
            "version": "1.0.0",
            "description": "Core API contract for authentication, request workflows, and real-time notification streams.",
        },
        "servers": [{"url": base_url}] if base_url else [],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string"},
                    },
                },
                "MobileLoginRequest": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "password": {"type": "string"},
                        "company_slug": {"type": "string"},
                    },
                },
                "MobileLoginResponse": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string"},
                        "user": {
                            "type": "object",
                            "properties": {
                                "email": {"type": "string"},
                                "dept_name": {"type": "string"},
                                "position_name": {"type": "string"},
                                "role_name": {"type": "string"},
                                "company_id": {"type": "integer"},
                                "company_slug": {"type": "string"},
                            },
                        },
                    },
                },
                "UpdateRequestStatusRequest": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["PENDING", "IN PROGRESS", "APPROVED", "REJECTED", "COMPLETED"],
                        },
                        "message": {"type": "string"},
                        "comment": {"type": "string"},
                    },
                },
            },
        },
        "paths": {
            "/api/mobile/signup": {
                "post": {
                    "tags": ["Mobile Auth"],
                    "summary": "Sign up a mobile user within a tenant",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": [
                                        "email",
                                        "password",
                                        "confirmpassword",
                                        "department",
                                        "signup_otp_token",
                                        "company_slug",
                                    ],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {"description": "Account created"},
                        "400": {"description": "Validation error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                }
            },
            "/api/mobile/login": {
                "post": {
                    "tags": ["Mobile Auth"],
                    "summary": "Authenticate mobile user and return bearer token",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/MobileLoginRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Authenticated",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/MobileLoginResponse"}
                                }
                            },
                        },
                        "401": {"description": "Invalid credentials"},
                    },
                }
            },
            "/api/mobile/requests": {
                "get": {
                    "tags": ["Mobile Requests"],
                    "summary": "List current user requests",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "Request list"},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
            "/api/mobile/notifications": {
                "get": {
                    "tags": ["Mobile Notifications"],
                    "summary": "List current user notifications",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "Notification list"},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
            "/api/request/{request_id}/status": {
                "post": {
                    "tags": ["Workflow"],
                    "summary": "Approve/reject/progress a request",
                    "parameters": [
                        {
                            "name": "request_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UpdateRequestStatusRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Status updated"},
                        "400": {"description": "Invalid input"},
                        "403": {"description": "Forbidden"},
                        "404": {"description": "Request not found"},
                    },
                }
            },
            "/api/stream/notifications": {
                "get": {
                    "tags": ["Realtime"],
                    "summary": "Server-sent events stream for web notifications",
                    "parameters": [
                        {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
                        {"name": "interval", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 10}},
                        {"name": "timeout", "in": "query", "schema": {"type": "integer", "minimum": 30, "maximum": 600}},
                    ],
                    "responses": {
                        "200": {"description": "SSE stream", "content": {"text/event-stream": {}}},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
            "/api/mobile/stream/notifications": {
                "get": {
                    "tags": ["Realtime"],
                    "summary": "Server-sent events stream for mobile notifications",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
                        {"name": "interval", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 10}},
                        {"name": "timeout", "in": "query", "schema": {"type": "integer", "minimum": 30, "maximum": 600}},
                    ],
                    "responses": {
                        "200": {"description": "SSE stream", "content": {"text/event-stream": {}}},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
        },
    }


@app.route("/api/openapi.json", methods=["GET"])
def openapi_spec():
    return jsonify(_build_openapi_spec())


@app.route("/api/docs", methods=["GET"])
def openapi_docs():
    html = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>API Docs</title>
  <style>
    body { font-family: Segoe UI, Tahoma, sans-serif; margin: 24px; color: #1a1a1a; }
    h1 { margin-bottom: 8px; }
    .muted { color: #666; margin-bottom: 16px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin-bottom: 10px; }
    .method { font-weight: 700; color: #0b5fff; }
    .path { font-family: Consolas, monospace; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    .tag { background: #eef3ff; border-radius: 999px; padding: 2px 10px; font-size: 12px; }
    pre { background: #f7f7f8; border: 1px solid #eee; border-radius: 8px; padding: 12px; overflow: auto; }
  </style>
</head>
<body>
  <h1>Requesting and Approval SaaS API</h1>
  <div class=\"muted\">OpenAPI JSON: <a href=\"/api/openapi.json\">/api/openapi.json</a></div>
  <div id=\"routes\"></div>
  <h2>Raw OpenAPI</h2>
  <pre id=\"raw\">Loading...</pre>
  <script>
    async function loadDocs() {
      const res = await fetch('/api/openapi.json');
      const spec = await res.json();
      const routesEl = document.getElementById('routes');
      const rawEl = document.getElementById('raw');

      const paths = spec.paths || {};
      Object.keys(paths).sort().forEach((path) => {
        const methods = paths[path] || {};
        Object.keys(methods).forEach((method) => {
          const op = methods[method] || {};
          const tags = (op.tags || []).map(t => `<span class=\"tag\">${t}</span>`).join('');
          const card = document.createElement('div');
          card.className = 'card';
          card.innerHTML = `
            <div class=\"row\"><span class=\"method\">${method.toUpperCase()}</span><span class=\"path\">${path}</span>${tags}</div>
            <div>${op.summary || ''}</div>
          `;
          routesEl.appendChild(card);
        });
      });

      rawEl.textContent = JSON.stringify(spec, null, 2);
    }
    loadDocs().catch((err) => {
      document.getElementById('raw').textContent = 'Failed to load docs: ' + err;
    });
  </script>
</body>
</html>
    """.strip()
    return Response(html, mimetype="text/html")


@app.route("/api/stream/notifications", methods=["GET"])
@login_required
def stream_notifications():
    user_id = int(session.get("user_id") or 0)
    if user_id <= 0:
        user_id = int(
            get_user_id_for_company(
                session.get("email"),
                int(session.get("company_id") or 0),
            )
            or 0
        )

    if user_id <= 0:
        return jsonify({"error": "Unauthorized"}), 401

    return _build_notification_sse_response(user_id)


@app.route("/api/mobile/stream/notifications", methods=["GET"])
@require_token
def mobile_stream_notifications():
    user_id = int(
        get_user_id_for_company(
            request.user_email,
            int(getattr(request, "user_company_id", 0) or 0),
        )
        or 0
    )
    if user_id <= 0:
        return jsonify({"error": "Unauthorized"}), 401

    return _build_notification_sse_response(user_id)


@app.route("/logout")
def logout():
    active_email = session.get("email")
    if active_email:
        log_auth_activity("Logout", active_email)
    session.clear()
    return redirect("/login")




def make_overlay_pdf(
    template_pdf_bytes: bytes, text_items: list, image_items: list
) -> bytes:
    """
    Build an overlay PDF (same page sizes as the template) containing texts and images.

    text_items: [{page:int, x:float, y:float, text:str, font:int=10}]
    image_items: [{page:int, x:float, y:float, w:float, h:float, image_bytes:bytes}]
    """
    from io import BytesIO as _BytesIO

    reader = _PdfReader(_BytesIO(template_pdf_bytes))
    page_sizes = [
        (float(p.mediabox.width), float(p.mediabox.height)) for p in reader.pages
    ]

    buf = _BytesIO()
    c = _rl_canvas.Canvas(buf)

    for page_index, (w, h) in enumerate(page_sizes):
        c.setPageSize((w, h))

        for item in text_items or []:
            if int(item.get("page", -1)) != page_index:
                continue
            font = int(item.get("font", 10) or 10)
            c.setFont("Helvetica", font)

            text = str(item.get("text", ""))
            lines = text.splitlines() or [""]

            box_h = float(item.get("h") or (font * 1.6))
            pad_x = 3.0
            pad_top = 2.0

            # Align text near the top-left of the saved text box so PDF output
            # matches what the user sees in the browser editor.
            start_x = float(item["x"]) + pad_x
            start_y = float(item["y"]) + max(font, box_h - font - pad_top)

            text_obj = c.beginText()
            text_obj.setTextOrigin(start_x, start_y)
            text_obj.setLeading(max(10.0, font * 1.2))
            for line in lines:
                text_obj.textLine(line)
            c.drawText(text_obj)

        for item in image_items or []:
            if int(item.get("page", -1)) != page_index:
                continue
            img = _ImageReader(_BytesIO(item["image_bytes"]))
            c.drawImage(
                img,
                float(item["x"]),
                float(item["y"]),
                float(item["w"]),
                float(item["h"]),
                mask="auto",
            )

        c.showPage()

    c.save()
    return buf.getvalue()


def merge_overlay(template_pdf_bytes: bytes, overlay_pdf_bytes: bytes) -> bytes:
    """Merge an overlay PDF onto a template PDF and return the final PDF bytes."""
    from io import BytesIO as _BytesIO

    base = _PdfReader(_BytesIO(template_pdf_bytes))
    overlay = _PdfReader(_BytesIO(overlay_pdf_bytes))

    writer = _PdfWriter()
    for i in range(len(base.pages)):
        page = base.pages[i]
        if i < len(overlay.pages):
            page.merge_page(overlay.pages[i])
        writer.add_page(page)

    out = _BytesIO()
    writer.write(out)
    return out.getvalue()


def build_text_items_from_field_map(field_map: dict, values: dict):
    items = []
    for key, value in values.items():
        if key not in field_map:
            continue
        page, x, y, font = field_map[key]
        items.append({"page": page, "x": x, "y": y, "text": value, "font": font})
    return items


def make_grid_overlay_for_pdf(pdf_path: str, out_path: str, step: int = 40) -> None:
    """
    Creates a copy of the PDF with a coordinate grid drawn on top (for calibration).
    Use this to find x/y positions for dates, names, etc.
    """
    from io import BytesIO as _BytesIO

    base = _PdfReader(pdf_path)
    writer = _PdfWriter()

    for i, page in enumerate(base.pages):
        w = float(page.mediabox.width)
        h = float(page.mediabox.height)

        buf = _BytesIO()
        c = _rl_canvas.Canvas(buf)
        c.setPageSize((w, h))
        c.setFont("Helvetica", 7)

        x = 0
        while x <= w:
            c.line(x, 0, x, h)
            c.drawString(x + 2, h - 10, f"x={int(x)}")
            x += step

        y = 0
        while y <= h:
            c.line(0, y, w, y)
            c.drawString(2, y + 2, f"y={int(y)}")
            y += step

        c.setFont("Helvetica-Bold", 10)
        c.drawString(10, h - 25, f"PAGE {i}")
        c.save()
        buf.seek(0)

        overlay_page = _PdfReader(buf).pages[0]
        page.merge_page(overlay_page)
        writer.add_page(page)

    with open(out_path, "wb") as f:
        writer.write(f)




    
apply_global_rate_limits()


if __name__ == "__main__":
    debug_mode = (os.environ.get("FLASK_DEBUG", "false").strip().lower() == "false")
    app.run(
        host=os.environ.get("HOST", "127.0.0.1").strip() or "127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=debug_mode,
        use_reloader=debug_mode,
    ) 