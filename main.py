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
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from sendotp import srotp, verify, request_signup_otp, verify_signup_otp
from config import get_connection
from sendotp import send_cc_email, send_request_email
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from sendotp import send_cc_email_with_blob
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from reportlab.pdfgen import canvas as _rl_canvas
from reportlab.lib.utils import ImageReader as _ImageReader
from pypdf import PdfReader as _PdfReader, PdfWriter as _PdfWriter
from flask import Response

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
from threading import Thread
from io import BytesIO, StringIO
from flask import send_file

load_dotenv()

logger = logging.getLogger(__name__)

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
            "argon2-cffi is required for password hashing. Install it with: python -m pip install argon2-cffi"
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

SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("secret_key")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
app.secret_key = SECRET_KEY
serializer = URLSafeTimedSerializer(app.secret_key)

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

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[
        os.environ.get("RATE_LIMIT_DEFAULT_DAY", "1000 per day"),
        os.environ.get("RATE_LIMIT_DEFAULT_HOUR", "200 per hour"),
    ],
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
)


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
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024 # 20 MB file upload
# Allowed Upload Types 
ALLOWED_EXTENSIONS = {"pdf"}



def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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
    return serializer.dumps({"email": email})


def verify_token(token, max_age=60 * 60 * 24 * 7):
    data = serializer.loads(token, max_age=max_age)
    return data["email"]


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
            email = verify_token(token)
        except SignatureExpired:
            return jsonify({"error": "Token expired"}), 401
        except BadSignature:
            return jsonify({"error": "Invalid token"}), 401

        request.user_email = email
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
    resp.headers["Referrer-Policy"] = "no-referrer"
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
ALLOWED_FORM_BLOCK_TYPES = {"heading", "text", "textarea", "number", "date", "shape", "table"}
ALLOWED_FORM_SHAPES = {"line", "box"}
ALLOWED_FORM_COLUMN_TYPES = {"text", "number"}
ADMIN_PIN_MAX_FAILED_ATTEMPTS = 5
ADMIN_PIN_WARNING_ATTEMPTS = 3
ADMIN_PIN_OTP_COOLDOWN_SECONDS = 60
ADMIN_PIN_OTP_MAX_AGE_SECONDS = 60 * 10
COO_ACTION_TOKEN_MAX_AGE_SECONDS = int(os.environ.get("COO_ACTION_TOKEN_MAX_AGE_SECONDS", str(60 * 60 * 24)))
BUDGET_DEFAULT_TOTAL = Decimal("100000.00")

_admin_pin_schema_checked = False
_user_account_control_schema_checked = False
_budget_schema_checked = False
_budget_request_schema_checked = False
_coo_special_approval_schema_checked = False
_request_type_form_schema_checked = False
_request_form_submission_schema_checked = False


def can_use_admin_pin(role=None):
    effective_role = (role or session.get("role") or "").strip()
    return effective_role in ALLOWED_ADMIN_PIN_ROLES


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


def ensure_budget_schema(cursor, conn):
    global _budget_schema_checked

    if _budget_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_budget_totals (
            email VARCHAR(255) NOT NULL PRIMARY KEY,
            total_budget DECIMAL(14,2) NOT NULL DEFAULT 100000.00,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    conn.commit()
    _budget_schema_checked = True


def ensure_budget_request_schema(cursor, conn):
    global _budget_request_schema_checked

    if _budget_request_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_budget_metadata (
            request_id INT NOT NULL PRIMARY KEY,
            budget_type VARCHAR(64) NOT NULL,
            target_department VARCHAR(255) NOT NULL,
            created_by_email VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_budget_transactions (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            request_id INT NOT NULL,
            provider VARCHAR(32) NOT NULL DEFAULT 'xendit',
            external_id VARCHAR(96) NULL,
            transaction_id VARCHAR(128) NULL,
            status VARCHAR(48) NOT NULL DEFAULT 'PENDING',
            amount DECIMAL(14,2) NOT NULL DEFAULT 0,
            currency VARCHAR(8) NOT NULL DEFAULT 'PHP',
            budget_type VARCHAR(64) NULL,
            target_department VARCHAR(255) NULL,
            payload_json LONGTEXT NULL,
            response_json LONGTEXT NULL,
            error_message TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_request_budget_transactions_request (request_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )

    conn.commit()
    _budget_request_schema_checked = True


def ensure_coo_special_approval_schema(cursor, conn):
    global _coo_special_approval_schema_checked

    if _coo_special_approval_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_coo_approvals (
            request_id INT NOT NULL PRIMARY KEY,
            status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
            requested_to_email VARCHAR(255) NULL,
            requested_by_email VARCHAR(255) NULL,
            approved_by_user_id INT NULL,
            approved_by_email VARCHAR(255) NULL,
            approval_method VARCHAR(32) NULL,
            requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMP NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_request_coo_approvals_status (status),
            INDEX idx_request_coo_approvals_requested_at (requested_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )

    conn.commit()
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


@app.route("/api/specialaccess/request/<int:request_id>/resend-email", methods=["POST"])
@login_required
def special_access_resend_email(request_id):
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
            return jsonify({"success": False, "error": "Request is not queued for COO approval."}), 404

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
        return {"success": True, "message": "Request already approved by COO."}, 200
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

    conn.commit()

    base = "COO special approval completed." if decision == "APPROVED" else "COO special rejection completed."
    base += " No post-decision COO email is sent by design."

    return {
        "success": True,
        "message": base,
        "email": {"sent": 0, "recipients": 0},
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


@app.route("/api/specialaccess/request/<int:request_id>/approve", methods=["POST"])
@login_required
def special_access_approve_request(request_id):
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
            return jsonify({"success": True, "message": "Request already approved by COO."})

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

        conn.commit()

        response_message = "COO special approval completed. No post-decision COO email is sent by design."

        return jsonify(
            {
                "success": True,
                "message": response_message,
                "email": {"sent": 0, "recipients": 0},
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

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_type_form_schemas (
            request_type_id INT NOT NULL PRIMARY KEY,
            schema_json LONGTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    conn.commit()
    _request_type_form_schema_checked = True


def ensure_request_form_submission_table(cursor, conn):
    global _request_form_submission_schema_checked

    if _request_form_submission_schema_checked:
        return

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_form_submissions (
            request_id INT NOT NULL PRIMARY KEY,
            request_type_id INT NOT NULL,
            form_data_json LONGTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    conn.commit()
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

            list_values = _split_list_values(value)

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


def _normalize_pdf_field_lookup_key(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def build_filled_pdf_from_submission(template_pdf_bytes, schema, cleaned_payload, total_amount=None):
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

        for block in schema.get("blocks", []):
            block_type = str(block.get("type") or "").strip().lower()
            if block_type != "number":
                continue

            block_id = str(block.get("id") or "").strip().lower()
            block_label = str(block.get("label") or "").strip().lower()
            if "total" not in block_id and "total" not in block_label:
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
                break

            if block_overlay_cfg:
                append_overlay_text(total_text, block_overlay_cfg)
                total_written = True
                break

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
        return redirect("/login")

    role = session.get("role").strip()
    dept = session.get("dept").strip()
    position = session.get("position").strip()
    
    if dept == "GSD" and role in ["AssistantAdmin", "Admin"]:
        flash("Login Successful", "success")
        return redirect("/gsd_dashboard")

    elif role in ["Dean", "Reviewer",]:
        flash("Login Successful", "success")
        return redirect("/dean")

    elif role in ["Admin", "AssistantAdmin", "SuperAdmin", "SBO"]:
        flash("Login Successful", "success")
        return redirect("/admin")

    elif role == "IT":
        flash("Login Successful", "success")
        return redirect("/IT")
    else:
        flash("Login Successful", "success")
        return redirect("/udashboard")


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

        return render_template(
            "dean.html",
            approvals_today=approvals_today,
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            r_requests=r_requests,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/udashboard")
def udashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    if (session.get("role") or "").strip() not in ["User"]:
        return "Forbidden", 403
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    user_id = get_user_id(session["email"])

    try:
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
            ORDER BY type_name ASC
        """)
        request_types = cursor.fetchall()

        cursor.execute("SELECT dept_name FROM departments ORDER BY dept_name ASC")
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
            WHERE r.user_id = %s
            ORDER BY r.request_id 
        """, (user_id,))
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
            WHERE r.user_id = %s
        """, (user_id,))
        counts = cursor.fetchone() or {}

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

        return jsonify(notifications)
    except Exception as e:
        print(f"Notification Error: {e}")
        return jsonify([])
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
        return jsonify({"success": True, "data": []})

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

@app.route("/api/user_dashboard", methods=["GET", "OPTIONS"])
@require_token
def api_user_dashboard():
    if request.method == "OPTIONS":
        return ("", 200)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    user_id = get_user_id(request.user_email)

    if not user_id:
        cursor.close()
        conn.close()
        return jsonify({"error": "Unauthorized"}), 401

    try:
        cursor.execute("""
            SELECT request_type_id, type_name, template_filename, template_mode
            FROM request_types
            ORDER BY type_name ASC
        """)
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
            WHERE r.user_id = %s
            ORDER BY r.request_id ASC
        """, (user_id,))
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
            WHERE r.user_id = %s
        """, (user_id,))
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

        return render_template(
            "gsddashboard.html",
            inventory_items=inventory_items,
            recent_requests=recent_requests,
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            approvals_today=approvals_today,
            completed_count=completed_count,
        )
    finally:
        cursor.close()
        conn.close()

@app.post("/api/inventory")
def inv_add():
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
def inv_edit(pid):
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
def inv_delete(pid):
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
    dept = (session.get("dept") or "").strip()
    role = (session.get("role") or "").strip()
    if not (role in ["Admin", "AssistantAdmin", "SuperAdmin", "SBO"]):
        return "Forbidden", 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'PENDING'
            AND r.stage_position_id = %s
            """,
            (position_id,),
        )
        pending_count = cursor.fetchone()["count"]

        # Per-position totals (who actually clicked approve/reject)
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'APPROVED'
            """,
            (position_id,),
        )
        approved_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'REJECTED'
            """,
            (position_id,),
        )
        rejected_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s
            AND action = 'APPROVED'
            AND DATE(created_at) = CURDATE()
            """,
            (position_id,),
        )
        approvals_today = cursor.fetchone()["count"]
        
        cursor.execute(
            """
            SELECT COUNT(*) AS count 
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'IN PROGRESS'
            """,
        )
        in_progress = cursor.fetchone()["count"]
        
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'COMPLETED'
            """,
        )
        completed = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM users")
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
            (%(is_purchasing)s = 1)
            OR (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s)
            OR (ra.request_id IS NOT NULL)

            ORDER BY r.created_at ASC
            LIMIT 50
            """

        cursor.execute(
            recent_sql,
            {
                "pos_id": int(position_id or 0),
                "is_purchasing": 1 if is_purchasing else 0,
            },
        )
        recent_requests = cursor.fetchall()
        apply_send_back_visibility(cursor, recent_requests)


        # Positions dropdown
        cursor.execute(
            "SELECT position_id, position_name FROM positions ORDER BY position_name ASC"
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
            GROUP BY rt.request_type_id, rt.type_name, rt.template_filename
            ORDER BY rt.type_name ASC
        """)
        existing_types = cursor.fetchall()

        # CC recipients dropdown (all known user emails)
        cursor.execute("""
            SELECT u.email
            FROM users u
            ORDER BY u.email ASC
        """)
        cc_recipients = [row["email"] for row in cursor.fetchall()]

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
            cc_recipients=cc_recipients,
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
            """,
            (position_id,),
        )
        pending_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'APPROVED'
            """,
            (position_id,),
        )
        approved_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_actions
            WHERE actor_position_id = %s AND action = 'REJECTED'
            """,
            (position_id,),
        )
        rejected_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'IN PROGRESS'
            """
        )
        in_progress = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM requests r
            JOIN request_status s ON r.status_id = s.status_id
            WHERE s.status_name = 'COMPLETED'
            """
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
            (%(is_purchasing)s = 1)
            OR (s.status_name = 'PENDING' AND r.stage_position_id = %(pos_id)s)
            OR (ra.request_id IS NOT NULL)

            ORDER BY r.created_at ASC
            LIMIT 50
            """

        cursor.execute(
            recent_sql,
            {
                "pos_id": position_id,
                "is_purchasing": is_purchasing,
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
        # get request basics
        cursor.execute(
            """
            SELECT request_id, request_type_id, stage_position_id
            FROM requests
            WHERE request_id = %s
        """,
            (request_id,),
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
        # ensure request exists
        cursor.execute(
            "SELECT request_id FROM requests WHERE request_id=%s", (request_id,)
        )
        if not cursor.fetchone():
            return jsonify({"error": "Request not found"}), 404

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
            WHERE request_id = %s
        """,
            (stage_position_id, request_id),
        )

        conn.commit()
        return jsonify({"success": True, "message": "Workflow updated successfully."})

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
    cursor = conn.cursor()

    try:
        ensure_request_type_form_schema_table(cursor, conn)

        # Insert request type WITH template + mode
        cursor.execute(
            """
            INSERT INTO request_types (type_name, template_filename, template_file, template_mode)
            VALUES (%s, %s, %s, %s)
            """,
            (type_name, template_filename, template_blob, template_mode),
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
        for i, pos_id in enumerate(reviewer_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_reviewers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (new_type_id, int(pos_id), i),
                )

        # approvers in the EXACT order selected
        for i, pos_id in enumerate(approver_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_approvers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (new_type_id, int(pos_id), i),
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
        resolved_user_id = get_user_id(session.get("email"))
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
    request_purpose = (request.form.get("purpose") or "").strip()
    request_budget = normalize_request_budget(request.form.get("request_budget"))
    request_department = (session.get("dept") or "").strip()
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
        ensure_request_type_form_schema_table(cursor, conn)
        ensure_request_form_submission_table(cursor, conn)
        ensure_budget_request_schema(cursor, conn)

        if can_request_budget:
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
                "SELECT dept_name FROM departments WHERE dept_name = %s LIMIT 1",
                (request_department,),
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
            WHERE request_type_id = %s
            LIMIT 1
            """,
            (request_type_id,),
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
            if not request_type_template_blob:
                msg = "Representative template is missing for this fillable request type. Please contact the representative/admin."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

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
                amount = float(computed_total)

            if request_type_template_blob:
                file_blob = build_filled_pdf_from_submission(
                    request_type_template_blob,
                    schema,
                    cleaned_payload,
                    total_amount=computed_total if has_total_sources else None,
                )
                filename = request_type_template_name or f"request_type_{request_type_id}_template.pdf"

        if amount is None:
            if not amount_raw:
                msg = "Amount is required."
                if request.headers.get("X-Requested-With") == "fetch":
                    return jsonify({"success": False, "message": msg}), 400
                flash(msg, "danger")
                return redirect(request.referrer or "/udashboard")

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

        if not wfor:
            try:
                cursor.execute(
                    """
                    SELECT wfor
                    FROM request_types
                    WHERE request_type_id = %s
                    LIMIT 1
                    """,
                    (request_type_id,),
                )
                request_type_wfor_row = cursor.fetchone() or {}
                wfor = (request_type_wfor_row.get("wfor") or "").strip()
            except Exception:
                try:
                    cursor.execute(
                        """
                        SELECT `for` AS wfor
                        FROM request_types
                        WHERE request_type_id = %s
                        LIMIT 1
                        """,
                        (request_type_id,),
                    )
                    request_type_wfor_row = cursor.fetchone() or {}
                    wfor = (request_type_wfor_row.get("wfor") or "").strip()
                except Exception:
                    wfor = ""

        if not wfor:
            wfor = "General Request"

        # Insert Request
        cursor.execute("""
            INSERT INTO requests (user_id, request_type_id, wfor, filename, attachment, amount, status_id, stage_position_id)
            VALUES (%s, %s, %s, %s, %s, %s, 1, %s)
        """, (user_id, request_type_id, wfor, filename, file_blob, amount, stage_position_id))

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

        # return JSON for fetch
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": True, "request_id": request_id}), 200

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
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) AS c FROM requests WHERE WEEK(created_at)=WEEK(NOW())")
        weekly = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM requests WHERE MONTH(created_at)=MONTH(NOW())")
        monthly = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM requests WHERE YEAR(created_at)=YEAR(NOW())")
        yearly = cur.fetchone()["c"]

        cur.execute("""
            SELECT t.type_name, COUNT(*) as total
            FROM requests r
            JOIN request_types t ON r.request_type_id=t.request_type_id
            GROUP BY t.type_name
            ORDER BY total DESC
            LIMIT 1
        """)
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
            WHERE YEAR(r.created_at) = YEAR(CURDATE())
            AND UPPER(COALESCE(rs.status_name, '')) IN ('APPROVED', 'IN PROGRESS', 'PENDING_USER', 'COMPLETED')
        """
        query_params = []
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

        total_cost = sum(monthly_totals, Decimal("0"))
        total_request_budget = total_cost
        student_department_total_cost = student_total_cost + department_total_cost

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
                "monthly_totals": [float(total) for total in monthly_totals],
                "records": records,
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


@app.route("/api/reports/export")
def export_reports_csv():
    if "email" not in session:
        return Response("Unauthorized", status=401, mimetype="text/plain")

    role = (session.get("role") or "").strip()
    if role not in {"Admin", "AssistantAdmin"}:
        return Response("Forbidden: only Admin and AssistantAdmin can export reports", status=403, mimetype="text/plain")

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

    where_clause = where_map[selected_range]
    status_values = allowed_statuses[selected_status]
    status_placeholders = ", ".join(["%s"] * len(status_values))
    status_clause = f"AND s.status_name IN ({status_placeholders})"

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            f"""
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
            WHERE {where_clause}
            {status_clause}
            ORDER BY r.created_at DESC
        """
            ,
            status_values,
        )
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

            if template_mode == "FILLABLE" and template_blob and raw_form_json and request_type_id and not row.get("signed_pdf"):
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

        pdf_bytes = row.get("signed_pdf")
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

        ann_user_id = _normalize_optional_int(ann.get("actor_user_id"))
        if actor_user_id is not None and ann_user_id is not None:
            return ann_user_id == actor_user_id

        ann_position_id = _normalize_optional_int(ann.get("actor_position_id"))
        if actor_position_id is not None and ann_position_id is not None:
            return ann_position_id == actor_position_id

        ann_email = (ann.get("actor_email") or "").strip().lower()
        if actor_email and ann_email:
            return ann_email == actor_email

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
                r.stage_position_id,
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
            is_signed=is_signed
        )
    finally:
        cur.close()
        conn.close()


@app.route("/api/request/<int:request_id>/annotate", methods=["POST"])
def annotate_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = session.get("role")
    position_id = session.get("position_id")

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

        now = datetime.now()

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
    if session.get("role") not in ["Admin", "AssistantAdmin"]:
        return redirect("/")
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (id,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (id,)
        )
        cursor.execute("DELETE FROM request_types WHERE request_type_id = %s", (id,))
        conn.commit()
        flash("Request Type deleted.", "success")
    except Exception as e:
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

    tpl = request.files.get("template_file")
    if tpl and tpl.filename:
        template_filename = secure_filename(tpl.filename)
        template_blob = tpl.read()
        cursor.execute(
            """
            UPDATE request_types
            SET template_filename = %s, template_file = %s
            WHERE request_type_id = %s
            """,
            (template_filename, template_blob, type_id),
        )

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Update the Name
        cursor.execute(
            "UPDATE request_types SET type_name = %s WHERE request_type_id = %s",
            (new_name, type_id),
        )

        # reviewer/approver
        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (type_id,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (type_id,)
        )

        for i, pos_id in enumerate(reviewer_pos_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_reviewers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (type_id, pos_id, i),
                )

        for i, pos_id in enumerate(approver_pos_ids, start=1):
            if pos_id:
                cursor.execute(
                    """
                    INSERT INTO request_type_approvers (request_type_id, position_id, order_no)
                    VALUES (%s, %s, %s)
                    """,
                    (type_id, pos_id, i),
                )

        conn.commit()
        flash("Request type updated successfully", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("admin_dashboard"))


#  IT DASHBOARD ROUTES


def ensure_department_management_schema(cursor, conn):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS department_heads (
            dept_id INT NOT NULL PRIMARY KEY,
            user_id INT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    conn.commit()


@app.route("/IT")
@login_required
@role_required("IT", "SuperAdmin")
def it_dashboard():

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_user_account_control_schema(cursor, conn)
        ensure_department_management_schema(cursor, conn)

        cursor.execute(
                        """
                        SELECT COUNT(*) as count
                        FROM users
                        WHERE COALESCE(is_deleted, 0) = 0
                            AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
                        """
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
            ORDER BY u.user_id DESC
        """
        cursor.execute(query_users)
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM roles")
        roles = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
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
            WHERE u.user_id IS NULL
               OR (
                    COALESCE(u.is_deleted, 0) = 0
                    AND LOWER(COALESCE(u.email, '')) NOT LIKE '%@deleted.local'
               )
            ORDER BY d.dept_name ASC, u.email ASC
            """
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
            ORDER BY r.created_at DESC
            """
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
            ORDER BY u.email ASC
            """
        )
        active_user_rows = cursor.fetchall() or []

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

        cursor.execute("SELECT * FROM activity_logs ORDER BY created_at ASC LIMIT 15")
        notifications = cursor.fetchall()

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
        ensure_user_account_control_schema(cursor, conn)

        cursor.execute(
                        """
                        SELECT COUNT(*) as count
                        FROM users
                        WHERE COALESCE(is_deleted, 0) = 0
                            AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
                        """
                )
        total_users = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM departments")
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
        ensure_user_account_control_schema(cursor, conn)

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
            ORDER BY u.user_id DESC
            """
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
    role_name = request.form.get("role_name")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Insert into Roles table
        cursor.execute("INSERT INTO roles (role_name) VALUES (%s)", (role_name,))

        # Log the Activity
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            ("Role Created", f"New system role '{role_name}' added."),
        )

        conn.commit()
        flash(f"Role '{role_name}' created successfully!", "success")

    except mysql.connector.Error as err:
        conn.rollback()
        # Check for Duplicate Entry error
        if err.errno == 1062:
            flash(f"Role '{role_name}' already exists.", "danger")
        else:
            flash(f"Database Error: {err}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/create_position", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def create_position():
    position_name = request.form.get("position_name")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Insert into Positions table
        cursor.execute(
            "INSERT INTO positions (position_name) VALUES (%s)", (position_name,)
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
        # Check for Duplicate Entry error
        if err.errno == 1062:
            flash(f"Position '{position_name}' already exists.", "danger")
        else:
            flash(f"Database Error: {err}", "danger")

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
    rejection_msg = data.get("message") or request.form.get("message")

    if not new_status:
        return jsonify({"error": "Missing status"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT stage_position_id FROM requests WHERE request_id = %s",
            (request_id,),
        )
        auth_row = cursor.fetchone()
        if not auth_row:
            return jsonify({"error": "Request not found"}), 404

        current_stage_for_auth = auth_row.get("stage_position_id")
        if not is_admin_role:
            if actor_position_id_int is None:
                return jsonify({"error": "Forbidden"}), 403
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
            WHERE r.request_id = %s
            """,
            (request_id,),
        )
        _owner_row = cursor.fetchone() or {}
        requestor_email = (_owner_row.get("requestor_email") or "").strip()

        # Get current stage before changing (used for logs)
        current_stage_before = current_stage_for_auth
        
        # IN PROGRESS
        if new_status.lower() == "in progress":
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
                    "VALUES (%s, %s, %s, %s, 'IN_PROGRESS', NULL)",
                    (request_id, actor_user_id, actor_position_id, actor_email),
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

            conn.commit()
            return jsonify({"message": "Request marked as IN PROGRESS"})
        # If REJECTED mark rejected immediately
        
        if (new_status or "").lower() == "rejected":
            approved_recipients = []
            request_type_name = "Request"
            rejection_reason_text = (rejection_msg or "").strip() or "No reason was provided."

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

            # log action (for per-position stats/history)
            try:
                cursor.execute(
                    "INSERT INTO request_actions (request_id, actor_user_id, actor_position_id, actor_email, action, message) "
                    "VALUES (%s, %s, %s, %s, 'APPROVED', NULL)",
                    (request_id, actor_user_id, actor_position_id, actor_email),
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
                "SELECT request_type_id, stage_position_id FROM requests WHERE request_id = %s",
                (request_id,),
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

            _reviewers, _approvers, workflow = get_effective_workflow_positions(
                cursor,
                request_id=request_id,
                request_type_id=req_type_id,
            )

            if current_stage is not None:
                current_stage = int(current_stage)

            if not workflow:
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

                base_message += " Budget processing will run when completion is done by Purchasing or Representative."
                return jsonify(
                    {
                        "message": base_message,
                        "coo": coo_queue_result,
                        "xendit": {"processed": False, "reason": "release_actor_required"},
                    }
                )

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
                return jsonify({"message": "Request routed to first stage."})

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
                return jsonify({"message": "Request stage reset to first stage."})

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
                return jsonify({"message": "Approved. Moved to next stage."})
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

                if coo_queue_result.get("queued"):
                    base_message += " COO special approval was queued."
                elif coo_queue_result.get("reason") == "already_approved":
                    base_message += " COO special approval was already completed."
                elif coo_queue_result.get("reason") == "no_coo_recipient":
                    base_message += " No COO recipient was found for special approval notification."
                elif coo_queue_result.get("reason") == "email_delivery_failed":
                    base_message += " COO queue was created but email delivery failed. Use Special Access resend email."

                base_message += " Budget processing will run when completion is done by Purchasing or Representative."
                return jsonify({
                    "message": base_message,
                    "coo": coo_queue_result,
                    "xendit": {"processed": False, "reason": "release_actor_required"},
                })

        # Fallback: set status as requested
        cursor.execute(
            """
            UPDATE requests 
            SET status_id = %s, rejection_message = %s 
            WHERE request_id = %s
        """,
            (status_id, rejection_msg, request_id),
        )

        conn.commit()
        return jsonify({"message": f"Request {new_status} successfully"})

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request/<int:request_id>/send-back", methods=["POST"])
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
        cursor.execute(
            """
            SELECT r.request_id, r.request_type_id, r.stage_position_id, s.status_name
            FROM requests r
            JOIN request_status s ON s.status_id = r.status_id
            WHERE r.request_id = %s
            LIMIT 1
        """,
            (request_id,),
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
            WHERE request_id = %s
        """,
            (pending_status_id, target_stage, request_id),
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
        ensure_department_management_schema(cursor, conn)

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s LIMIT 1",
            (dept_id,),
        )
        existing = cursor.fetchone()
        if not existing:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute(
            "SELECT dept_id FROM departments WHERE LOWER(TRIM(dept_name))=LOWER(TRIM(%s)) AND dept_id<>%s LIMIT 1",
            (dept_name, dept_id),
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
        ensure_department_management_schema(cursor, conn)

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s LIMIT 1",
            (dept_id,),
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
              AND COALESCE(is_deleted, 0)=0
              AND LOWER(COALESCE(email, '')) NOT LIKE '%@deleted.local'
            LIMIT 1
            """,
            (head_user_id, dept_id),
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
        ensure_department_management_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s LIMIT 1",
            (dept_id,),
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
            LIMIT 1
            """,
            (user_id,),
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
        ensure_department_management_schema(cursor, conn)
        ensure_user_account_control_schema(cursor, conn)

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s LIMIT 1",
            (dept_id,),
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
            LIMIT 1
            """,
            (user_id,),
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


@app.route("/it/department/<int:dept_id>/delete", methods=["POST"])
@login_required
@role_required("IT", "SuperAdmin")
def it_delete_department(dept_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_department_management_schema(cursor, conn)

        cursor.execute(
            "SELECT dept_id, dept_name FROM departments WHERE dept_id=%s LIMIT 1",
            (dept_id,),
        )
        dept = cursor.fetchone()
        if not dept:
            flash("Department not found.", "danger")
            return redirect(url_for("it_dashboard"))

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE dept_id=%s", (dept_id,))
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
    cursor = conn.cursor()

    try:
        #  Insert the New User
        query_user = """
            INSERT INTO users (email, password, dept_id, role_id, position_id)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(
            query_user, (email, hashed_password, dept_id, role_id, position_id)
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
        cursor = conn.cursor()

        try:
            #  Create the Department
            cursor.execute(
                "INSERT INTO departments (dept_name) VALUES (%s)", (dept_name,)
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
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT request_type_id, type_name FROM request_types")
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

        cursor.execute(
            """
            SELECT request_type_id, type_name, template_mode, template_file
            FROM request_types
            WHERE request_type_id = %s
            LIMIT 1
            """,
            (request_type_id,),
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
            if (session.get("role") or "").strip() not in {"Admin", "AssistantAdmin", "SuperAdmin"}:
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
        return jsonify(
            {
                "success": True,
                "request_type_id": request_type_id,
                "type_name": request_type.get("type_name"),
                "template_mode": template_mode,
                "schema": schema,
                "template_fields": template_fields,
                "template_page_count": template_page_count,
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

        cursor.execute(
            """
            SELECT request_type_id, template_mode, template_filename, template_file
            FROM request_types
            WHERE request_type_id = %s
            LIMIT 1
            """,
            (request_type_id,),
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
@role_required("Admin", "AssistantAdmin", "SuperAdmin")
def request_type_form_builder_page():
    return render_template("request_type_form_builder.html")


@app.route("/request-type-field-mapper/<int:request_type_id>", methods=["GET"])
@login_required
@role_required("Admin", "AssistantAdmin", "SuperAdmin")
def request_type_field_mapper_page(request_type_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT request_type_id, type_name, template_mode
            FROM request_types
            WHERE request_type_id = %s
            LIMIT 1
            """,
            (request_type_id,),
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
        return jsonify({"error": "Unauthorized"})

    user_id = get_user_id(session["email"])
    if not user_id:
        return jsonify({"error": "User ID not found"})

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

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
                    ORDER BY r.created_at DESC
                    """

            cursor.execute(query, (user_id,))
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

            # Handle JSON
            req_type_id_raw = (request.form.get("request_type_id") or "").strip()
            template_data_json = (request.form.get("template_data_json") or "").strip()
            amount_raw = (
                request.form.get("template_total")
                or request.form.get("amount")
                or ""
            ).strip()
            request_budget = normalize_request_budget(request.form.get("request_budget"))
            request_department = (session.get("dept") or "").strip()
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

            if can_request_budget:
                if not request_budget:
                    return jsonify({"error": "Request budget is required"}), 400

                if not request_department:
                    return jsonify({"error": "Your account has no assigned department. Please contact admin."}), 400

                cursor.execute(
                    "SELECT dept_name FROM departments WHERE dept_name = %s LIMIT 1",
                    (request_department,),
                )
                if not (cursor.fetchone() or {}).get("dept_name"):
                    return jsonify({"error": "Invalid target department selected"}), 400

            cursor.execute(
                """
                SELECT request_type_id, template_mode, template_filename, template_file
                FROM request_types
                WHERE request_type_id = %s
                LIMIT 1
                """,
                (req_type_id,),
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
                if not request_type_template_blob:
                    return jsonify({"error": "Representative template is missing for this fillable request type."}), 400

                schema = get_request_type_fillable_schema(cursor, req_type_id)
                cleaned_payload, computed_total, has_total_sources, validation_error = validate_fillable_submission(
                    schema,
                    template_data_json,
                )
                if validation_error:
                    return jsonify({"error": validation_error}), 400

                validated_template_payload_json = json.dumps(cleaned_payload, ensure_ascii=True)
                if has_total_sources:
                    amount = float(computed_total)

                if request_type_template_blob:
                    file_data = build_filled_pdf_from_submission(
                        request_type_template_blob,
                        schema,
                        cleaned_payload,
                        total_amount=computed_total if has_total_sources else None,
                    )
                    filename = request_type_template_name or f"request_type_{req_type_id}_template.pdf"

            if amount is None:
                if not amount_raw:
                    return jsonify({"error": "Amount is required"}), 400

                try:
                    amount = float(amount_raw)
                except (TypeError, ValueError):
                    return jsonify({"error": "Invalid amount value"}), 400

            if amount < 0:
                return jsonify({"error": "Amount cannot be negative"}), 400

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

            # Get PENDING Status ID
            cursor.execute(
                "SELECT status_id FROM request_status WHERE status_name='PENDING'"
            )
            status_row = cursor.fetchone()
            if not status_row:
                return jsonify({"error": "Pending status not configured in DB"}), 500

            status_id = status_row["status_id"]

            if not wfor:
                try:
                    cursor.execute(
                        """
                        SELECT wfor
                        FROM request_types
                        WHERE request_type_id = %s
                        LIMIT 1
                        """,
                        (req_type_id,),
                    )
                    request_type_row = cursor.fetchone() or {}
                    wfor = (request_type_row.get("wfor") or "").strip()
                except Exception:
                    try:
                        cursor.execute(
                            """
                            SELECT `for` AS wfor
                            FROM request_types
                            WHERE request_type_id = %s
                            LIMIT 1
                            """,
                            (req_type_id,),
                        )
                        request_type_row = cursor.fetchone() or {}
                        wfor = (request_type_row.get("wfor") or "").strip()
                    except Exception:
                        wfor = ""

            if not wfor:
                wfor = "General Request"

            cursor.execute(
                """
                INSERT INTO requests (request_type_id, user_id, wfor, filename, attachment, amount, status_id, stage_position_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
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
            return jsonify({"message": "Request created successfully"}), 201

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
        except Exception as _:
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

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # Monthly totals
        cur.execute("""
            SELECT DATE_FORMAT(created_at,'%b') AS month,
            COUNT(*) AS total
            FROM requests
            WHERE YEAR(created_at)=YEAR(NOW())
            GROUP BY MONTH(created_at)
            ORDER BY MONTH(created_at)
        """)

        rows = cur.fetchall()

        months=[r["month"] for r in rows]
        totals=[r["total"] for r in rows]


        # Request types
        cur.execute("""
            SELECT t.type_name,COUNT(*) as total
            FROM requests r
            JOIN request_types t ON r.request_type_id=t.request_type_id
            GROUP BY t.type_name
        """)

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
    cursor.execute("SELECT dept_name FROM departments ORDER BY dept_name")
    departments = cursor.fetchall()
    cursor.close()
    conn.close()

    if request.method == "POST":
        if not session.get("otp_verified"):
            return render_template(
                "signup.html",
                message="Please verify OTP first",
                departments=departments,
            )

        e = request.form["email"].strip().lower()
        p = request.form["pass"]
        cp = request.form["cpass"]
        dept_name = request.form.get("dept", "").strip()

        ad = "phinmaed.com"

        if not dept_name:
            return render_template(
                "signup.html",
                message="Please Select your Department",
                departments=departments,
            )
        if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", e):
            return render_template(
                "signup.html", message="Invalid email address", departments=departments
            )
        if e.split("@")[1] != ad:
            return render_template(
                "signup.html",
                message="Use your phinmaed account",
                departments=departments,
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
            )
        if p != cp:
            return render_template(
                "signup.html", message="Passwords do not match", departments=departments
            )

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT user_id FROM users WHERE email=%s", (e,))
            if cursor.fetchone():
                return render_template(
                    "signup.html",
                    message="Email already used please login",
                    departments=departments,
                )

            cursor.execute(
                "SELECT dept_id FROM departments WHERE dept_name=%s", (dept_name,)
            )
            dept = cursor.fetchone()
            if not dept:
                return render_template(
                    "signup.html", message="Invalid department", departments=departments
                )
            dept_id = dept["dept_id"]

            # Default Role/Position
            cursor.execute("SELECT role_id FROM roles WHERE role_name='User'")
            role_row = cursor.fetchone()
            role_id = role_row["role_id"] if role_row else 1

            cursor.execute(
                "SELECT position_id FROM positions WHERE position_name='None'"
            )
            pos_row = cursor.fetchone()
            position_id = pos_row["position_id"] if pos_row else 1

            hp = hash_user_password(p)

            cursor.execute(
                "INSERT INTO users (email, password, dept_id, role_id, position_id) VALUES (%s,%s,%s,%s,%s)",
                (e, hp, dept_id, role_id, position_id),
            )
            created_user_id = cursor.lastrowid
            conn.commit()

            session["email"] = e
            session["user_id"] = created_user_id
            session["dept"] = dept_name
            session["role"] = "User"
            session["position"] = "None"
            session.pop("otp_verified", None)

            return redirect("/udashboard")

        except Exception as ex:
            print("Signup error:", ex)
            return render_template(
                "signup.html", message="Something went wrong", departments=departments
            )
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("signup.html", departments=departments)


# web login
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        password = request.form["pass"]

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            ensure_user_account_control_schema(cursor, conn)

            cursor.execute(
                """
                SELECT u.user_id, u.email, u.password, r.role_name, 
                p.position_name, p.position_id, d.dept_name,
                COALESCE(u.is_banned, 0) AS is_banned,
                COALESCE(u.is_deleted, 0) AS is_deleted
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                JOIN positions p ON u.position_id = p.position_id
                LEFT JOIN departments d ON u.dept_id = d.dept_id
                WHERE u.email = %s
            """,
                (e,),
            )
            user = cursor.fetchone()

            if user and int(user.get("is_deleted") or 0) == 1:
                return render_template("login.html", message="Account has been deleted. Please contact IT.")

            if user and int(user.get("is_banned") or 0) == 1:
                return render_template("login.html", message="Account is banned. Please contact IT.")

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
                session["position"] = user["position_name"]
                session["position_id"] = user["position_id"]
                session["dept"] = user["dept_name"]
                return redirect("/")
            
            else:
                jsonify({"message": "Login attept"})
                return render_template("login.html", message="Invalid credentials")
                
        finally:
            cursor.close()
            conn.close()
    return render_template("login.html", message=request.args.get("message"))


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
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
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

    ad = "phinmaed.com"

    if not e or not p or not cp or not dept_name or not signup_otp_token:
        return jsonify({"error": "Please fill all fields"}), 400

    if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", e):
        return jsonify({"error": "Invalid email address"}), 400

    if "@" not in e or e.split("@", 1)[1] != ad:
        return jsonify({"error": "Please use your phinmaed email"}), 400

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
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (e,))
        if cursor.fetchone():
            return jsonify({"error": "Email already used, please login"}), 409

        cursor.execute("SELECT dept_id FROM departments WHERE dept_name=%s", (dept_name,))
        dept = cursor.fetchone()
        if not dept:
            return jsonify({"error": "Invalid department"}), 400
        dept_id = dept["dept_id"]

        cursor.execute("SELECT role_id FROM roles WHERE role_name='User'")
        role_row = cursor.fetchone()
        role_id = role_row["role_id"] if role_row else 1

        cursor.execute("SELECT position_id FROM positions WHERE position_name='None'")
        pos_row = cursor.fetchone()
        position_id = pos_row["position_id"] if pos_row else 1

        hp = hash_user_password(p)
        cursor.execute(
            "INSERT INTO users (email, password, dept_id, role_id, position_id) VALUES (%s,%s,%s,%s,%s)",
            (e, hp, dept_id, role_id, position_id),
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

    if not e or not pw:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.user_id, u.email, u.password, r.role_name,
            p.position_name, d.dept_name
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            WHERE u.email = %s
            """,
            (e,),
        )
        user = cursor.fetchone()

        if not user or not verify_user_password(user["password"], pw):
            return jsonify({"error": "Invalid credentials"}), 401

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

        token = create_token(user["email"])

        return jsonify({
            "token": token,
            "user": {
                "email": user["email"],
                "dept_name": user.get("dept_name"),
                "position_name": user.get("position_name"),
                "role_name": user.get("role_name"),
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
        """,
            (request.user_email,),
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
    user_id = get_user_id(request.user_email)
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
    user_id = get_user_id(request.user_email)
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

        return jsonify(notifications)
    finally:
        cursor.close()
        conn.close()


@app.route("/logout")
def logout():
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


CDR_FIELDS = {
    "date_needed": (0, 180, 310, 12),
    "requesting_dept": (0, 300, 310, 14),
    "cdr_number": (0, 440, 310, 10),
    "payee": (0, 110, 280, 10),
    "requested_by_name": (0, 270, 80, 9),
    "requested_by_date": (0, 280, 70, 9),
    "approved_by_name": (0, 400, 80, 9),
    "approved_by_date": (0, 400, 70, 9),
}

PR_FIELDS = {
    "to": (0, 50, 530, 10),
    "date_prepared": (0, 40, 480, 12),
    "date_required": (0, 130, 480, 10),
    "requested_by": (0, 30, 400, 10),
    "date": (0, 45, 380, 10),
    "dept": (0, 75, 370, 10),
}


def generate_test_cdr_stamped_pdf(
    template_path="CHECK DISBURSEMENT REQUEST.pdf", out_path="CDR_test_stamped.pdf"
):
    with open(template_path, "rb") as f:
        template_bytes = f.read()

    values = {
        "date_needed": "date_needed",
        "requesting_dept": "dept",
        "cdr_number": "CDR-0001",
        "payee": "payee",
        "requested_by_name": "request_name",
        "requested_by_date": "current_date",
        "signature": "app/revsignature",
        "approved_by_date": "presentdate",
    }

    text_items = build_text_items_from_field_map(CDR_FIELDS, values)
    overlay_bytes = make_overlay_pdf(
        template_bytes, text_items=text_items, image_items=[]
    )
    final_bytes = merge_overlay(template_bytes, overlay_bytes)

    with open(out_path, "wb") as f:
        f.write(final_bytes)


    

if __name__ == "__main__":
    debug_mode = (os.environ.get("FLASK_DEBUG", "true").strip().lower() == "true")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=debug_mode,
        use_reloader=debug_mode,
    ) 