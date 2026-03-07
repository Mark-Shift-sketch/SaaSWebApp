import json
import logging
from flask import (
    Flask,
    session,
    redirect,
    request,
    render_template,
    url_for,
    flash,
    jsonify,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from dotenv import load_dotenv
from sendotp import srotp, verify
from config import Email, password, get_connection
import mysql.connector
from sendotp import send_cc_email
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from sendotp import send_cc_email_with_blob
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from reportlab.pdfgen import canvas as _rl_canvas
from reportlab.lib.utils import ImageReader as _ImageReader
from pypdf import PdfReader as _PdfReader, PdfWriter as _PdfWriter
from flask import Response

import datetime
import os
import re
import base64
from io import BytesIO
from flask import send_file
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


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
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "false"),
    PERMANENT_SESSION_LIFETIME=int(os.environ.get("PERMANENT_SESSION_LIFETIME", "3600")),
)

# CSRF protection for HTML forms
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
except Exception:
    csrf = None  

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(get_remote_address, app=app, default_limits=[])
except Exception:
    limiter = None


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


#def get_key():
#    if request.headers.get("Authorization"):
#        return request.headers.get("Authorization")
#    return get_remote_address()


#limiter = Limiter(
#    app, key_func=get_remote_address,
#    default_limits=["200 per day","50 per hour"]
#)
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("File too large. Maximum allowed size is 20MB.", "danger")
    return redirect(request.referrer or "/")


def create_token(email):
    return serializer.dumps({"email": email})


def verify_token(token, max_age=60 * 60 * 24 * 7):
    data = serializer.loads(token, max_age=max_age)
    return data["email"]


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
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-site"
    # Basic CSP 
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
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


# OTP Routes 
if limiter:
    srotp_view = limiter.limit("5 per minute")(srotp)
    verify_view = limiter.limit("10 per minute")(verify)
else:
    srotp_view = srotp
    verify_view = verify

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
        flash("Login successful", "success")
        return redirect("/gsd_dashboard")

    elif role in ["Dean", "Reviewer"]:
        flash("Login successful", "success")
        return redirect("/dean")

    elif role in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        flash("Login successful", "success")
        return redirect("/admin")

    elif role == "IT":
        flash("Login successful", "success")
        return redirect("/IT")
    else:
        flash("Login successful", "success")
        return redirect("/udashboard")


@app.route("/dean")
def dean_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    if (session.get("role") or "").strip() not in ["Dean", "Program Head", "Reviewer"]:
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

            ORDER BY r.created_at DESC
            LIMIT 50
            """, (position_id, position_id, position_id, position_id, position_id))
        r_requests = cursor.fetchall()

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

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    user_id = get_user_id(session["email"])

    try:
        cursor.execute("""
            SELECT request_type_id, type_name, template_filename, template_mode
            FROM request_types
            ORDER BY type_name ASC
        """)
        request_types = cursor.fetchall()

        # user table list WITH status
        cursor.execute("""
            SELECT
                r.request_id,
                rt.type_name,
                r.filename,
                s.status_name,
                r.created_at
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s
            ORDER BY r.request_id DESC
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
            ORDER BY r.created_at DESC
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
                    f"Currently being reviewed by: {req['current_stage']}"
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

    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT
                ra.action_id AS id,
                ra.created_at,

                CONCAT('Request ', ra.action) AS title,

                CONCAT(
                    'REQ#', ra.request_id, ' ',
                    LOWER(ra.action), ' by ',
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
            ORDER BY ra.created_at DESC
            LIMIT 200
        """)

        rows = cur.fetchall()

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
                rt.type_name,
                r.filename,
                s.status_name,
                r.created_at
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s
            ORDER BY r.request_id DESC
        """, (user_id,))
        all_request = cursor.fetchall()

        for r in all_request:
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
            ORDER BY r.created_at DESC
            LIMIT 50
            """, (position_id,))
        recent_requests = cursor.fetchall()

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

    role = session.get("role")
    user_id = session.get("user_id")
    position_id = session.get("position_id")

    if role not in ["Admin", "AssistantAdmin", "SuperAdmin"]:
        return redirect("/")

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
            r.filename,
            r.created_at,
            u.email,
            d.dept_name,
            s.status_name,
            rt.type_name,
            r.stage_position_id,
            sp.position_name AS stage_position_name,

            -- latest action by MY position (if any)
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

            ORDER BY r.created_at DESC
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

        # My requests
        query_my = """
            SELECT
                r.request_id,
                r.filename,
                r.created_at,
                s.status_name,
                rt.type_name,
                r.rejection_message
            FROM requests r
            LEFT JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
            LIMIT 50
        """
        cursor.execute(query_my, (user_id,))
        my_requests = cursor.fetchall()

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

        # CC recipients (Admins + AssistantAdmins)
        cursor.execute("""
            SELECT u.email
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE r.role_name IN ('Admin', 'AssistantAdmin')
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
            my_requests=my_requests,
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


@app.route("/api/request/<int:request_id>/workflow", methods=["GET"])
def get_request_workflow(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    role = session.get("role")
    position = session.get('position_id')
    if role not in ["AssistantAdmin"] and position not in ["Purchasing"]:
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

        # prefer per-request override reviewers
        cursor.execute(
            """
            SELECT position_id
            FROM request_workflow_reviewers
            WHERE request_id = %s
            ORDER BY order_no ASC
        """,
            (request_id,),
        )
        rev = [row["position_id"] for row in cursor.fetchall()]

        #  fallback to request_type reviewers
        if not rev:
            cursor.execute(
                """
                SELECT position_id
                FROM request_type_reviewers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
            """,
                (req["request_type_id"],),
            )
            rev = [row["position_id"] for row in cursor.fetchall()]

        # prefer per-request override approvers
        cursor.execute(
            """
            SELECT position_id
            FROM request_workflow_approvers
            WHERE request_id = %s
            ORDER BY order_no ASC
        """,
            (request_id,),
        )
        app = [row["position_id"] for row in cursor.fetchall()]

        # fallback to request_type approvers
        if not app:
            cursor.execute(
                """
                SELECT position_id
                FROM request_type_approvers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
            """,
                (req["request_type_id"],),
            )
            app = [row["position_id"] for row in cursor.fetchall()]

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

    # Template mode 
    template_mode = (request.form.get("template_mode") or "FILLABLE").upper()
    if template_mode not in ("FILLABLE", "DOWNLOAD"):
        template_mode = "FILLABLE"

    if not type_name:
        flash("Request type name is required.", "danger")
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

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Insert request type WITH template + mode
        cursor.execute(
            """
            INSERT INTO request_types (type_name, template_filename, template_file, template_mode)
            VALUES (%s, %s, %s, %s)
            """,
            (type_name, template_filename, template_blob, template_mode),
        )
        new_type_id = cursor.lastrowid

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

    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin_dashboard"))

@app.route("/create_request", methods=["POST"])
def create_request():
    if "user_id" not in session:
        # JSON for fetch
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return redirect("/login")

    user_id = session["user_id"]
    request_type_id = request.form.get("request_type_id")
    file = request.files.get("file")

    filename = None
    file_blob = None

    #  upload
    if file and file.filename:
        # PDF-only checks
        if not allowed_file(file.filename) or file.mimetype != "application/pdf":
            msg = "Attachment not supported. Please use PDF."
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

        # Insert Request
        cursor.execute("""
            INSERT INTO requests (user_id, request_type_id, filename, attachment, status_id, stage_position_id)
            VALUES (%s, %s, %s, %s, 1, %s)
        """, (user_id, request_type_id, filename, file_blob, stage_position_id))
        conn.commit()

        # return JSON for fetch
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": True, "request_id": cursor.lastrowid}), 200

        flash("Request submitted successfully!", "success")
        return redirect("/udashboard")

    except Exception:
        conn.rollback()
        logger.exception("create_request failed")
        msg = "Internal server error"
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"success": False, "message": msg}), 500
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
    
# Download template

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
            SELECT r.request_id, r.user_id, r.stage_position_id, r.filename, r.attachment,
                a.signed_pdf
            FROM requests r
            LEFT JOIN request_annotations a ON a.request_id = r.request_id
            WHERE r.request_id = %s
        """,
            (request_id,),
        )
        row = cursor.fetchone()

        if not row or not row.get("attachment"):
            return Response("No attachment found", status=404, mimetype="text/plain")


        allowed = False

        # Admin always allowed
        if role in (
            "Admin",
            "SuperAdmin",
            "AssistantAdmin",
            "Assistant",
            "GSDHead",
            "Dean",
            "Reviewer",
        ):
            allowed = True

        # If you are the CURRENT assigned stage (reviewer/approver), allow
        elif position_id and row.get("stage_position_id") == int(position_id):
            allowed = True

        # Requester always allowed
        elif row.get("user_id") == user_id:
            allowed = True

        if not allowed:
            return Response("Access Denied", status=403, mimetype="text/plain")


        pdf_bytes = row["signed_pdf"] or row["attachment"]
        # View in browser
        force_download = request.args.get("download") == "1"

        import mimetypes

        mime_type, _ = mimetypes.guess_type(row.get("filename") or "")

        return send_file(
            BytesIO(pdf_bytes),
            download_name=row.get("filename") or f"request_{request_id}_attachment.pdf",
            mimetype=mime_type or "application/pdf",
            as_attachment=force_download,
        )
    finally:
        cursor.close()
        conn.close()


@app.get("/api/request/<int:request_id>/annotations")
def get_annotations(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT annotations_json FROM request_annotations WHERE request_id=%s",
            (request_id,),
        )
        row = cur.fetchone()
        if not row or not row.get("annotations_json"):
            return jsonify({"annotations": []})
        return jsonify({"annotations": json.loads(row["annotations_json"])})
    finally:
        cur.close()
        conn.close()


@app.post("/api/request/<int:request_id>/annotations")
def save_annotations(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    annotations = data.get("annotations") or []

    if not isinstance(annotations, list):
        return jsonify({"error": "Invalid annotations"}), 400

    #  limit count for safety
    if len(annotations) > 200:
        return jsonify({"error": "Too many items"}), 400

    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # Load base PDF
        cur.execute(
            "SELECT attachment FROM requests WHERE request_id=%s", (request_id,)
        )
        r = cur.fetchone()
        if not r or not r.get("attachment"):
            return jsonify({"error": "Original PDF not found"}), 404

        template_pdf_bytes = r["attachment"]

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

        for it in annotations:
            t = (it.get("type") or "").strip().lower()
            page = int(it.get("page") or 0)
            x = float(it.get("x") or 0)
            y = float(it.get("y") or 0)

            if t == "text":
                text = (it.get("text") or "").strip()
                if not text:
                    continue
                font = int(it.get("font") or 12)
                text_items.append(
                    {"page": page, "x": x, "y": y, "text": text, "font": font}
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
            (json.dumps(annotations), signed_pdf, request_id),
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
                a.signed_pdf
            FROM requests r
            LEFT JOIN request_annotations a 
                ON a.request_id = r.request_id
            WHERE r.request_id=%s
        """, (request_id,))
        row = cur.fetchone()
        if not row:
            return "Not found", 404

        allowed = False

        # Admin always allowed
        if role in ("Admin", "SuperAdmin"):
            allowed = True

        # If you are the CURRENT assigned stage (reviewer/approver), allow
        elif position_id and row.get("stage_position_id") == int(position_id):
            allowed = True

        # Requester always allowed
        elif row.get("user_id") == user_id:
            allowed = True

        if not allowed:
            return "Access Denied", 403

        return render_template(
            "annotate.html",
            request_id=request_id,
            filename=row.get("filename"),
            is_signed=bool(row.get("signed_pdf"))
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
        cursor.execute(
            "SELECT request_id, attachment FROM requests WHERE request_id=%s",
            (request_id,),
        )
        r = cursor.fetchone()
        if not r or not r.get("attachment"):
            return jsonify({"error": "Original PDF not found"}), 404

        template_pdf_bytes = r["attachment"]

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
                as_attachment=True,
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


@app.route("/IT")
@login_required
@role_required("IT", "SuperAdmin")
def it_dashboard():

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) as count FROM users")
        result = cursor.fetchone()
        total_users = result["count"] if result else 0
        new_users_count = 5

        query_users = """
            SELECT u.user_id, u.email, d.dept_name, r.role_name, p.position_name
            FROM users u
            JOIN departments d ON u.dept_id = d.dept_id
            JOIN roles r ON u.role_id = r.role_id
            JOIN positions p ON u.position_id = p.position_id
            ORDER BY u.user_id DESC LIMIT 20
        """
        cursor.execute(query_users)
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM roles")
        roles = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()

        cursor.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 15")
        notifications = cursor.fetchall()

        return render_template(
            "IT.html",
            users=users,
            total_users=total_users,
            new_users_count=new_users_count,
            departments=departments,
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
        cursor.execute("SELECT COUNT(*) as count FROM users")
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

def get_all_users_for_admin():
    """Return all users for IT user management."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.user_id, u.email, u.full_name, u.role, u.position_id, p.position_name, u.dept_id, d.dept_name
            FROM users u
            LEFT JOIN positions p ON p.position_id = u.position_id
            LEFT JOIN departments d ON d.dept_id = u.dept_id
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
def create_role():
    # Security check
    if "email" not in session:
        return redirect("/login")

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
def create_position():
    # Security check
    if "email" not in session:
        return redirect("/login")

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
def update_request_status(request_id):
    
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or request.form.get("status") or "").strip()
    rejection_msg = data.get("message") or request.form.get("message")

    if not new_status:
        return jsonify({"error": "Missing status"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
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
        actor_position_id = session.get("position_id")
        actor_email = session.get("email")

        # Get current stage before changing (used for logs)
        cursor.execute(
            "SELECT stage_position_id FROM requests WHERE request_id = %s",
            (request_id,),
        )
        _stage_row = cursor.fetchone()
        current_stage_before = _stage_row["stage_position_id"] if _stage_row else None
        
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
            conn.commit()
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

            # reviewers first, then approvers
            cursor.execute(
                """
                SELECT position_id
                FROM request_type_reviewers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
                """,
                (req_type_id,),
            )
            reviewers = [
                int(r["position_id"])
                for r in cursor.fetchall()
                if r.get("position_id") is not None
            ]

            cursor.execute(
                """
                SELECT position_id
                FROM request_type_approvers
                WHERE request_type_id = %s
                ORDER BY order_no ASC
                """,
                (req_type_id,),
            )
            approvers = [
                int(a["position_id"])
                for a in cursor.fetchall()
                if a.get("position_id") is not None
            ]

            workflow = []
            for position in reviewers + approvers:
                if position not in workflow:
                    workflow.append(position)

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
                conn.commit()
                return jsonify(
                    {"message": "Request approved (no workflow configured)."}
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
                return jsonify({"message": "Request fully approved. Completed"})

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

@app.route("/create_user", methods=["POST"])
def create_user():

    if "email" not in session:
        return redirect("/login")

    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    dept_id = request.form["dept_id"]
    role_id = request.form["role_id"]
    position_id = request.form["position_id"]

    # Hash the password
    hashed_password = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16
    )

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
def create_dept():
    # Security check
    if "email" not in session:
        return redirect("/login")

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
                        r.filename,
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
            # Handle JSON
            req_type_id = request.form.get("request_type_id")

            # Handle File
            if "attachment" in request.files:
                file = request.files["attachment"]
                filename = secure_filename(file.filename)
                file_data = file.read()
            else:
                # Fallback if no file uploaded
                filename = request.form.get("filename")
                file_data = None

            if not req_type_id:
                return jsonify({"error": "Request Type ID is required"})

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

            cursor.execute(
                """
                INSERT INTO requests (request_type_id, user_id, filename, attachment, status_id, stage_position_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
                (
                    req_type_id,
                    user_id,
                    filename,
                    file_data,
                    status_id,
                    stage_position_id,
                ),
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

        conn.commit()
        return jsonify({"message": "Admin marked completed. Waiting for user confirmation."})

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
def cc_completed_request(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"})

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

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # allow only Admin/AssistantAdmin recipients
       # placeholders = ",".join(["%s"] * len(to_emails))
       # cursor.execute(
        #    f"""
         #   SELECT LOWER(u.email) AS email
          #  FROM users u
           # JOIN roles r ON u.role_id = r.role_id
            #WHERE LOWER(u.email) IN ({placeholders})
          #  AND r.role_name IN ('Admin','AssistantAdmin')
        #""",
         #   tuple(to_emails),
        #)
        #allowed_rows = cursor.fetchall()
        #allowed_set = set([row["email"] for row in allowed_rows])

        #not_allowed = [e for e in to_emails if e not in allowed_set]
        #if not_allowed:
        #    return (
         #       jsonify(
          #          {"error": f"Not allowed recipient(s): {', '.join(not_allowed)}"}
           #     ),
            #    400,
            #)

        # fetch request + attachment blob
        cursor.execute(
            """
            SELECT
                r.request_id,
                r.filename,
                r.attachment,
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

        if not req.get("attachment"):
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
                file_blob=req["attachment"],
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

        if user and check_password_hash(user["password"], current_pass):
            new_hash = generate_password_hash(
                new_pass, method="pbkdf2:sha256", salt_length=16
            )
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

        allow_domain = "phinmaed.com"

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
        if e.split("@")[1] != allow_domain:
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

            hp = generate_password_hash(p, method="pbkdf2:sha256", salt_length=16)

            cursor.execute(
                "INSERT INTO users (email, password, dept_id, role_id, position_id) VALUES (%s,%s,%s,%s,%s)",
                (e, hp, dept_id, role_id, position_id),
            )
            conn.commit()

            session["email"] = e
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
@limiter.limit("5/minute")
def login():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        password = request.form["pass"]

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT u.user_id, u.email, u.password, r.role_name, 
                p.position_name, p.position_id, d.dept_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                JOIN positions p ON u.position_id = p.position_id
                LEFT JOIN departments d ON u.dept_id = d.dept_id
                WHERE u.email = %s
            """,
                (e,),
            )
            user = cursor.fetchone()

            if user and check_password_hash(user["password"], password):
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
    return render_template("login.html")


# Mobile API Endpoints (Connected to flutter)
@app.route("/api/mobile/login", methods=["POST"])
@csrf.exempt
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

        if not user or not check_password_hash(user["password"], pw):
            return jsonify({"error": "Invalid credentials"}), 401

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
        ORDER BY created_at DESC
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
                "message": f"Currently being reviewed by: {req['current_stage']}",
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
            c.drawString(float(item["x"]), float(item["y"]), str(item.get("text", "")))

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


test_text = [
    {"page": 0, "x": 240, "y": 330, "text": "DATE_NEEDE", "font": 10},
    {"page": 0, "x": 340, "y": 300, "text": "DEpT_HERE", "font": 10},
    {"page": 0, "x": 470, "y": 330, "text": "CDR-))!", "font": 10},
]

@app.get("/api/ping")
def ping():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=(os.environ.get("FLASK_DEBUG", "true").lower() == "true"),
    ) 

