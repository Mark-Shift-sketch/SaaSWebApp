from flask import session, request
from config import Email, password, get_connection
import smtplib
from email.message import EmailMessage
import hmac
import random
import os


ALLOWED_EMAIL_DOMAIN = str(os.environ.get("ALLOWED_EMAIL_DOMAIN", "phinmaed.com")).strip().lower()
EMAIL_DOMAIN_HELPER_MESSAGE = str(
    os.environ.get("EMAIL_DOMAIN_HELPER_MESSAGE", "Please use youre phinmaed email")
).strip()
SMTP_HOST = str(os.environ.get("SMTP_HOST", "smtp.gmail.com")).strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))


def _is_allowed_system_email(email):
    normalized_email = (email or "").strip().lower()
    if "@" not in normalized_email:
        return False
    local_part, domain = normalized_email.rsplit("@", 1)
    return bool(local_part) and domain == ALLOWED_EMAIL_DOMAIN


def sent_otp(receiver, otp):
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(Email, password)

        message = f"""Subject: OTP Verification
                    From: {Email}
                    To: {receiver}

                    Your OTP is: {otp}

                    System generated. Do not reply.
                    """
        server.sendmail(Email, receiver, message)
        server.quit()
        return True
    except Exception as e:
        print("Email error:", e)
        return False


def _get_request_value(key):
    form_value = request.form.get(key)
    if form_value is not None and str(form_value).strip() != "":
        return str(form_value).strip()

    data = request.get_json(silent=True) or {}
    value = data.get(key)
    if value is None:
        return ""
    return str(value).strip()


def request_signup_otp(email):
    email = (email or "").strip().lower()
    if not email:
        return "Email is required", False
    if not _is_allowed_system_email(email):
        return EMAIL_DOMAIN_HELPER_MESSAGE, False

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return "Email already registered", False

        cursor.execute(
            """
            SELECT TIMESTAMPDIFF(SECOND, created_at, NOW())
            FROM otp_codes
            WHERE email=%s
            """,
            (email,),
        )
        rs = cursor.fetchone()

        if rs and rs[0] < 120:
            return f"Please wait {120 - rs[0]} seconds before resending", False

        otp = random.randint(100000, 999999)

        cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
        cursor.execute(
            "INSERT INTO otp_codes (email, otp) VALUES (%s, %s)",
            (email, otp),
        )
        conn.commit()

        if not sent_otp(email, otp):
            return "Failed to send OTP. Please try again.", False

        return "OTP sent successfully", True
    finally:
        cursor.close()
        conn.close()


def verify_signup_otp(email, userotp, consume=True):
    email = (email or "").strip().lower()
    userotp = (userotp or "").strip()

    if not email or not userotp:
        return "Email and OTP are required", False
    if not _is_allowed_system_email(email):
        return EMAIL_DOMAIN_HELPER_MESSAGE, False

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT otp FROM otp_codes
            WHERE email=%s
            AND TIMESTAMPDIFF(MINUTE, created_at, NOW()) <= 10
            """,
            (email,),
        )
        rs = cursor.fetchone()

        if rs and hmac.compare_digest(str(rs[0]), str(userotp)):
            if consume:
                cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
                conn.commit()
            return "OTP verified successfully", True

        return "Invalid or expired OTP", False
    finally:
        cursor.close()
        conn.close()
    
    
def srotp():
    email = _get_request_value("email").lower()
    message, _ok = request_signup_otp(email)
    return message


    # verify otp
def verify():
    email = _get_request_value("email").lower()
    userotp = _get_request_value("otp")

    message, ok = verify_signup_otp(email, userotp, consume=True)
    if ok:
        session['otp_verified'] = True
        session['otp_email'] = email

    return message

# send email for approval or rejected request
def send_request_email(receiver, status):
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(Email, password)

        if status == 'APPROVED':
            subject = "Request Approved"
            body = """Good day,

            Your request has been APPROVED. 
            Please check the web app for details.

            This is an automated message. Do not reply."""
        else:
            subject = "Request Rejected"
            body = """Good day,

            Your request has been REJECTED. 
            Please check the web app for details.

            This is an automated message. Do not reply."""

        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(Email, receiver, message)
        server.quit()
        return True
    except Exception as e:
        print("Email sending error:", e)
        return False
    
def send_cc_email(receiver, subject, body):
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(Email, password)

        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(Email, receiver, message)
        server.quit()
        return True
    except Exception as e:
        print("CC email error:", e)
        return False
    


def send_cc_email_with_blob(receiver, subject, body, filename, file_blob):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = Email
        msg["To"] = receiver
        msg.set_content(body)

        if file_blob and filename:
            msg.add_attachment(
                file_blob,
                maintype="application",
                subtype="octet-stream",
                filename=filename
            )

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(Email, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("CC email error:", e)
        return False


def send_pending_action_reminder_email(receiver, request_id, request_type, stage_name, age_hours=24):
    receiver = (receiver or "").strip()
    if not receiver:
        return False

    req_type_text = (request_type or "Request").strip() or "Request"
    stage_text = (stage_name or "Assigned Stage").strip() or "Assigned Stage"
    try:
        age_hours_int = max(1, int(age_hours or 24))
    except (TypeError, ValueError):
        age_hours_int = 24

    subject = f"Reminder: Request #{request_id} is pending your action"
    body = (
        "Good day,\n\n"
        f"Request #{request_id} ({req_type_text}) has been pending in your stage ({stage_text}) for at least {age_hours_int} hour(s).\n"
        "Please review and take action (approve/reject) in the system dashboard.\n\n"
        "This is an automated reminder."
    )

    return send_cc_email(receiver, subject, body)
    
