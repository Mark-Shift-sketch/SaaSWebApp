from flask import Flask, session, redirect, request, render_template, url_for
from config import Email, password, get_connection
import smtplib
from email.message import EmailMessage
import secrets
import hmac
import random


def sent_otp(receiver, otp):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
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
    
    
# resend otp if more than 2 minute not recieve 
def c():
    email = request.form['email']

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        # Generic response to avoid account enumeration
        return "If eligible, OTP will be sent"

    cursor.execute("""SELECT TIMESTAMPDIFF(SECOND, created_at, NOW())
        FROM otp_codes WHERE email=%s
    """, (email,))
    rs = cursor.fetchone()

    if rs and rs[0] < 120:
        return f"Please wait {120 - rs[0]} seconds before resending"

    otp = secrets.randbelow(900000) + 100000

    cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
    cursor.execute(
        "INSERT INTO otp_codes (email, otp) VALUES (%s, %s)",
        (email, otp)
    )
    conn.commit()

    sent_otp(email, otp)

    cursor.close()
    conn.close()

    return "If eligible, OTP will be sent"


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
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(Email, password)

        if status == 'APPROVED':
            subject = "Request Approved"
            body = f"""Good day,

            Your request has been APPROVED. 
            Please check the web app for details.

            This is an automated message. Do not reply."""
        else:
            subject = "Request Rejected"
            body = f"""Good day,

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
        server = smtplib.SMTP('smtp.gmail.com', 587)
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

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(Email, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("CC email error:", e)
        return False
    
