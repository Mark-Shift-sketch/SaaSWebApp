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
    email = request.form['email']

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        return "Email already registered"

    cursor.execute("""SELECT TIMESTAMPDIFF(SECOND, created_at, NOW())
        FROM otp_codes WHERE email=%s
    """, (email,))
    rs = cursor.fetchone()

    if rs and rs[0] < 120:
        return f"Please wait {120 - rs[0]} seconds before resending"

    otp = random.randint(100000, 999999)

    cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
    cursor.execute(
        "INSERT INTO otp_codes (email, otp) VALUES (%s, %s)",
        (email, otp)
    )
    conn.commit()

    sent_otp(email, otp)

    cursor.close()
    conn.close()

    return "OTP sent successfully"


    # verify otp
def verify():
    email = request.form['email']
    userotp = request.form['otp']

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT otp FROM otp_codes
        WHERE email=%s
        AND TIMESTAMPDIFF(MINUTE, created_at, NOW()) <= 10
    """, (email,))
    rs = cursor.fetchone()

    if rs and hmac.compare_digest(str(rs[0]), str(userotp)):
        cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
        conn.commit()

        # Connects to sign up
        session['otp_verified'] = True
        session['otp_email'] = email

        return "OTP verified successfully"

    return "Invalid or expired OTP"

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
    
