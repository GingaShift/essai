import os
import smtplib
from email.mime.text import MIMEText


FROM_EMAIL = "pythonaeeproject@atomicmail.io"

# ⚠️ IMPORTANT : ces 2 valeurs doivent venir des "SMTP settings" atomicmail
SMTP_SERVER = os.getenv("SMTP_SERVER", "mail.atomicmail.io")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_ENCRYPTION = os.getenv("SMTP_ENCRYPTION", "starttls")  # "starttls" ou "ssl"


def send_email_smtp(to_email: str, subject: str, body: str):
    password = os.getenv("ATOMICMAIL_PASSWORD")
    if not password:
        raise RuntimeError("ATOMICMAIL_PASSWORD n'est pas défini (variable d'environnement)")

    msg = MIMEText(body)
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject

    if SMTP_ENCRYPTION.lower() == "ssl":
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.login(FROM_EMAIL, password)
        server.send_message(msg)
        server.quit()
        return

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(FROM_EMAIL, password)
    server.send_message(msg)
    server.quit()


def send_test_email():
    send_email_smtp(
        to_email="pythonaeeproject@atomicmail.io",
        subject="TEST - Projet ANSSI (Python)",
        body="Si tu lis ça, l'envoi SMTP fonctionne ✅"
    )
