import os
import smtplib
from email.mime.text import MIMEText

from dotenv import load_dotenv

load_dotenv()  # charge le fichier .env à la racine du projet


def send_email_smtp(to_email: str, subject: str, body: str):
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_encryption = os.getenv("SMTP_ENCRYPTION", "starttls").lower()

    from_email = os.getenv("FROM_EMAIL")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not from_email:
        raise RuntimeError("FROM_EMAIL manquant dans .env")
    if not smtp_username or not smtp_password:
        raise RuntimeError("SMTP_USERNAME/SMTP_PASSWORD manquants dans .env")

    msg = MIMEText(body, _charset="utf-8")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    if smtp_encryption == "ssl":
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=20)
    else:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
        server.ehlo()
        server.starttls()
        server.ehlo()

    server.login(smtp_username, smtp_password)
    server.send_message(msg)
    server.quit()


def send_test_email():
    send_email_smtp(
        to_email=os.getenv("TEST_TO_EMAIL", os.getenv("FROM_EMAIL", "")),
        subject="TEST - Projet ANSSI (Python)",
        body="Si tu lis ça, l'envoi SMTP Gmail fonctionne ✅"
    )
