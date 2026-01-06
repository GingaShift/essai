from src.mailer import send_email_smtp

send_email_smtp(
    to_email="projectmailaee@gmail.com",
    subject="TEST - Projet Python ANSSI",
    body="Si tu lis ce mail, l'envoi SMTP Gmail depuis Python fonctionne ✅"
)

print("OK: email envoyé (si aucune erreur n'est affichée).")
