import os #lire les variables d'environnement dans .env
import smtplib #J'importe la bibliothèque standard qui permet d'envoyer des mails via le protocole SMTP
from email.mime.text import MIMEText #Classe qui permet de créer un mail texte correctement formaté

from dotenv import load_dotenv #fonction qui sait charger automatiquement les variables définies dans un fichier .env

load_dotenv()  # charge le fichier .env à la racine du projet


def send_email_smtp(to_email: str, subject: str, body: str): #fonction qui envoie un email vers une adresse donnée avec un sujet et un contenu texte
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com") #Je lis l'adresse du serveur SMTP depuis.env, ou j'utilise GMAIl par défaut
    smtp_port = int(os.getenv("SMTP_PORT", "587")) #Je lis le port SMTP et je le convertis en entier  
    smtp_encryption = os.getenv("SMTP_ENCRYPTION", "starttls").lower() #Encore du technique...

    from_email = os.getenv("FROM_EMAIL") #Je récupère l'adresse email utilisée comme un expéditeur
    smtp_username = os.getenv("SMTP_USERNAME") #Je recupère l'identifiant SMTP (souvent identique à l'email)
    smtp_password = os.getenv("SMTP_PASSWORD")# Je recupère le mot de passe SMTP (ici mot de passe d'application Gmail)

    if not from_email: #Je vérifie que l'adresse expéditeur est bien définie
        raise RuntimeError("FROM_EMAIL manquant dans .env") #J'arrête le programme avec une erreur claire si ce n'est pas le cas
    if not smtp_username or not smtp_password: #Je vérifie que les ids smtp sont bien présents
        raise RuntimeError("SMTP_USERNAME/SMTP_PASSWORD manquants dans .env") # J'arrête le programme si l'authentification smtp est impossible

    msg = MIMEText(body, _charset="utf-8") #je crée un email texte avec encodage utf-8 supporte plein d'affichage genre emoji
    msg["From"] = from_email #Je définis l'adresse de l'expéditeur dans l'en-tête du mail
    msg["To"] = to_email #Je définis le destinataire du mail
    msg["Subject"] = subject #Je définis le sujet

    if smtp_encryption == "ssl": #Je teste si le mode SSL direct est demandé
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=20) #Je crée une connexion SMTP sécurisée dès le départ (SSL)
    else:#Sinon j'utilise une autre méthode standard
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
        server.ehlo()
        server.starttls()
        server.ehlo()

    server.login(smtp_username, smtp_password) #On s'authentifie auprès du serveur SMTP avec les identifiants
    server.send_message(msg) #Envoie du message construit précédement
    server.quit()  #Je ferme proprement la connexion SMTP





# ¨--------------------------------- PREMIER TEST DENVOIET-------------------------------
def send_test_email():
    send_email_smtp(
        to_email=os.getenv("TEST_TO_EMAIL", os.getenv("FROM_EMAIL", "")),
        subject="TEST - Projet ANSSI (Python)",
        body="Si tu lis ça, l'envoi SMTP Gmail fonctionne "
    )
