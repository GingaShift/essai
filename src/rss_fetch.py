from typing import List, Dict # On annonce ce qu'on va utiliser (à voir si on garde)
import requests # outil qui permet d'aller chercher les données sur internet (requêtes HTTP)
import certifi #Paquet de certificats SSL fiables pour éviter les erreurs HTTPs
import feedparser  # Librairie qui sait lire et comprendre un flux RSS(XML)

FEED_URL = "https://www.cert.ssi.gouv.fr/feed/" # Je définis l'adresse du flux RSS officiel de l'ANSSI il liste les derniers bulletins publiés


def fetch_all_bulletins() -> List[Dict[str, str]]: # Fonction qui va récupérer tous les bulletins récents.
    """
    
    
    Récupère les bulletins ANSSI via le flux RSS global.
    On télécharge le flux avec requests+certifi (SSL OK),
    puis on parse avec feedparser à partir des bytes (pas de SSL).
    
    
    
    """
    headers = { #Je prépare des en-têtes HTTP pour la requête
        "User-Agent": "Mozilla/5.0 (compatible; ANSSI-Vuln-Intel/1.0)", #Je me présente comme un vrai client (navigateur /outil légitime)
        "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",  #Je dis au serveur que j'accepte XML/RSS
    }

    resp = requests.get(FEED_URL, headers=headers, timeout=20, verify=certifi.where()) 
    #Je fais une requête HTTP GET vers le flux RSS, j'utilise l'url officielle du flux, j'envoie les entêtes définis plus haut, je limite le temps à 20 secondes et ensuite je force l'utilsiation des certificats SSL fiables (on évite les erreurs HTTPS)
    
    resp.raise_for_status() #Si la réponse n'est pas correcte, on déclenche une erreur.

    rss = feedparser.parse(resp.content) #Je donne le contenu XML téléchargé à feedparser. Il va ensuite transformer le RSS en structure Python (objets, listes, champs)

    if getattr(rss, "bozo", False): #Je vérifie si feedparser a détecté un problème de formatage du flux RSS (bozo = flux mal formé)
        print(f"[WARNING] RSS bozo: {getattr(rss, 'bozo_exception', None)}") #Si oui, j'affiche un averto mais non bloquant

    bulletins: List[Dict[str, str]] = [] # Je crée une liste vide pour stocker les bulletins extraits
    for entry in getattr(rss, "entries", []): #Je parcours chaque entrée (bulletin) du flux RSS
        link = getattr(entry, "link", "") #Je récupère le lien du bulletin

        if ("/alerte/" not in link) and ("/avis/" not in link): #Si le lien n'est ni une alerte ni un avis, je passe au suivant, ca permet d'éliminer les pages "actualités" qui ne contiennent aps de cves exploitables
            continue

        bulletin_type = "alerte" if "/alerte/" in link else "avis" #Si l'url contient /alerte/, je marque le bulletin comme "alerte". sinon, c'est un "avis"

        #Constuction du dictionnaire représentant le bulletin
        bulletins.append({ #J'ajoute le bulletin à la liste
            "type": bulletin_type, #Type du bulletin (alerte ou avis)
            "title": getattr(entry, "title", ""), #Titre du bulletin
            "description": getattr(entry, "summary", ""), #Résumé/description du bulletin
            "link": link, #Lien vers le bulletin
            "published": getattr(entry, "published", ""), #Date de publication du bulletin
        })
    return bulletins #Je renvoie la liste de tous les bulletins extraits du flux RSS
