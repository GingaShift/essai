from typing import List, Dict
import requests
import certifi
import feedparser

FEED_URL = "https://www.cert.ssi.gouv.fr/feed/"


def fetch_all_bulletins() -> List[Dict[str, str]]:
    """
    
    
    Récupère les bulletins ANSSI via le flux RSS global.
    On télécharge le flux avec requests+certifi (SSL OK),
    puis on parse avec feedparser à partir des bytes (pas de SSL).
    
    
    
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ANSSI-Vuln-Intel/1.0)",
        "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    }

    resp = requests.get(FEED_URL, headers=headers, timeout=20, verify=certifi.where())
    resp.raise_for_status()

    rss = feedparser.parse(resp.content)

    if getattr(rss, "bozo", False):
        print(f"[WARNING] RSS bozo: {getattr(rss, 'bozo_exception', None)}")

    bulletins: List[Dict[str, str]] = []
    for entry in getattr(rss, "entries", []):
        link = getattr(entry, "link", "")

        if ("/alerte/" not in link) and ("/avis/" not in link):
            continue

        bulletin_type = "alerte" if "/alerte/" in link else "avis"

        bulletins.append({
            "type": bulletin_type,
            "title": getattr(entry, "title", ""),
            "description": getattr(entry, "summary", ""),
            "link": link,
            "published": getattr(entry, "published", ""),
        })
    return bulletins
