import requests 
import feedparser
URL_RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"

resp = requests.get(URL_RSS_AVIS, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
resp.raise_for_status()

rss = feedparser.parse(resp.text)

bulletins = []

for entry in rss.entries:
    bulletins.append({
        "type": "avis",
        "title": entry.title,
        "published": getattr(entry, "published", None),
        "link": entry.link,
    })

print("Bulletins récupérés :", len(bulletins))
print("Exemple (1er bulletin) :", bulletins[0])

