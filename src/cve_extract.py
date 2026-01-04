import re #l'outil regex pour repérer des motifs de text (ici les CVE)
import time # on charge l'outil "pause" pour ralentir entre les requêtes 
from typing import List, Set, Dict, Any 
import requests #librairie qui permet de faire des requêtes HTTP pour aller cherhcher le JSON sur le site 


CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


def bulletin_to_json_url(bulletin_url: str) -> str: #fonction qui transforme un lien de bulletin (page web ) en lien JSON
    """
        Convertit l’URL "HTML" d’un bulletin CERT-FR (ANSSI) en URL de sa version JSON.

        Le site CERT-FR expose généralement deux versions d’un bulletin :
        - Page lisible par un humain : https://www.cert.ssi.gouv.fr/avis/CERTFR-XXXX-AVI-YYYY/
        - Version JSON (machine-readable) : .../json/

        Cette fonction :
        1) Nettoie l’URL (strip)
        2) S’assure qu’elle se termine par un "/"
        3) Ajoute "json/" si ce n’est pas déjà le cas

        Args:
        bulletin_url: URL du bulletin (souvent la page HTML du bulletin).

        Returns:
        L’URL pointant vers la ressource JSON associée au bulletin.
    
    """
    url = bulletin_url.strip() # Je nettoie l'url en enlevant les espaces au début et à la fin
    if not url.endswith("/"): #Si l'url ne finit pas pr /, je l'ajoute pour éviter un lien mal formé
        url += "/" #ajout de /
    if not url.endswith("json/"): #Si l'url ne finit pas déjà par json/, je l'ajoute pour pointer vers la version JSON du bulletin 
        url += "json/"
    return url #Je renvoie l'url JSON finale.


def extract_cves_from_json_data(data: Dict[str, Any]) -> Set[str]: # fonction qui reçoit un dictionnaire JSON et va en extraire les CVEs.
    
    """
    Extrait l'ensemble des identifiants CVE présents dans un dictionnaire JSON ANSSI.

    Stratégie en 2 niveaux (robuste) :
    - Méthode 1 (structurée) : lecture de la clé "cves" si elle existe.
        Dans les JSON CERT-FR, on retrouve souvent une liste "cves" de la forme :
        "cves": [{"name": "CVE-2024-xxxx"}, ...]
        -> C’est la source la plus fiable quand elle est présente.

    - Méthode 2 (fallback) : recherche par expression régulière dans tout le JSON converti en string.
        -> Permet de récupérer des CVE même si la structure JSON change ou si "cves" est absent.

    On retourne un set afin de :
    - dédupliquer automatiquement les CVE
    - combiner les résultats des deux méthodes sans doublons

    Args:
        data: Dictionnaire Python issu du JSON (response.json()).

    Returns:
        Un ensemble (set) de CVE uniques trouvées dans les données.
    
    """
    
    cves: Set[str] = set() #Je crée un set vide pour stocker les CVEs uniques (sans doublons)

    if isinstance(data.get("cves"), list): #Je vérifie si dans le JSON, la clé "cves" existe et si c'est une liste.
        for item in data["cves"]: # Je parcours chaque élément de cette liste
            if isinstance(item, dict): #Je vérifie que l'élément est un dictionnaire
                name = item.get("name") #Je récupère la valeur associée à la clé "name"
                if isinstance(name, str) and CVE_REGEX.fullmatch(name): # Je vérifie que cette valeur est une string et qu'elle correspond au format CVE
                    cves.add(name) #Si tout est OK, j'ajoute cette CVE au set

    cves.update(CVE_REGEX.findall(str(data))) #Je convertis tout le dictionnaire JSON en string et j'utilise la regex pour trouver toutes les occurrences de CVE. Je les ajoute au set (déduplication automatique)
    return cves #On renvoit le set de CVE trouvées.


def extract_cves(bulletin_url: str, timeout: int = 15, delay: float = 2.0) -> List[str]: # fonction qui prend un lien de bulletin et renvoie la liste des CVEs
    
    """
    Récupère le JSON d’un bulletin CERT-FR (ANSSI) et renvoie la liste des CVE extraites.

    Pipeline :
        1) Transforme l'URL HTML du bulletin en URL JSON via bulletin_to_json_url()
        2) Télécharge le JSON avec requests.get()
        3) Parse le JSON (response.json())
        4) Extrait les CVE avec extract_cves_from_json_data()
        5) Renvoie une liste triéede CVE uniques

    Gestion d'erreurs :
        - Erreur réseau / HTTP / timeout : catch requests.RequestException -> retourne []
        - JSON invalide : catch ValueError -> retourne []
    Rate limiting :
        - Une pause "delay" est appliquée en finally, même si une erreur survient.
        Cela évite de spammer le site en boucle lors de problèmes.

    Args:
        bulletin_url: URL du bulletin (souvent la page HTML).
        timeout: Durée maxs pour la requête HTTP avant abandon.
        delay: Pauses après chaque appel, pour limiter la charge et respecter le rate limiting.

    Returns:
        Liste triée de CVE (strings) pour ce bulletin.
        Retourne une liste vide [] en cas de problème.
    
    """
    
    json_url = bulletin_to_json_url(bulletin_url) # Je transforme le lien bulletin en lien JSON

    try: #Je tente au cas où ca plante (prévention d'erreurs )
        response = requests.get(json_url, timeout=timeout) #Je fais une requête HTTP GET pour récupérer le JSON du bulletin
        response.raise_for_status()
        data = response.json() #Je transforme la réponse en dictionnaire Python (JSON to dict)
        return sorted(extract_cves_from_json_data(data)) #J'extrait les CVEs du dictionnaire JSON et je les renvoie sous forme de liste triée

    except requests.RequestException as e: #Si problème réseau, timeout, http pas ok...
        print(f"[ERROR] HTTP {json_url} → {e}") # On affiche l'erreur et je renvoie la liste vide 
        return [] 
    except ValueError as e: #Si la réponse nest pas un JSON valide...
        print(f"[ERROR] JSON invalide {json_url} → {e}") #on affiche l'erreur et je renvoie la liste vide
        return []
    finally:
        time.sleep(delay) # quoi qu'il arrive, je fais une pause avant la prochaine requête pour éviter de surcharger le site
