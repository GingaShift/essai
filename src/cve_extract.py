import re
import time
from typing import List, Set, Dict, Any
import requests


CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


def bulletin_to_json_url(bulletin_url: str) -> str:
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
    url = bulletin_url.strip()
    if not url.endswith("/"):
        url += "/"
    if not url.endswith("json/"):
        url += "json/"
    return url


def extract_cves_from_json_data(data: Dict[str, Any]) -> Set[str]:
    
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
    
    cves: Set[str] = set()

    if isinstance(data.get("cves"), list):
        for item in data["cves"]:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str) and CVE_REGEX.fullmatch(name):
                    cves.add(name)

    cves.update(CVE_REGEX.findall(str(data)))
    return cves


def extract_cves(bulletin_url: str, timeout: int = 15, delay: float = 2.0) -> List[str]:
    
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
    
    json_url = bulletin_to_json_url(bulletin_url)

    try:
        response = requests.get(json_url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        return sorted(extract_cves_from_json_data(data))

    except requests.RequestException as e:
        print(f"[ERROR] HTTP {json_url} → {e}")
        return []
    except ValueError as e:
        print(f"[ERROR] JSON invalide {json_url} → {e}")
        return []
    finally:
        time.sleep(delay)
