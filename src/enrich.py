import requests # Je charge la bibliothèque qui permet d'aller sur internet (requêtes HTTP)
import certifi # Je charge une liste de certificats SSL fiables pour éviter les erreurs HTTPS 
from typing import Dict, Any #On précise le type de données qu'on manipule 
from typing import Optional, List, Tuple #pareil 

def fetch_mitre_cve(cve_id: str, timeout: int = 20) -> Dict[str, Any]: #fonction qui prend une cve et qui renvoie toutes les infos MITRE sous forme de dictionnaire 
    """
    Récupère les informations d’une CVE depuis l’API officielle de MITRE.

    Concrètement :
        - Je construis l’URL de l’API à partir de l’identifiant CVE
        - Je fais une requête HTTP GET
        - Je transforme la réponse JSON en dictionnaire Python

    Args:
        cve_id: identifiant CVE (ex: "CVE-2023-24488")
        timeout: temps maximum d’attente pour la requête HTTP

    Returns:
        Un dictionnaire Python contenant toutes les données MITRE de la CVE.

    Raises:
        requests.RequestException si la requête HTTP échoue
        ValueError si la réponse n’est pas un JSON valide
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}" #L'url de l'api mitre à partir de l'id CVE

    response = requests.get(
        url,
        timeout=timeout,
        verify=certifi.where()
    )
    # Je fais une requête HTTP GET vers l'api  que je limite dans le temps et je vérifie le certificat SSL pour éviter les erreurs
    
    response.raise_for_status() #j'arrete si la requête échoue 

    return response.json() #Je transforme la réponse en dictionnaire, je renvoie le json brut sans modifier 

def _safe_get(d: dict, path: List, default=None): 
    """
    Accède à une valeur dans un dict JSON via une liste de clés.
    Si une clé manque -> renvoie default.
    """
    cur = d #je pars du dictionnaire principal
    try:
        for key in path: #je chercher clé par clé 
            cur = cur[key]
        return cur #Si tout s'est bien passé, je renvoie la valeur 
    except Exception: #Si une clé manque à n'importe quel niveau, je renvoie la valeur default 
        return default


def parse_mitre(data: Dict[str, Any]) -> Dict[str, Any]: #Je prend le JSON MITRE et je le transforme en dictionnaire propre
    """
    Extrait les champs principaux d'une réponse MITRE (CVE API).
    Renvoie un dict 'plat' (facile à mettre en CSV).
    """

    # Description 
    description = "Non disponible" #Valeur par défaut si rien n'est trouvé
    descriptions = _safe_get(data, ["containers", "cna", "descriptions"], []) or [] #Je vais chercher la liste des descriptions dans le JSON
    if descriptions:
        description = descriptions[0].get("value", description) #Si une description existe, je prends la première sinon je garde "Non disponible"

    #CVSS + Severity
    cvss_score: Optional[float] = None #Je prépare les valeurs par défaut
    base_severity = "Non disponible"

    metrics = _safe_get(data, ["containers", "cna", "metrics"], []) or [] #Je récupère les métriques CVSS (s'il yen a)
    for m in metrics: #Je parcours chaque blocs de métriques.
        # Certaines CVE utilisent cvssV3_1, d'autres cvssV3_0, parfois autre
        for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"): #Je teste les différentes versions de CVSS
            if k in m:
                cvss_score = m[k].get("baseScore", None)
                base_severity = m[k].get("baseSeverity", base_severity)
                break
            #Si je trouve un score, je le récupère et je sors de la boucle
        if cvss_score is not None:
            break

    #CWE (type de faille)
    cwe_id = "Non disponible" #valeur par défaut
    cwe_desc = "Non disponible" #valeur par défaut
    problem_types = _safe_get(data, ["containers", "cna", "problemTypes"], []) or [] #Je vais chercher les types vulnérabilités
    if problem_types:
        descs = problem_types[0].get("descriptions", []) or [] #je prend la première catégorie
        if descs:
            cwe_id = descs[0].get("cweId", cwe_id)
            cwe_desc = descs[0].get("description", cwe_desc)
        #Je récupère l'id CWE et sa description si elles existent 
        
    #Affected (vendor/product/versions)
    vendor = "Non disponible" #valeur par défaut
    product = "Non disponible"  #valeur par défaut
    versions_affectees = "Non disponible" #valeur par défaut

    affected = _safe_get(data, ["containers", "cna", "affected"], []) or [] #Je récupère la liste des produits affectés
    if affected:
        a0 = affected[0]  # on prend le premier bloc pour rester simple à ce stade
        vendor = a0.get("vendor", vendor) #je récupère l'éditeur
        product = a0.get("product", product) #je récupère le produit 

        versions = a0.get("versions", []) or []
        vers = [v.get("version") for v in versions if v.get("status") == "affected" and v.get("version")] #je recupère uniquement les versions réellement vulnérables
        if vers:
            versions_affectees = ", ".join(sorted(set(vers)))

    return {
        "description": description,
        "cvss_score": cvss_score,
        "base_severity": base_severity,
        "cwe_id": cwe_id,
        "cwe_desc": cwe_desc,
        "vendor": vendor,
        "product": product,
        "versions_affectees": versions_affectees,
    }
    
    #On renvoit un dictionnaire propre
    

def fetch_epss(cve_id: str, timeout: int = 20) -> Optional[float]: # fonction qui renvoie la probabilité d'exploitation
    """
    Récupère le score EPSS (probabilité d'exploitation) pour une CVE
    depuis l'API officielle FIRST.

    Returns:
        score EPSS entre 0 et 1, ou None si non disponible
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}" #on construit l'url epss

    try:
        response = requests.get(url, timeout=timeout) #Je fais une requête HTTP GET vers l'api epss
        response.raise_for_status() #j'arrete si la requête échoue
        data = response.json()#Je transforme la réponse en dictionnaire Python

        epss_data = data.get("data", []) #Je récupère la liste des scores
        if epss_data: #Je renvoie le score s'il existe
            return epss_data[0].get("epss")

    except Exception as e:
        print(f"[WARNING] EPSS indisponible pour {cve_id} → {e}") #on attarape si l'epss n'est pas dispo

    return None # et renvoie none

def enrich_cve(cve_id: str) -> Dict[str, Any]: #fonction chef d'orcheste qui combine mitre + epss
    """
    Combine MITRE + EPSS et renvoie un dict plat prêt pour un CSV.
    """
    mitre_data = fetch_mitre_cve(cve_id) #je recupère les données mitre
    parsed = parse_mitre(mitre_data) #je les parse pour structurer les données
    parsed["epss"] = fetch_epss(cve_id) #j'ajoute la probabilité d'exploitation
    parsed["cve"] = cve_id #j'ajoute l'id cve
    return parsed #je renvoie la totalité des données combinées

