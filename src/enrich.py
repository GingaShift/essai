import requests
import certifi
from typing import Dict, Any
from typing import Optional, List, Tuple

def fetch_mitre_cve(cve_id: str, timeout: int = 20) -> Dict[str, Any]:
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
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    response = requests.get(
        url,
        timeout=timeout,
        verify=certifi.where()
    )
    response.raise_for_status()

    return response.json()

def _safe_get(d: dict, path: List, default=None):
    """
    Accède à une valeur dans un dict JSON via une liste de clés.
    Si une clé manque -> renvoie default.
    """
    cur = d
    try:
        for key in path:
            cur = cur[key]
        return cur
    except Exception:
        return default


def parse_mitre(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrait les champs principaux d'une réponse MITRE (CVE API).
    Renvoie un dict 'plat' (facile à mettre en CSV).
    """

    # ---- Description ----
    description = "Non disponible"
    descriptions = _safe_get(data, ["containers", "cna", "descriptions"], []) or []
    if descriptions:
        description = descriptions[0].get("value", description)

    # ---- CVSS + Severity ----
    cvss_score: Optional[float] = None
    base_severity = "Non disponible"

    metrics = _safe_get(data, ["containers", "cna", "metrics"], []) or []
    for m in metrics:
        # Certaines CVE utilisent cvssV3_1, d'autres cvssV3_0, parfois autre
        for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if k in m:
                cvss_score = m[k].get("baseScore", None)
                base_severity = m[k].get("baseSeverity", base_severity)
                break
        if cvss_score is not None:
            break

    # ---- CWE ----
    cwe_id = "Non disponible"
    cwe_desc = "Non disponible"
    problem_types = _safe_get(data, ["containers", "cna", "problemTypes"], []) or []
    if problem_types:
        descs = problem_types[0].get("descriptions", []) or []
        if descs:
            cwe_id = descs[0].get("cweId", cwe_id)
            cwe_desc = descs[0].get("description", cwe_desc)

    # ---- Affected (vendor/product/versions) ----
    vendor = "Non disponible"
    product = "Non disponible"
    versions_affectees = "Non disponible"

    affected = _safe_get(data, ["containers", "cna", "affected"], []) or []
    if affected:
        a0 = affected[0]  # on prend le premier bloc pour rester simple à ce stade
        vendor = a0.get("vendor", vendor)
        product = a0.get("product", product)

        versions = a0.get("versions", []) or []
        vers = [v.get("version") for v in versions if v.get("status") == "affected" and v.get("version")]
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
    
if __name__ == "__main__":
    test_cve = "CVE-2023-24488"
    print(f"Test MITRE pour {test_cve}")

    data = fetch_mitre_cve(test_cve)
    parsed = parse_mitre(data)

    print("Description:", parsed["description"][:120], "...")
    print("CVSS:", parsed["cvss_score"], "Severity:", parsed["base_severity"])
    print("CWE:", parsed["cwe_id"], "-", parsed["cwe_desc"])
    print("Vendor:", parsed["vendor"], "| Product:", parsed["product"])
    print("Versions affectées:", parsed["versions_affectees"])

def fetch_epss(cve_id: str, timeout: int = 20) -> Optional[float]:
    """
    Récupère le score EPSS (probabilité d'exploitation) pour une CVE
    depuis l'API officielle FIRST.

    Returns:
        score EPSS entre 0 et 1, ou None si non disponible
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        epss_data = data.get("data", [])
        if epss_data:
            return epss_data[0].get("epss")

    except Exception as e:
        print(f"[WARNING] EPSS indisponible pour {cve_id} → {e}")

    return None

def enrich_cve(cve_id: str) -> Dict[str, Any]:
    """
    Combine MITRE + EPSS et renvoie un dict plat prêt pour un CSV.
    """
    mitre_data = fetch_mitre_cve(cve_id)
    parsed = parse_mitre(mitre_data)
    parsed["epss"] = fetch_epss(cve_id)
    parsed["cve"] = cve_id
    return parsed

