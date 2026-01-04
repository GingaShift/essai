import re
import time
from typing import List, Set, Dict, Any
import requests


CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


def bulletin_to_json_url(bulletin_url: str) -> str:
    url = bulletin_url.strip()
    if not url.endswith("/"):
        url += "/"
    if not url.endswith("json/"):
        url += "json/"
    return url


def extract_cves_from_json_data(data: Dict[str, Any]) -> Set[str]:
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
