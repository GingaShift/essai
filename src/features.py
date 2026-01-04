from typing import Optional
import pandas as pd


def add_risk_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ajoute une colonne 'risk_score' = cvss_score * epss.
    - Si cvss_score ou epss est manquant/non numérique => risk_score = NaN
    Retourne une copie du DataFrame (ne modifie pas df en place).
    """
    out = df.copy()

    # Force les colonnes en numérique (si elles sont des strings dans le CSV)
    out["cvss_score"] = pd.to_numeric(out.get("cvss_score"), errors="coerce")
    out["epss"] = pd.to_numeric(out.get("epss"), errors="coerce")

    out["risk_score"] = out["cvss_score"] * out["epss"]
    return out


def add_risk_level(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ajoute une colonne 'risk_level' à partir de 'risk_score'.
    Seuils simples (pragmatiques) :
        - risk_score >= 7  => CRITIQUE
        - risk_score >= 4  => ÉLEVÉ
        - risk_score >= 2  => MOYEN
        -  sinon            => FAIBLE
    Si risk_score est NaN => 'Non disponible'
    """
    out = df.copy()

    rs = pd.to_numeric(out.get("risk_score"), errors="coerce")

    def _level(x: Optional[float]) -> str:
        if pd.isna(x):
            return "Non disponible"
        if x >= 7:
            return "CRITIQUE"
        if x >= 4:
            return "ÉLEVÉ"
        if x >= 2:
            return "MOYEN"
        return "FAIBLE"

    out["risk_level"] = rs.apply(_level)
    return out


def top_cves(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """
    Retourne un DataFrame 'Top N' des CVE les plus risquées.
    - Trie par risk_score décroissant
    - Garde les colonnes les plus utiles
    """
    cols = [c for c in [
        "cve", "risk_score", "risk_level", "cvss_score", "epss",
        "base_severity", "cwe_id", "vendor", "product", "title", "link", "published"
    ] if c in df.columns]

    tmp = df.copy()
    tmp["risk_score"] = pd.to_numeric(tmp.get("risk_score"), errors="coerce")

    top = (tmp.dropna(subset=["risk_score"]).sort_values("risk_score", ascending=False).drop_duplicates(subset=["cve"]).head(n))

    return top[cols]


def vendor_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Produit un tableau agrégé par éditeur (vendor) :
    - nb_cve_uniques
    - risk_moyen
    - nb_critique (risk_level == CRITIQUE)
    - nb_eleve  (risk_level == ÉLEVÉ)
    """
    tmp = df.copy()

    if "vendor" not in tmp.columns:
        tmp["vendor"] = "Non disponible"

    tmp["risk_score"] = pd.to_numeric(tmp.get("risk_score"), errors="coerce")

    # Une seule ligne par CVE pour éviter de compter plusieurs fois la même CVE
    base = tmp.drop_duplicates(subset=["cve"])

    summary = (
        base.groupby("vendor", dropna=False)
            .agg(
                nb_cve_uniques=("cve", "nunique"),
                risk_moyen=("risk_score", "mean"),
                nb_critique=("risk_level", lambda s: (s == "CRITIQUE").sum()),
                nb_eleve=("risk_level", lambda s: (s == "ÉLEVÉ").sum()),
            )
            .reset_index()
            .sort_values(["nb_critique", "nb_eleve", "risk_moyen", "nb_cve_uniques"], ascending=False)
    )

    return summary
