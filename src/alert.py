import pandas as pd

def add_alert_fields(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # sécurité: conversion numérique (si jamais ça arrive en string)
    df["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce")
    df["epss"] = pd.to_numeric(df.get("epss"), errors="coerce")

    def compute_alert(row):
        cvss = row["cvss_score"]
        epss = row["epss"]

        # Valeurs manquantes
        if pd.isna(cvss) and pd.isna(epss):
            return "LOW", "cvss&epss_missing"

        if pd.isna(epss):
            # on retombe sur CVSS seul
            if cvss >= 9:
                return "HIGH", "cvss>=9_epss_missing"
            if cvss >= 7:
                return "MEDIUM", "cvss>=7_epss_missing"
            return "LOW", "low_or_missing"

        if pd.isna(cvss):
            # EPSS seul
            if epss >= 0.5:
                return "CRITICAL", "epss>=0.5_cvss_missing"
            if epss >= 0.2:
                return "HIGH", "epss>=0.2_cvss_missing"
            return "LOW", "low_or_missing"

        # Règles combinées (principales)
        if (epss >= 0.5) or (cvss >= 9 and epss >= 0.1):
            return "CRITICAL", "epss>=0.5_or_(cvss>=9&epss>=0.1)"
        if cvss >= 7 and epss >= 0.05:
            return "HIGH", "cvss>=7&epss>=0.05"
        if cvss >= 7 and epss < 0.05:
            return "MEDIUM", "cvss>=7&epss<0.05"

        return "LOW", "below_thresholds"

    df[["alert_level", "alert_reason"]] = df.apply(
        lambda r: pd.Series(compute_alert(r)),
        axis=1
    )
    return df
