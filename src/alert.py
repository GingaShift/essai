import pandas as pd #Car je vais manipule un dataframe

def add_alert_fields(df: pd.DataFrame) -> pd.DataFrame: #Je définis une fonction qui prend un dataframe et renvoie un dataframe avec des colonnes d'alerte ajoutées
    df = df.copy() #Je copie le dataframe pour pas modifier l'originale

    # sécurité: conversion numérique (si jamais ça arrive en string)
    df["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce")
    df["epss"] = pd.to_numeric(df.get("epss"), errors="coerce")

    def compute_alert(row): #Petite fonction interne qui calcule le niveau d'alerte pour une seule ligne (CVE)
        cvss = row["cvss_score"] #Je recupère le score CVSS de la ligne
        epss = row["epss"] #Je recupère le score EPSS de la ligne

        # Valeurs manquantes
        if pd.isna(cvss) and pd.isna(epss): #Si CVSS et EPSS sont tous les 2 absents, je classe en low et j'explique pourquoi tout manque..
            return "LOW", "cvss&epss_missing"

        if pd.isna(epss): # cas 1 : si EPSS manquant, je fais une décision basée uniquement sur CVSS
            
            if cvss >= 9: #Si CVSS est trés elevé, c'est trés grave
                return "HIGH", "cvss>=9_epss_missing" #J'envoie HIGH avec une raison qui explique la règle
            if cvss >= 7: # C'est sérieux
                return "MEDIUM", "cvss>=7_epss_missing" #J'envoie medium avec la raison
            return "LOW", "low_or_missing" #Sinon je renvoie low parce qu'on a pas assez d'info pour être sur 

        if pd.isna(cvss): #cas 2 : CVSS manquant, je fais une décision basée sur EPSS
            
            if epss >= 0.5: #
                return "CRITICAL", "epss>=0.5_cvss_missing" #Probabilité d'exploitation trés forte, je renvoie critical et j'explique pk
            if epss >= 0.2:
                return "HIGH", "epss>=0.2_cvss_missing" #même logique que pour cas 1 aprés...
            return "LOW", "low_or_missing"

        # Règles combinées (principales) : CVSS et EPSS présents
        if (epss >= 0.5) or (cvss >= 9 and epss >= 0.1):
            return "CRITICAL", "epss>=0.5_or_(cvss>=9&epss>=0.1)"
        if cvss >= 7 and epss >= 0.05:
            return "HIGH", "cvss>=7&epss>=0.05"
        if cvss >= 7 and epss < 0.05:
            return "MEDIUM", "cvss>=7&epss<0.05"

        return "LOW", "below_thresholds"

    df[["alert_level", "alert_reason"]] = df.apply( #ligne par ligne j'applique computer alert...
        lambda r: pd.Series(compute_alert(r)),
        axis=1
    )
    return df
