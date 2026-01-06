import pandas as pd #On importe pandas pour lire le csv d'abonnées et filtrer/manipuler les Dataframes
from src.mailer import send_email_smtp #J'importe la fonction qui sait envoyer un emails SMTP quand on veut envoyer pour de vrai 
from pathlib import Path #Permet de gérer des chemins de fichiers de façon robuste 

LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3} #Je définis un "ordre" numérique des niveaux d'alerte pour pouvoir comparer facilement


def _parse_set(s): #Une fonction utilitaire qui transforme un champ texte vendors/products en ensemble de valeurs
    if not isinstance(s, str) or not s.strip(): #Si s n'est pas une chaîne ou est vide (rien écrit), je considère qu'il n'y a pas de filtre
        return None #pour dire : ya pas de filtre, on accepte tout 
    return {x.strip().lower() for x in s.split(";") if x.strip()} #Je découpe la chaîne par ";", je nettoie les espaces, je mets en minuscules et je mets le tout dans un set pour comparer facilement ( car le set enlève les doublons automatiquement et en miniscule pour tout...)


def _build_email(df: pd.DataFrame, min_level: str) -> tuple[str, str]: #fonction qui fabrique le sujet et le contenu d'un email à partir d'un dataframe filtré
    n_crit = int((df["alert_level"] == "CRITICAL").sum()) #Je compte combien de lignes ont alert_level == CRITICAL (True =1, False = 0, donc sum fait le compte)
    n_high = int((df["alert_level"] == "HIGH").sum()) #pareil qu'avant avec high 

    top = df.head(10) #je garde seulement les 10 premières lignes pour éviter des emails trop longs

    lines = [] #liste de lignes text 
    lines.append(f"Résumé alertes (>= {min_level})") #titre qui rappelle la règle de l'abonné
    lines.append(f"- CRITICAL: {n_crit}") #une lgine "stat" pour les CRITICAL
    lines.append(f"- HIGH    : {n_high}") #j'ajoute une ligne "stat" pour les HIGH
    lines.append("") #j'ajoute une ligne vite pour rendre l'email plus lisible
    lines.append("Top CVE :") #J'ajoute un sous-titre avant la liste des cves
    lines.append("")

    for _, r in top.iterrows():# Je parcours les lignes du DataFrame top, une par une (chaque r est une ligne)
        lines.append( #Je commence à ajouter une ligne de résumé pour cette CVE
            f"{r.get('alert_level')} | {r.get('cve')} | " #J'affiche le niveau d'alerte et l'id de la cve
            f"CVSS={r.get('cvss_score')} | EPSS={r.get('epss')} | RISK={r.get('risk_score')}" #j'affiche les scores principaux (cvss, epss, notre score combiné RISK)
        )
        lines.append(f"Titre: {r.get('title','')}") #j'ajoute le titre du bulletin anssi 
        lines.append(f"Lien : {r.get('link','')}") #j'ajoute le lien anssi pour que l'utilisateur puisse cliquer et vérifier
        lines.append("")#lisbilité

    subject = f"[ANSSI] {len(df)} alertes >= {min_level} (C:{n_crit} H:{n_high})" #Je fabrique le sujet de mail avec un résumé (nombre total + crit/high)
    body = "\n".join(lines) #Je transforme la liste lines en un texte final en mettant un saut de ligne entre chaque élément
    return subject, body #Je renvoie le sujet + le corps de mail


def notify_subscribers( #Je crée la fonction qui lit les abonnées et envoie les mails
    final_df: pd.DataFrame, #final_df est le dataframe final (enrichi + features + alertes)
    subscribers_csv: str = "data/subscribers.csv", #on lit les abonnés par le chemin et suscribers csv
    dry_run: bool = True, #Si true, je n'envoie rien, je fais juste un affichage dans le terminal 
    max_items: int = 10, #Je limite le nombre de cve listées dans un mail (anti email trop long)
):
    root = Path(__file__).resolve().parents[1]  # .../anssi-vulnerability-intelligence
    subs_path = root / subscribers_csv
    subs = pd.read_csv(subs_path)

    
    base = final_df.copy() #Je fais une copie pour éviter de modifier final_df par erreur
    base = base.drop_duplicates(subset=["cve"]) # Je garde une seule ligne par cve (éviter d'envoyer le même cve plusierus fois)

    # On ne mail que HIGH/CRITICAL puis on permet de tester MEDIUM et LOW
    base = base[base["alert_level"].isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])].copy()

    # Tri : CRITICAL d'abord, puis risk_score si dispo
    if "risk_score" in base.columns: #Si la colonne risk_score existe, je l'utilise pour trier plus finement
        base["risk_score"] = pd.to_numeric(base.get("risk_score"), errors="coerce") #Je convertis risk_score en nombre (et je met NaN si ça ne se convertit pas)
        base = base.sort_values(["alert_level", "risk_score"], ascending=[False, False]) #Je trie d'abord par alert_level décroissant (critical avant low) puis par risk_score décroissant
    else: # Si risk_score n'existe pas, je fais un tri plus simple
        base = base.sort_values(["alert_level"], ascending=False) #Je trie uniquement sur le niveau d'alerte

    for _, sub in subs.iterrows(): # je parcours chaque abonné (chaque ligne de subscribers.csv)
        email = str(sub["email"]).strip() #Je récupère l'email et je supprime les espaces inutiles
        min_level = str(sub.get("min_level", "HIGH")).upper().strip() #Je récupère le niveau minimal demandé par l'abonné (par défaut HIGH) en majuscules)
        min_rank = LEVEL_RANK.get(min_level, 2) # je transforme ce niveau en nombre 

        vendors = _parse_set(sub.get("vendors", "")) #Je convertis le champ vendors en ensemble de vendors
        products = _parse_set(sub.get("products", "")) #pareil pour products

        df = base.copy() #je pars d'une copie de la base filtrée pour construire le dataset spécifique à cet abonné 
        df = df[df["alert_level"].map(LEVEL_RANK).fillna(-1) >= min_rank] #Je garde seulement les lignes dont le niveau est au moins celui demandé par l'abonné. 
        #SUBTILITE : 
        #.map(LEVEL_RANK) transforme LOW/MEDIUM/HIGH/CRITICAL en 0/1/2/3
        #.fillna(-1) remplace les valeurs manquantes (NaN) par -1 pour qu'elles soient toujours filtrées (évite de casser si valeur inconnue)
        # >= min_rank fait la comparaison

        if vendors is not None and "vendor" in df.columns: #Si l'abonné à mis un filtre vendors et que la colonne vendor existe, je filtre
            df = df[df["vendor"].fillna("").str.lower().isin(vendors)] #Je garde seulement les lignes dont le vendor est dans la liste demandée (comparaison sans casse)
        if products is not None and "product" in df.columns: #même logique pour product
            df = df[df["product"].fillna("").str.lower().isin(products)]

        if df.empty:
            continue

        df = df.head(max_items) #Je limite le nombre de cve envoyées dans le mail (10 par défaut)
        subject, body = _build_email(df, min_level) #Je génère le suejt et le contenu du mail à partir de la CVE sélectionnées

        if dry_run: #Si on est en mode test (dry run), je n'envoie pas de mail, je fais juste un affichage
            print(f"\n--- DRY RUN email to {email} ---")
            print(subject)
            print(body[:1200] + ("\n...(truncated)" if len(body) > 1200 else ""))
        else: #mode réel, on envoie véritablement le mail en faisant appel à SMTP et le sujet et le corps générés
            send_email_smtp(email, subject, body)
            print(f"[OK] Email envoyé à {email} ({min_level})") #confirmation
