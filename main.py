from src.rss_fetch import fetch_all_bulletins #J’importe la fonction qui va récupérer les bulletins depuis le RSS ANSSI.
from src.cve_extract import extract_cves #J'importe la fonction qui va extraire les CVEs depuis un bulletin donné.
from src.enrich import enrich_cve
from src.features import add_risk_score, add_risk_level, top_cves, vendor_summary
import pandas as pd #J'importe pandas pour manipuler les données et créer le fichier CSV.
import time 


DEV_FAST = True
DELAY_ANSSI = 0.2 if DEV_FAST else 2.0  # requêtes JSON ANSSI
DELAY_API = 1.0 if DEV_FAST else 2.0    # requêtes MITRE/EPSS (rate limit)

MAX_CVE_ENRICH = 80 if DEV_FAST else None  # en dev on limite, en rendu tu mets None


def main():
    
    """
    
    
    
    """
    
    bulletins = fetch_all_bulletins() #Je récupère tous les bulletins récents via le flux RSS ANSSI.

    rows = [] #Je crée une liste vide pour stocker les lignes du futur CSV.
    total = len(bulletins)
    print(f"Traiteement de {total} bulletins...\n")
    
    for i,b in enumerate(bulletins, start=1): #On parcours les bulletins un par un avec i le numéro du bulletin et b le bulletin courant (dict avec type, title, link...)
        if i  == 1 or i % 5 == 0 or i == total : #Affichage de la progession tous les 5 bulletins
            print(f"progress: {i}/{total} bulletins", end="\r")
            
        cves  = extract_cves(b["link"], delay = 0.2) 
        # Je prends le lien du bulletin
        #Je télécharge son JSON
        #J'extraits tous les cves associées
        #Je fais une petite pause de 0.2s entre chaque requête pour ne pas surcharger le site ANSSI
    
        for cve in cves: # Je parcours chaque cve trouvée dans ce bulletin
            rows.append({ #Je crée une ligne dans le CSV pour chaque cve
                "type": b["type"], #Type du bulletin (alerte ou avis)
                "published": b["published"],#Date de publication du bulletin
                "title": b["title"],#Titre du bulletin
                "link": b["link"],#Je stocke le lien vers le bulletin
                "cve": cve, #Je stocke la CVE
            })

    df = pd.DataFrame(rows) #Je transforme la liste de lignes en DataFrame pandas (tableau de données)
    df.to_csv("output_bulletins_cves.csv", index=False, encoding="utf-8")  # J'exporte le DataFrame en fichier CSV

    print(f"OK : bulletins={len(bulletins)}  lignes={len(df)}") # J'affiche combien de bulletins ont été traités
    print("Fichier créé : output_bulletins_cves.csv") #J'indique le csv

# ---- Enrichissement (une fois par CVE unique) ----
    unique_cves = sorted(df["cve"].unique().tolist()) #Je prends toutes les CVE du DataFrame, je supprime les doublons (par unique()), je transforme ça en liste puis je trie pour avoir un ordre stable et lisible
    if MAX_CVE_ENRICH is not None: # On peut mettre une limite de cve à enrichir, c'est une technique pour les tests et éviter trop d'appels d'api
        unique_cves = unique_cves[:MAX_CVE_ENRICH]

    print(f"\nEnrichissement de {len(unique_cves)} CVE uniques (MITRE + EPSS)...\n") #J'indique combien de CVE uniques vont être enrichies (et ce qu'il se passe)

    enriched_rows = [] #Je prépare une liste qui contiendra les CVE enrichies (chaque élément = 1CVE enrichie)
    for j, cve_id in enumerate(unique_cves, start=1): # je parcours chaque CVE une par une. j sert à afficher la progression
        if j == 1 or j % 10 == 0 or j == len(unique_cves): #on affiche l'avancement progressif
            print(f"Enrich : {j}/{len(unique_cves)}", end="\r")

        try:
            e = enrich_cve(cve_id) #Je demande à ma fonction enrich_cve d'appeler mitre, d'appeler epss, de structurer les données puis je stocke le résultat dans ma liste
            enriched_rows.append(e)
        except Exception as ex: #si une cve, on ne bloque pas le programme
            print(f"\n[WARNING] enrich failed {cve_id} -> {ex}")
        finally:
            time.sleep(DELAY_API) #je fais une pause entre 2 appels API 

    enrich_df = pd.DataFrame(enriched_rows) #Je transforme la liste des CVE enrichies en tableau 

    # Merge sur la colonne "cve"
    final_df = df.merge(enrich_df, on="cve", how="left") #je rattache les données enrichies à toutes les lignes du dataset original
    final_df.to_csv("output_bulletins_cves_enriched.csv", index=False, encoding="utf-8")  #je sauvegarde le dataset enrichi "officiel"

    print(f"\nFichier créé : output_bulletins_cves_enriched.csv")
    print(f"Colonnes finales : {list(final_df.columns)}")

    # Features (colonnes supplémentaires) pour le fun finalement 
    final_df = add_risk_score(final_df) #J’ajoute une colonne calculée à partir de CVSS et EPSS.
    final_df = add_risk_level(final_df) #Je traduis le score numérique en niveau de risque lisible.

    final_df.to_csv("output_bulletins_cves_enriched_features.csv", index=False, encoding="utf-8") #Je sauvegarde la version “augmentée” du dataset.
    print("Fichier créé : output_bulletins_cves_enriched_features.csv")

    # Top CVE
    top10 = top_cves(final_df, n=10) #Je sélectionne les 10 CVE les plus risquées.
    top10.to_csv("top10_cves.csv", index=False, encoding="utf-8") 
    print("Fichier créé : top10_cves.csv")

    # Résumé par éditeur
    vendors = vendor_summary(final_df)
    vendors.to_csv("vendor_summary.csv", index=False, encoding="utf-8") #Je crée une vue stratégique du risque par fournisseur.
    print("Fichier créé : vendor_summary.csv")

if __name__ == "__main__":
    main()