from src.rss_fetch import fetch_all_bulletins #J’importe la fonction qui va récupérer les bulletins depuis le RSS ANSSI.
from src.cve_extract import extract_cves #J'importe la fonction qui va extraire les CVEs depuis un bulletin donné.
import pandas as pd #J'importe pandas pour manipuler les données et créer le fichier CSV.

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

if __name__ == "__main__":
    main() #execution et fonction executée 
