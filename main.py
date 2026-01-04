from src.rss_fetch import fetch_all_bulletins
from src.cve_extract import extract_cves
import pandas as pd

def main():
    bulletins = fetch_all_bulletins()

    rows = []
    total = len(bulletins)
    print(f"Traiteement de {total} bulletins...\n")
    
    for i,b in enumerate(bulletins, start=1):
        if i  == 1 or i % 5 == 0 or i == total :
            print(f"progress: {i}/{total} bulletins", end="\r")
            
        cves  = extract_cves(b["link"], delay = 0.2) 
    
        for cve in cves:
            rows.append({
                "type": b["type"],
                "published": b["published"],
                "title": b["title"],
                "link": b["link"],
                "cve": cve,
            })

    df = pd.DataFrame(rows)
    df.to_csv("output_bulletins_cves.csv", index=False, encoding="utf-8")

    print(f"OK ✅ bulletins={len(bulletins)}  lignes={len(df)}")
    print("Fichier créé : output_bulletins_cves.csv")

if __name__ == "__main__":
    main()
