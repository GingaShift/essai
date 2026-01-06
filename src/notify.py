import pandas as pd
from src.mailer import send_email_smtp
from pathlib import Path

LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _parse_set(s):
    if not isinstance(s, str) or not s.strip():
        return None
    return {x.strip().lower() for x in s.split(";") if x.strip()}


def _build_email(df: pd.DataFrame, min_level: str) -> tuple[str, str]:
    n_crit = int((df["alert_level"] == "CRITICAL").sum())
    n_high = int((df["alert_level"] == "HIGH").sum())

    top = df.head(10)

    lines = []
    lines.append(f"Résumé alertes (>= {min_level})")
    lines.append(f"- CRITICAL: {n_crit}")
    lines.append(f"- HIGH    : {n_high}")
    lines.append("")
    lines.append("Top CVE :")
    lines.append("")

    for _, r in top.iterrows():
        lines.append(
            f"{r.get('alert_level')} | {r.get('cve')} | "
            f"CVSS={r.get('cvss_score')} | EPSS={r.get('epss')} | RISK={r.get('risk_score')}"
        )
        lines.append(f"Titre: {r.get('title','')}")
        lines.append(f"Lien : {r.get('link','')}")
        lines.append("")

    subject = f"[ANSSI] {len(df)} alertes >= {min_level} (C:{n_crit} H:{n_high})"
    body = "\n".join(lines)
    return subject, body


def notify_subscribers(
    final_df: pd.DataFrame,
    subscribers_csv: str = "data/subscribers.csv",
    dry_run: bool = True,
    max_items: int = 10,
):
    root = Path(__file__).resolve().parents[1]  # .../anssi-vulnerability-intelligence
    subs_path = root / subscribers_csv
    subs = pd.read_csv(subs_path)

    # Dataset = bulletin × CVE : on veut éviter 10 fois la même CVE dans l'email
    base = final_df.copy()
    base = base.drop_duplicates(subset=["cve"])

    # On ne mail que HIGH/CRITICAL
    base = base[base["alert_level"].isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])].copy()

    # Tri : CRITICAL d'abord, puis risk_score si dispo
    if "risk_score" in base.columns:
        base["risk_score"] = pd.to_numeric(base.get("risk_score"), errors="coerce")
        base = base.sort_values(["alert_level", "risk_score"], ascending=[False, False])
    else:
        base = base.sort_values(["alert_level"], ascending=False)

    for _, sub in subs.iterrows():
        email = str(sub["email"]).strip()
        min_level = str(sub.get("min_level", "HIGH")).upper().strip()
        min_rank = LEVEL_RANK.get(min_level, 2)

        vendors = _parse_set(sub.get("vendors", ""))
        products = _parse_set(sub.get("products", ""))

        df = base.copy()
        df = df[df["alert_level"].map(LEVEL_RANK).fillna(-1) >= min_rank]

        if vendors is not None and "vendor" in df.columns:
            df = df[df["vendor"].fillna("").str.lower().isin(vendors)]
        if products is not None and "product" in df.columns:
            df = df[df["product"].fillna("").str.lower().isin(products)]

        if df.empty:
            continue

        df = df.head(max_items)
        subject, body = _build_email(df, min_level)

        if dry_run:
            print(f"\n--- DRY RUN email to {email} ---")
            print(subject)
            print(body[:1200] + ("\n...(truncated)" if len(body) > 1200 else ""))
        else:
            send_email_smtp(email, subject, body)
            print(f"[OK] Email envoyé à {email} ({min_level})")
