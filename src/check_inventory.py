"""Match a software inventory against the KEV catalog and rank what to review first.

Usage: python src/check_inventory.py data/sample_inventory.csv

The match is on vendor and product name only. It does not check versions, so the
output is a list of products to review, not proof that a system is vulnerable.
"""
import sqlite3
import sys
from pathlib import Path

import pandas as pd

DB_PATH = Path("data/kev.db")


def match(inventory: pd.DataFrame, vulns: pd.DataFrame) -> pd.DataFrame:
    """Return one row per inventory product with its KEV exposure, worst first."""
    rows = []
    for item in inventory.itertuples():
        same_vendor = vulns["vendor"].str.lower() == item.vendor.strip().lower()
        same_product = vulns["product"].str.lower().str.contains(
            item.product.strip().lower(), regex=False)
        hits = vulns[same_vendor & same_product]
        rows.append({
            "vendor": item.vendor,
            "product": item.product,
            "owner": item.owner,
            "kev_cves": len(hits),
            "ransomware_cves": int(hits["ransomware"].sum()),
            "latest_added": hits["date_added"].max() if len(hits) else "",
            "example_cve": hits.sort_values("date_added")["cve_id"].iloc[-1] if len(hits) else "",
        })
    out = pd.DataFrame(rows)
    # Ransomware-linked flaws first, then the most entries, then the most recent.
    return out.sort_values(["ransomware_cves", "kev_cves", "latest_added"],
                           ascending=False).reset_index(drop=True)


def main(inventory_path: str) -> None:
    inventory = pd.read_csv(inventory_path)
    with sqlite3.connect(DB_PATH) as conn:
        vulns = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
    result = match(inventory, vulns)
    Path("reports").mkdir(exist_ok=True)
    result.to_csv("reports/inventory_review.csv", index=False)
    print(result.to_string(index=False))
    print("\nSaved reports/inventory_review.csv")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/sample_inventory.csv")
