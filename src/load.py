"""Clean the KEV catalog and load it into a SQLite database."""
import json
import sqlite3
from pathlib import Path

import pandas as pd

RAW_PATH = Path("data/kev.json")
DB_PATH = Path("data/kev.db")


def clean(raw: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (vulnerabilities, weaknesses) tables from the raw catalog."""
    df = pd.DataFrame(raw["vulnerabilities"])

    # One row per CVE. Fail loudly if the source ever sends duplicates.
    if df["cveID"].duplicated().any():
        raise ValueError("Duplicate CVE IDs in the catalog")

    df = df.rename(columns={
        "cveID": "cve_id",
        "vendorProject": "vendor",
        "vulnerabilityName": "name",
        "dateAdded": "date_added",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse": "ransomware_use",
        "shortDescription": "description",
    })
    df["vendor"] = df["vendor"].str.strip()
    df["product"] = df["product"].str.strip()
    df["date_added"] = pd.to_datetime(df["date_added"])
    df["due_date"] = pd.to_datetime(df["due_date"])
    # Days CISA gives federal agencies to fix the issue.
    df["days_to_fix"] = (df["due_date"] - df["date_added"]).dt.days
    # The year in the CVE ID is when the flaw was first recorded.
    df["cve_year"] = df["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int)
    df["ransomware"] = (df["ransomware_use"] == "Known").astype(int)

    # A CVE can have several weakness types (CWEs), so they get their own table.
    weaknesses = (
        df[["cve_id", "cwes"]].explode("cwes").dropna().rename(columns={"cwes": "cwe"})
    )

    keep = ["cve_id", "vendor", "product", "name", "description", "date_added",
            "due_date", "days_to_fix", "cve_year", "ransomware"]
    vulns = df[keep].copy()
    vulns["date_added"] = vulns["date_added"].dt.strftime("%Y-%m-%d")
    vulns["due_date"] = vulns["due_date"].dt.strftime("%Y-%m-%d")
    return vulns, weaknesses


def load(raw_path: Path = RAW_PATH, db_path: Path = DB_PATH) -> int:
    """Rebuild the database from the raw file. Returns the number of CVEs loaded."""
    raw = json.loads(raw_path.read_text())
    vulns, weaknesses = clean(raw)

    # Check our row count against the count CISA reports in the file itself.
    if len(vulns) != raw["count"]:
        raise ValueError(f"Loaded {len(vulns)} rows but catalog says {raw['count']}")

    with sqlite3.connect(db_path) as conn:
        vulns.to_sql("vulnerabilities", conn, if_exists="replace", index=False)
        weaknesses.to_sql("weaknesses", conn, if_exists="replace", index=False)
        pd.DataFrame([{"catalog_version": raw["catalogVersion"],
                       "date_released": raw["dateReleased"]}]
                     ).to_sql("catalog_info", conn, if_exists="replace", index=False)
    return len(vulns)


if __name__ == "__main__":
    print(f"Loaded {load()} vulnerabilities into {DB_PATH}")
