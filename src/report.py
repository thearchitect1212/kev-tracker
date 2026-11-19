"""Run the SQL analysis, draw the charts, and write reports/summary.md."""
import sqlite3
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

DB_PATH = Path("data/kev.db")
SQL_PATH = Path("sql/analysis.sql")
OUT_DIR = Path("reports")
BLUE, RED = "#2a6f97", "#c1121f"


def read_queries(sql_path: Path = SQL_PATH) -> dict[str, str]:
    """Split analysis.sql into {name: query} using the '-- name:' markers."""
    queries, name, lines = {}, None, []
    for line in sql_path.read_text().splitlines():
        if line.startswith("-- name:"):
            if name:
                queries[name] = "\n".join(lines).strip()
            name, lines = line.split(":", 1)[1].strip(), []
        elif name:
            lines.append(line)
    if name:
        queries[name] = "\n".join(lines).strip()
    return queries


def run_all(db_path: Path = DB_PATH) -> dict[str, pd.DataFrame]:
    with sqlite3.connect(db_path) as conn:
        results = {name: pd.read_sql_query(sql, conn) for name, sql in read_queries().items()}
        results["catalog_info"] = pd.read_sql_query("SELECT * FROM catalog_info", conn)
    return results


def bar_chart(df, label_col, title, filename, horizontal=False):
    """Stacked bars: ransomware-linked CVEs in red, the rest in blue."""
    other = df["cves"] - df["ransomware_cves"]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if horizontal:
        df, other = df.iloc[::-1], other.iloc[::-1]
        ax.barh(df[label_col], other, color=BLUE, label="No known ransomware use")
        ax.barh(df[label_col], df["ransomware_cves"], left=other, color=RED,
                label="Used in ransomware campaigns")
        ax.set_xlabel("Exploited vulnerabilities")
    else:
        ax.bar(df[label_col], other, color=BLUE, label="No known ransomware use")
        ax.bar(df[label_col], df["ransomware_cves"], bottom=other, color=RED,
               label="Used in ransomware campaigns")
        ax.set_ylabel("Exploited vulnerabilities")
    ax.set_title(title)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT_DIR / filename, dpi=150)
    plt.close(fig)


def write_summary(r: dict[str, pd.DataFrame]) -> None:
    t = r["totals"].iloc[0]
    info = r["catalog_info"].iloc[0]
    top = r["top_vendors"].iloc[0]
    age = r["old_flaws_still_exploited"].set_index("age_when_added")["cves"]
    old_pct = 100 * age.get("5+ years", 0) / t["total_cves"]
    recent = r["added_last_30_days"]

    lines = [
        "# KEV Tracker summary",
        "",
        f"Catalog version {info['catalog_version']} (released {info['date_released'][:10]}).",
        "",
        "## Key numbers",
        "",
        f"- **{int(t['total_cves']):,}** vulnerabilities are known to be exploited in real attacks.",
        f"- **{int(t['ransomware_cves']):,}** of them ({t['ransomware_pct']}%) have been used in ransomware campaigns.",
        f"- **{top['vendor']}** has the most entries: {int(top['cves'])}.",
        f"- **{old_pct:.0f}%** were already 5 or more years old when they were added, so old unpatched flaws still get attacked.",
        f"- **{len(recent)}** were added in the 30 days up to {t['last_added']}.",
        "",
        "## Top 10 vendors",
        "",
        r["top_vendors"].to_markdown(index=False),
        "",
        "![Top vendors](top_vendors.png)",
        "",
        "## Added per year",
        "",
        r["added_per_year"].to_markdown(index=False),
        "",
        "![Added per year](added_per_year.png)",
        "",
        "## Top 10 weakness types (CWE)",
        "",
        r["top_weaknesses"].to_markdown(index=False),
        "",
        "## Age of the flaw when it was added",
        "",
        r["old_flaws_still_exploited"].to_markdown(index=False),
        "",
        "## Added in the last 30 days",
        "",
        recent.to_markdown(index=False),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(lines))


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    r = run_all()
    bar_chart(r["top_vendors"], "vendor", "Vendors with the most exploited vulnerabilities",
              "top_vendors.png", horizontal=True)
    bar_chart(r["added_per_year"], "year_added", "Exploited vulnerabilities added to the catalog per year",
              "added_per_year.png")
    write_summary(r)
    print(f"Wrote {OUT_DIR}/summary.md and 2 charts")


if __name__ == "__main__":
    main()
