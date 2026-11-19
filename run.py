"""Run the whole pipeline: download, load, report, inventory check."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import check_inventory
import fetch
import load
import report

if __name__ == "__main__":
    print(f"Downloaded {fetch.fetch()}")
    print(f"Loaded {load.load()} vulnerabilities")
    report.main()
    check_inventory.main("data/sample_inventory.csv")
