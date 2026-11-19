"""Download the current CISA Known Exploited Vulnerabilities (KEV) catalog."""
from pathlib import Path

import requests

# CISA publishes the catalog in its public GitHub repository and on cisa.gov.
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
RAW_PATH = Path("data/kev.json")


def fetch(url: str = KEV_URL, out_path: Path = RAW_PATH) -> Path:
    """Save the catalog JSON to disk and return the path."""
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(response.content)
    return out_path


if __name__ == "__main__":
    print(f"Saved {fetch()}")
