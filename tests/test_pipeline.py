"""Tests use a small made-up catalog, so they run without the internet."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from check_inventory import match
from load import clean


def entry(cve, vendor, product, added, due, ransomware="Unknown", cwes=None):
    return {"cveID": cve, "vendorProject": vendor, "product": product,
            "vulnerabilityName": f"{product} flaw", "dateAdded": added, "dueDate": due,
            "knownRansomwareCampaignUse": ransomware, "shortDescription": "test",
            "cwes": cwes or []}


RAW = {"vulnerabilities": [
    entry("CVE-2019-0001", "Microsoft", "Windows", "2024-01-10", "2024-01-31", "Known", ["CWE-787"]),
    entry("CVE-2024-0002", "Microsoft ", "Exchange Server", "2024-03-01", "2024-03-22", cwes=["CWE-20", "CWE-78"]),
    entry("CVE-2023-0003", "Fortinet", "FortiOS", "2023-06-01", "2023-06-22", "Known"),
]}


def test_clean_builds_expected_columns():
    vulns, _ = clean(RAW)
    assert len(vulns) == 3
    assert vulns.loc[0, "days_to_fix"] == 21
    assert vulns.loc[0, "cve_year"] == 2019
    assert vulns["ransomware"].tolist() == [1, 0, 1]


def test_clean_strips_vendor_whitespace():
    vulns, _ = clean(RAW)
    assert vulns.loc[1, "vendor"] == "Microsoft"


def test_weaknesses_one_row_per_cwe():
    _, weaknesses = clean(RAW)
    assert len(weaknesses) == 3
    assert set(weaknesses[weaknesses["cve_id"] == "CVE-2024-0002"]["cwe"]) == {"CWE-20", "CWE-78"}


def test_duplicate_cves_are_rejected():
    raw = {"vulnerabilities": RAW["vulnerabilities"] + [RAW["vulnerabilities"][0]]}
    with pytest.raises(ValueError):
        clean(raw)


def test_inventory_match_ranks_ransomware_first():
    vulns, _ = clean(RAW)
    inventory = pd.DataFrame([
        {"vendor": "Zoom", "product": "Zoom Client", "owner": "All"},
        {"vendor": "microsoft", "product": "exchange", "owner": "IT"},
        {"vendor": "Fortinet", "product": "FortiOS", "owner": "Network"},
    ])
    result = match(inventory, vulns)
    assert result.loc[0, "product"] == "FortiOS"
    assert result.loc[0, "ransomware_cves"] == 1
    assert result[result["product"] == "exchange"]["kev_cves"].iloc[0] == 1
    assert result[result["product"] == "Zoom Client"]["kev_cves"].iloc[0] == 0
