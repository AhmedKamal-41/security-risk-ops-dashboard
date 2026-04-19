"""Shared pytest fixtures for the vulnerability pipeline test suite."""

import os
import sys
from datetime import date, timedelta

import pytest

# Make the project root importable so `from pipelines import ...` works
# regardless of where pytest is invoked from.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture
def sample_cve_row():
    """A typical CVE record as produced by the ingestion pipeline."""
    published = date.today() - timedelta(days=30)
    return {
        "cve_id": "CVE-2024-12345",
        "published_date": published,
        "last_modified_date": published,
        "cvss_score": 7.5,
        "severity": "HIGH",
        "vendor": "acme",
        "product": "widget",
        "description": "Remote code execution in Acme Widget via crafted input.",
        "is_kev": False,
        "epss_score": 0.42,
        "age_days": 30,
    }


@pytest.fixture
def kev_cve_row(sample_cve_row):
    """A KEV-listed variant of the sample CVE."""
    row = dict(sample_cve_row)
    row.update(cve_id="CVE-2024-99999", is_kev=True, epss_score=0.90)
    return row
