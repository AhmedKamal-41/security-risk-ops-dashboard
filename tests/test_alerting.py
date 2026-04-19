"""Tests for alert-threshold classification.

The alerting module reads from the database via SQL, so these tests pin
the threshold *values* and the classification logic that those queries
implement — independent of any live database.
"""

import pytest

from pipelines.alerting import (
    HIGH_AVG_RISK_THRESHOLD,
    HIGH_EPSS_THRESHOLD,
    HIGH_RISK_SCORE_THRESHOLD,
    HIGH_VULN_COUNT_THRESHOLD,
)


def triggers_high_risk_cve(row):
    """Mirrors the WHERE clause of the high_risk_cve alert query."""
    return (row.get("risk_score") or 0.0) >= HIGH_RISK_SCORE_THRESHOLD


def triggers_kev_vulnerability(row):
    """Mirrors the WHERE clause of the kev_vulnerability alert query."""
    return bool(row.get("is_kev"))


def triggers_high_epss(row):
    """Mirrors the WHERE clause of the high_epss alert query."""
    return (row.get("epss_score") or 0.0) >= HIGH_EPSS_THRESHOLD


# --- high_risk_cve ---------------------------------------------------------

def test_risk_score_at_threshold_triggers_high_risk_cve(sample_cve_row):
    row = dict(sample_cve_row, risk_score=8.0)
    assert triggers_high_risk_cve(row)


def test_risk_score_below_threshold_does_not_trigger(sample_cve_row):
    row = dict(sample_cve_row, risk_score=7.99)
    assert not triggers_high_risk_cve(row)


def test_high_risk_threshold_constant_is_eight():
    assert HIGH_RISK_SCORE_THRESHOLD == 8.0


# --- kev_vulnerability -----------------------------------------------------

def test_kev_row_triggers_kev_alert(kev_cve_row):
    assert triggers_kev_vulnerability(kev_cve_row)


def test_kev_triggers_regardless_of_risk_score(sample_cve_row):
    # Even a low-risk CVE triggers a KEV alert if flagged as KEV.
    row = dict(sample_cve_row, is_kev=True, risk_score=1.0, epss_score=0.0)
    assert triggers_kev_vulnerability(row)


def test_non_kev_row_does_not_trigger_kev_alert(sample_cve_row):
    assert sample_cve_row["is_kev"] is False
    assert not triggers_kev_vulnerability(sample_cve_row)


# --- high_epss -------------------------------------------------------------

@pytest.mark.parametrize("epss", [0.75, 0.80, 0.99, 1.0])
def test_epss_at_or_above_threshold_triggers(sample_cve_row, epss):
    row = dict(sample_cve_row, epss_score=epss)
    assert triggers_high_epss(row)


@pytest.mark.parametrize("epss", [0.0, 0.5, 0.749])
def test_epss_below_threshold_does_not_trigger(sample_cve_row, epss):
    row = dict(sample_cve_row, epss_score=epss)
    assert not triggers_high_epss(row)


def test_high_epss_threshold_constant_is_point_seven_five():
    assert HIGH_EPSS_THRESHOLD == 0.75


# --- threshold sanity ------------------------------------------------------

def test_threshold_constants_have_expected_ranges():
    assert 0.0 < HIGH_EPSS_THRESHOLD <= 1.0
    assert 0.0 < HIGH_RISK_SCORE_THRESHOLD <= 15.0
    assert HIGH_VULN_COUNT_THRESHOLD > 0
    assert HIGH_AVG_RISK_THRESHOLD > 0
