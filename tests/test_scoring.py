"""Tests for pipelines.scoring.compute_risk_score."""

import pytest

from pipelines.scoring import (
    AGE_WEIGHT_PER_DAY,
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    KEV_BONUS,
    MAX_AGE_DAYS_CAP,
    compute_risk_score,
)


def test_kev_scores_higher_than_non_kev_with_same_cvss():
    non_kev = compute_risk_score(cvss_score=7.5, is_kev=False, epss_score=0.3, age_days=30)
    kev = compute_risk_score(cvss_score=7.5, is_kev=True, epss_score=0.3, age_days=30)
    assert kev > non_kev
    assert kev - non_kev == pytest.approx(KEV_BONUS)


def test_epss_zero_vs_one_differs_by_five_points():
    low = compute_risk_score(cvss_score=5.0, is_kev=False, epss_score=0.0, age_days=10)
    high = compute_risk_score(cvss_score=5.0, is_kev=False, epss_score=1.0, age_days=10)
    assert high - low == pytest.approx(5.0)
    assert EPSS_WEIGHT == 5.0


def test_age_is_capped_at_max_age_days():
    at_cap = compute_risk_score(cvss_score=6.0, is_kev=False, epss_score=0.2, age_days=MAX_AGE_DAYS_CAP)
    over_cap = compute_risk_score(cvss_score=6.0, is_kev=False, epss_score=0.2, age_days=400)
    assert at_cap == pytest.approx(over_cap)


def test_none_inputs_are_handled_gracefully():
    # Must not raise, and must produce a numeric result.
    score = compute_risk_score(cvss_score=None, is_kev=None, epss_score=None, age_days=None)
    assert isinstance(score, float)
    assert score == pytest.approx(0.0)


@pytest.mark.parametrize(
    "cvss,is_kev,epss,age",
    [
        (None, False, 0.5, 10),
        (7.0, None, 0.5, 10),
        (7.0, True, None, 10),
        (7.0, True, 0.5, None),
        (None, None, None, None),
    ],
)
def test_partial_none_inputs_do_not_crash(cvss, is_kev, epss, age):
    score = compute_risk_score(cvss_score=cvss, is_kev=is_kev, epss_score=epss, age_days=age)
    assert isinstance(score, float)
    assert score >= 0.0


def test_maximum_possible_score():
    score = compute_risk_score(
        cvss_score=10.0,
        is_kev=True,
        epss_score=1.0,
        age_days=MAX_AGE_DAYS_CAP,
    )
    expected = (
        10.0 * CVSS_WEIGHT
        + KEV_BONUS
        + 1.0 * EPSS_WEIGHT
        + MAX_AGE_DAYS_CAP * AGE_WEIGHT_PER_DAY
    )
    assert score == pytest.approx(expected)
    # Going beyond the age cap must not exceed the maximum.
    beyond = compute_risk_score(cvss_score=10.0, is_kev=True, epss_score=1.0, age_days=10_000)
    assert beyond == pytest.approx(expected)


def test_known_example_from_docstring(sample_cve_row):
    # Sanity check against the documented formula using the shared fixture.
    row = dict(sample_cve_row)
    row.update(cvss_score=7.5, is_kev=True, epss_score=0.8, age_days=30)
    score = compute_risk_score(
        cvss_score=row["cvss_score"],
        is_kev=row["is_kev"],
        epss_score=row["epss_score"],
        age_days=row["age_days"],
    )
    assert score == pytest.approx(9.3)
