# Scoring

## Overview

The risk scoring system combines multiple vulnerability factors into a single composite score for prioritization.

## Formula

```
risk_score = (CVSS × 0.4) + (KEV_BONUS if in KEV) + (EPSS × 5.0) + (age_days × 0.01)
```

Where:
- **CVSS** = CVSS score (0-10 scale)
- **KEV_BONUS** = 2.0 if vulnerability is in Known Exploited Vulnerabilities, else 0
- **EPSS** = EPSS score (0-1 scale)
- **age_days** = Days since publication (capped at 365)

## Weight Rationale

### CVSS Weight (0.4)
CVSS provides baseline severity but doesn't account for exploitability or active exploitation. Lower weight reflects that severity alone isn't sufficient for prioritization.

### KEV Bonus (+2.0)
Known Exploited Vulnerabilities get a flat bonus because they're actively exploited in the wild. This ensures they rise to the top of priority lists regardless of other factors.

### EPSS Weight (5.0)
EPSS predicts exploit likelihood and is highly predictive of real-world risk. Higher weight reflects that exploitability is often more important than severity alone.

### Age Weight (0.01 per day, max 365)
Older vulnerabilities may have more exposure time or be forgotten. Small per-day weight prevents age from dominating while still providing a slight boost to older, unpatched issues.

## Example Calculation

For a vulnerability with CVSS 7.5, in KEV, EPSS 0.8, age 30 days:
- CVSS component: 7.5 × 0.4 = 3.0
- KEV bonus: 2.0
- EPSS component: 0.8 × 5.0 = 4.0
- Age component: 30 × 0.01 = 0.3
- **Total risk score: 9.3**

## Implementation

Scores are computed in `pipelines/scoring.py` and stored in `report_cve_daily.risk_score`. The formula can be adjusted by modifying weights in the scoring module.
