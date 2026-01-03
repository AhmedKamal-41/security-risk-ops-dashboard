# KPIs

## Overview

Key Performance Indicators (KPIs) track vulnerability management effectiveness and help prioritize remediation efforts.

## Key Metrics

### Open Vulnerabilities (`open_vulns`)
Total count of unpatched vulnerabilities per vendor/product. **Why it matters:** Provides baseline visibility into security debt and helps track remediation progress over time.

### High/Critical Count (`high_crit_count`)
Number of vulnerabilities with severity "High" or "Critical". **Why it matters:** Focuses attention on the most severe issues that pose the greatest risk to the organization.

### KEV Count (`kev_count`)
Number of vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog. **Why it matters:** These are actively exploited in the wild and require immediate attention, making this a critical prioritization metric.

### Average EPSS (`avg_epss`)
Mean Exploit Prediction Scoring System score across vulnerabilities. **Why it matters:** Indicates likelihood of exploitation - higher scores mean vulnerabilities are more likely to be exploited soon.

### Average Risk Score (`avg_risk_score`)
Mean computed risk score combining CVSS, KEV status, EPSS, and age. **Why it matters:** Provides a single composite metric that balances multiple risk factors for easier prioritization and trend analysis.

## Reporting

KPIs are calculated daily and stored in `report_product_daily` table, aggregated by vendor and product. Use these metrics to:
- Track remediation progress
- Identify high-risk products
- Allocate security resources effectively
- Report to stakeholders on security posture
