-- Insert alerts for high-risk vulnerabilities
-- This SQL file can be executed directly or used as reference
-- Alerts are also generated programmatically by pipelines/alerting.py
--
-- Usage options:
-- 1. Execute directly: psql -f sql/04_insert_alerts.sql (or via database client)
-- 2. Via Python: pipelines/alerting.py (default) or run_alerting(use_sql=True)
-- 3. Both methods are compatible - they both clear today's alerts first
--
-- Thresholds (matching Python constants):
-- - High risk CVEs: risk_score >= 8.0
-- - High EPSS: epss_score >= 0.75
-- - High vuln count: open_vulns >= 50
-- - High avg risk: avg_risk_score >= 7.0

-- Clear today's alerts to allow rebuild
DELETE FROM alerts WHERE DATE(created_at) = CURRENT_DATE;

-- Alert 1: High risk score CVEs (risk_score >= 8.0)
INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
SELECT
    CURRENT_TIMESTAMP AS created_at,
    'high_risk_cve' AS alert_type,
    'CVE-' || cve_id AS scope,
    'High risk vulnerability detected: ' || cve_id || 
    ' (Risk Score: ' || ROUND(risk_score::numeric, 2) || 
    ', Severity: ' || COALESCE(severity, 'Unknown') || 
    ', KEV: ' || CASE WHEN is_kev THEN 'Yes' ELSE 'No' END || ')' AS message,
    'high' AS severity,
    risk_score AS metric_value
FROM report_cve_daily
WHERE as_of_date = CURRENT_DATE
  AND risk_score >= 8.0
ORDER BY risk_score DESC
LIMIT 100;

-- Alert 2: KEV vulnerabilities (all known exploited)
INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
SELECT
    CURRENT_TIMESTAMP AS created_at,
    'kev_vulnerability' AS alert_type,
    CASE 
        WHEN vendor IS NOT NULL AND product IS NOT NULL 
        THEN vendor || '/' || product || ' - CVE-' || cve_id
        ELSE 'CVE-' || cve_id
    END AS scope,
    'Known Exploited Vulnerability: ' || cve_id || 
    ' (Risk Score: ' || ROUND(COALESCE(risk_score, 0)::numeric, 2) || 
    ', Severity: ' || COALESCE(severity, 'Unknown') || ')' AS message,
    'critical' AS severity,
    COALESCE(risk_score, 0) AS metric_value
FROM report_cve_daily
WHERE as_of_date = CURRENT_DATE
  AND is_kev = TRUE
ORDER BY risk_score DESC NULLS LAST;

-- Alert 3: High EPSS score CVEs (EPSS >= 0.75)
INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
SELECT
    CURRENT_TIMESTAMP AS created_at,
    'high_epss' AS alert_type,
    'CVE-' || cve_id AS scope,
    'High EPSS score: ' || cve_id || 
    ' (EPSS: ' || ROUND(epss_score::numeric, 4) || 
    ', Risk Score: ' || ROUND(COALESCE(risk_score, 0)::numeric, 2) || ')' AS message,
    'medium' AS severity,
    epss_score AS metric_value
FROM report_cve_daily
WHERE as_of_date = CURRENT_DATE
  AND epss_score >= 0.75
ORDER BY epss_score DESC
LIMIT 50;

-- Alert 4: Products with high vulnerability counts (>= 50)
INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
SELECT
    CURRENT_TIMESTAMP AS created_at,
    'high_vuln_count' AS alert_type,
    vendor || '/' || product AS scope,
    'High vulnerability count: ' || vendor || '/' || product || 
    ' has ' || open_vulns || ' vulnerabilities' ||
    ' (KEV: ' || kev_count || 
    ', Avg Risk: ' || ROUND(COALESCE(avg_risk_score, 0)::numeric, 2) || ')' AS message,
    'medium' AS severity,
    open_vulns::numeric AS metric_value
FROM report_product_daily
WHERE as_of_date = CURRENT_DATE
  AND open_vulns >= 50
ORDER BY open_vulns DESC
LIMIT 20;

-- Alert 5: Products with high average risk scores (>= 7.0)
INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
SELECT
    CURRENT_TIMESTAMP AS created_at,
    'high_avg_risk' AS alert_type,
    vendor || '/' || product AS scope,
    'High average risk score: ' || vendor || '/' || product || 
    ' has avg risk ' || ROUND(avg_risk_score::numeric, 2) ||
    ' (' || open_vulns || ' vulns, ' || kev_count || ' KEV)' AS message,
    'high' AS severity,
    avg_risk_score AS metric_value
FROM report_product_daily
WHERE as_of_date = CURRENT_DATE
  AND avg_risk_score >= 7.0
  AND open_vulns > 0
ORDER BY avg_risk_score DESC
LIMIT 20;

-- View today's alerts
-- SELECT * FROM alerts WHERE DATE(created_at) = CURRENT_DATE ORDER BY severity DESC, created_at DESC;
