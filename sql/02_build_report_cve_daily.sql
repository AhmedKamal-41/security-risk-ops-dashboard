-- Build daily CVE report
-- Rebuilds today's snapshot by joining raw_cve, raw_kev, and raw_epss

-- Delete existing records for today to allow rebuild
DELETE FROM report_cve_daily WHERE as_of_date = CURRENT_DATE;

-- Build report with CTEs for readability
WITH latest_epss AS (
    -- Get most recent EPSS score per CVE
    SELECT DISTINCT ON (cve_id)
        cve_id,
        epss_score,
        epss_date
    FROM raw_epss
    ORDER BY cve_id, epss_date DESC
),
cve_report_data AS (
    -- Join all data sources
    SELECT
        CURRENT_DATE AS as_of_date,
        c.cve_id,
        c.severity,
        c.cvss_score,
        CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_kev,
        e.epss_score,
        (CURRENT_DATE - c.published_date)::INT AS age_days,
        NULL::NUMERIC AS risk_score,
        k.vendor,
        k.product
    FROM raw_cve c
    LEFT JOIN raw_kev k ON c.cve_id = k.cve_id
    LEFT JOIN latest_epss e ON c.cve_id = e.cve_id
)
-- Insert into report table
INSERT INTO report_cve_daily (
    as_of_date,
    cve_id,
    severity,
    cvss_score,
    is_kev,
    epss_score,
    age_days,
    risk_score,
    vendor,
    product
)
SELECT
    as_of_date,
    cve_id,
    severity,
    cvss_score,
    is_kev,
    epss_score,
    age_days,
    risk_score,
    vendor,
    product
FROM cve_report_data;
