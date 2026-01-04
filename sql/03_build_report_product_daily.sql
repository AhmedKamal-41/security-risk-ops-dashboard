-- Build daily product report
-- Aggregates today's CVE report data into product-level metrics

-- Delete existing records for today to allow rebuild
DELETE FROM report_product_daily WHERE as_of_date = CURRENT_DATE;

-- Aggregate metrics by vendor and product
INSERT INTO report_product_daily (
    as_of_date,
    vendor,
    product,
    open_vulns,
    high_crit_count,
    kev_count,
    avg_epss,
    avg_risk_score
)
SELECT
    CURRENT_DATE AS as_of_date,
    COALESCE(vendor, 'Unknown') AS vendor,
    COALESCE(product, 'Unknown') AS product,
    COUNT(*) AS open_vulns,
    COUNT(*) FILTER (WHERE severity IN ('High', 'Critical')) AS high_crit_count,
    COUNT(*) FILTER (WHERE is_kev = TRUE) AS kev_count,
    AVG(epss_score) AS avg_epss,
    AVG(risk_score) AS avg_risk_score
FROM report_cve_daily
WHERE as_of_date = CURRENT_DATE
GROUP BY COALESCE(vendor, 'Unknown'), COALESCE(product, 'Unknown');
