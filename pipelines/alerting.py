"""
Alerting system for high-risk vulnerabilities.
"""

from datetime import datetime
from pipelines.db import get_engine, fetch_df, execute
from sqlalchemy import text


# Alert thresholds
HIGH_RISK_SCORE_THRESHOLD = 8.0
HIGH_EPSS_THRESHOLD = 0.75
HIGH_VULN_COUNT_THRESHOLD = 50
HIGH_AVG_RISK_THRESHOLD = 7.0


def generate_alerts():
    """
    Generate alerts for high-risk vulnerabilities and products.
    
    Returns:
        int: Number of alerts generated
    """
    engine = get_engine()
    alert_count = 0
    
    # Clear today's alerts to allow rebuild
    with engine.begin() as conn:
        delete_query = text("""
            DELETE FROM alerts 
            WHERE DATE(created_at) = CURRENT_DATE
        """)
        conn.execute(delete_query)
    
    # Alert 1: High risk score CVEs
    high_risk_cves = fetch_df("""
        SELECT cve_id, risk_score, severity, is_kev, epss_score
        FROM report_cve_daily
        WHERE as_of_date = CURRENT_DATE
          AND risk_score >= :threshold
        ORDER BY risk_score DESC
        LIMIT 100
    """, {"threshold": HIGH_RISK_SCORE_THRESHOLD})
    
    for _, row in high_risk_cves.iterrows():
        insert_alert(
            alert_type="high_risk_cve",
            scope=f"CVE-{row['cve_id']}",
            message=f"High risk vulnerability detected: {row['cve_id']} (Risk Score: {row['risk_score']:.2f}, Severity: {row['severity']}, KEV: {row['is_kev']})",
            severity="high",
            metric_value=float(row['risk_score'])
        )
        alert_count += 1
    
    # Alert 2: KEV vulnerabilities
    kev_cves = fetch_df("""
        SELECT cve_id, risk_score, severity, vendor, product
        FROM report_cve_daily
        WHERE as_of_date = CURRENT_DATE
          AND is_kev = TRUE
        ORDER BY risk_score DESC
    """)
    
    for _, row in kev_cves.iterrows():
        scope = f"CVE-{row['cve_id']}"
        if row['vendor'] and row['product']:
            scope = f"{row['vendor']}/{row['product']} - {scope}"
        
        insert_alert(
            alert_type="kev_vulnerability",
            scope=scope,
            message=f"Known Exploited Vulnerability: {row['cve_id']} (Risk Score: {row['risk_score']:.2f}, Severity: {row['severity']})",
            severity="critical",
            metric_value=float(row['risk_score']) if row['risk_score'] else 0.0
        )
        alert_count += 1
    
    # Alert 3: High EPSS score CVEs
    high_epss_cves = fetch_df("""
        SELECT cve_id, epss_score, risk_score, severity
        FROM report_cve_daily
        WHERE as_of_date = CURRENT_DATE
          AND epss_score >= :threshold
        ORDER BY epss_score DESC
        LIMIT 50
    """, {"threshold": HIGH_EPSS_THRESHOLD})
    
    for _, row in high_epss_cves.iterrows():
        insert_alert(
            alert_type="high_epss",
            scope=f"CVE-{row['cve_id']}",
            message=f"High EPSS score: {row['cve_id']} (EPSS: {row['epss_score']:.4f}, Risk Score: {row['risk_score']:.2f})",
            severity="medium",
            metric_value=float(row['epss_score'])
        )
        alert_count += 1
    
    # Alert 4: Products with high vulnerability counts
    high_vuln_products = fetch_df("""
        SELECT vendor, product, open_vulns, avg_risk_score, kev_count
        FROM report_product_daily
        WHERE as_of_date = CURRENT_DATE
          AND open_vulns >= :threshold
        ORDER BY open_vulns DESC
        LIMIT 20
    """, {"threshold": HIGH_VULN_COUNT_THRESHOLD})
    
    for _, row in high_vuln_products.iterrows():
        insert_alert(
            alert_type="high_vuln_count",
            scope=f"{row['vendor']}/{row['product']}",
            message=f"High vulnerability count: {row['vendor']}/{row['product']} has {row['open_vulns']} vulnerabilities (KEV: {row['kev_count']}, Avg Risk: {row['avg_risk_score']:.2f})",
            severity="medium",
            metric_value=float(row['open_vulns'])
        )
        alert_count += 1
    
    # Alert 5: Products with high average risk scores
    high_risk_products = fetch_df("""
        SELECT vendor, product, avg_risk_score, open_vulns, kev_count
        FROM report_product_daily
        WHERE as_of_date = CURRENT_DATE
          AND avg_risk_score >= :threshold
          AND open_vulns > 0
        ORDER BY avg_risk_score DESC
        LIMIT 20
    """, {"threshold": HIGH_AVG_RISK_THRESHOLD})
    
    for _, row in high_risk_products.iterrows():
        insert_alert(
            alert_type="high_avg_risk",
            scope=f"{row['vendor']}/{row['product']}",
            message=f"High average risk score: {row['vendor']}/{row['product']} has avg risk {row['avg_risk_score']:.2f} ({row['open_vulns']} vulns, {row['kev_count']} KEV)",
            severity="high",
            metric_value=float(row['avg_risk_score'])
        )
        alert_count += 1
    
    return alert_count


def insert_alert(alert_type, scope, message, severity, metric_value):
    """
    Insert a single alert into the alerts table.
    
    Args:
        alert_type: Type of alert (e.g., 'high_risk_cve', 'kev_vulnerability')
        scope: Scope of the alert (e.g., CVE ID, vendor/product)
        message: Alert message
        severity: Alert severity ('low', 'medium', 'high', 'critical')
        metric_value: Numeric value that triggered the alert
    """
    engine = get_engine()
    with engine.begin() as conn:
        insert_query = text("""
            INSERT INTO alerts (created_at, alert_type, scope, message, severity, metric_value)
            VALUES (:created_at, :alert_type, :scope, :message, :severity, :metric_value)
        """)
        conn.execute(insert_query, {
            "created_at": datetime.now(),
            "alert_type": alert_type,
            "scope": scope,
            "message": message,
            "severity": severity,
            "metric_value": metric_value
        })


def run_alerting(use_sql=False):
    """
    Main entry point for alerting system.
    
    Args:
        use_sql: If True, use SQL file instead of Python implementation
    
    Returns:
        int: Number of alerts generated
    """
    if use_sql:
        # Use SQL file for alert generation
        from pipelines.db import run_sql_file, fetch_df
        run_sql_file("sql/04_insert_alerts.sql")
        # Count generated alerts
        count_df = fetch_df("""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE DATE(created_at) = CURRENT_DATE
        """)
        return count_df.iloc[0]["count"]
    else:
        # Use Python implementation (default)
        alert_count = generate_alerts()
        return alert_count
