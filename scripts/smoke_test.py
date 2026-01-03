"""
Smoke test script to verify pipeline functionality.
"""

import argparse
from datetime import date
from pipelines.db import run_sql_file, fetch_df
from run import create_tables, ingest_kev, ingest_epss, build_reports


def run_smoke_test(skip_ingest=False):
    """
    Run smoke test to verify pipeline functionality.
    
    Args:
        skip_ingest: If True, skip ingestion steps
    """
    print("=" * 60)
    print("SMOKE TEST - Vulnerability Management Pipeline")
    print("=" * 60 + "\n")
    
    # Step 1: Create tables
    print("Step 1: Creating tables...")
    try:
        create_tables()
    except Exception as e:
        print(f"❌ FAILED: {e}\n")
        return False
    
    # Step 2: Run ingestion (if not skipped)
    if not skip_ingest:
        print("\nStep 2: Running ingestion...")
        print("=" * 60)
        try:
            ingest_kev()
            ingest_epss()
        except Exception as e:
            print(f"⚠ WARNING: Ingestion failed: {e}")
            print("Continuing with existing data...\n")
    else:
        print("\nStep 2: Skipping ingestion (using existing data)\n")
    
    # Step 3: Build reports
    print("\nStep 3: Building reports...")
    try:
        build_reports()
    except Exception as e:
        print(f"❌ FAILED: {e}\n")
        return False
    
    # Step 4: Query and display results
    print("\n" + "=" * 60)
    print("QUERY RESULTS")
    print("=" * 60 + "\n")
    
    try:
        # Count raw tables
        print("Raw Data Tables:")
        raw_kev_count = fetch_df("SELECT COUNT(*) as count FROM raw_kev").iloc[0]["count"]
        raw_epss_count = fetch_df("SELECT COUNT(*) as count FROM raw_epss").iloc[0]["count"]
        raw_cve_count = fetch_df("SELECT COUNT(*) as count FROM raw_cve").iloc[0]["count"]
        print(f"  - raw_kev: {raw_kev_count} rows")
        print(f"  - raw_epss: {raw_epss_count} rows")
        print(f"  - raw_cve: {raw_cve_count} rows")
        
        # Count report tables for today
        print(f"\nReport Tables (as_of_date = {date.today()}):")
        cve_report_count = fetch_df(
            "SELECT COUNT(*) as count FROM report_cve_daily WHERE as_of_date = CURRENT_DATE"
        ).iloc[0]["count"]
        product_report_count = fetch_df(
            "SELECT COUNT(*) as count FROM report_product_daily WHERE as_of_date = CURRENT_DATE"
        ).iloc[0]["count"]
        print(f"  - report_cve_daily: {cve_report_count} rows")
        print(f"  - report_product_daily: {product_report_count} rows")
        
        # Top 5 products by avg_risk_score
        print("\nTop 5 Products by Average Risk Score:")
        top_products = fetch_df("""
            SELECT vendor, product, avg_risk_score, open_vulns, kev_count
            FROM report_product_daily
            WHERE as_of_date = CURRENT_DATE
            ORDER BY avg_risk_score DESC NULLS LAST
            LIMIT 5
        """)
        if not top_products.empty:
            for _, row in top_products.iterrows():
                print(f"  - {row['vendor']}/{row['product']}: "
                      f"risk={row['avg_risk_score']:.2f}, "
                      f"vulns={row['open_vulns']}, "
                      f"kev={row['kev_count']}")
        else:
            print("  (No data)")
        
        # Most recent 5 alerts
        print("\nMost Recent 5 Alerts:")
        recent_alerts = fetch_df("""
            SELECT created_at, alert_type, scope, message, severity, metric_value
            FROM alerts
            ORDER BY created_at DESC
            LIMIT 5
        """)
        if not recent_alerts.empty:
            for _, row in recent_alerts.iterrows():
                print(f"  - [{row['created_at']}] {row['alert_type']}: {row['message']}")
        else:
            print("  (No alerts)")
        
        print("\n" + "=" * 60)
        print("✓ SMOKE TEST PASSED")
        print("=" * 60 + "\n")
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: Query error: {e}\n")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Smoke test for vulnerability management pipeline")
    parser.add_argument(
        "--skip-ingest",
        action="store_true",
        help="Skip ingestion steps (use existing data)"
    )
    
    args = parser.parse_args()
    success = run_smoke_test(skip_ingest=args.skip_ingest)
    exit(0 if success else 1)


if __name__ == "__main__":
    main()

