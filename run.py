"""
Main entry point for the vulnerability management pipeline.
"""

import argparse
from pipelines.db import run_sql_file
from pipelines.ingest_kev import run_kev_ingest
from pipelines.ingest_epss import run_epss_ingest
from pipelines.build_reports import run_reports_build


def create_tables():
    """Create database tables from SQL script."""
    print("=" * 60)
    print("Step 1: Creating database tables...")
    print("=" * 60)
    run_sql_file("sql/01_create_tables.sql")
    print("✓ Tables created successfully\n")


def ingest_kev():
    """Ingest KEV data."""
    print("=" * 60)
    print("Step 2: Ingesting KEV data...")
    print("=" * 60)
    inserted, updated = run_kev_ingest()
    print(f"✓ KEV ingestion complete: {inserted} inserted, {updated} updated\n")


def ingest_epss():
    """Ingest EPSS data."""
    print("=" * 60)
    print("Step 3: Ingesting EPSS data...")
    print("=" * 60)
    inserted, updated = run_epss_ingest()
    print(f"✓ EPSS ingestion complete: {inserted} inserted, {updated} updated\n")


def ingest_cve():
    """Ingest CVE data."""
    print("=" * 60)
    print("Step 4: Ingesting CVE data...")
    print("=" * 60)
    print("⚠ CVE ingestion not yet implemented\n")


def build_reports():
    """Build daily reports."""
    print("=" * 60)
    print("Step 5: Building reports...")
    print("=" * 60)
    cve_inserted, cve_updated, product_inserted = run_reports_build()
    print(f"✓ Report build complete: {cve_inserted} CVE rows inserted, {cve_updated} risk scores updated, {product_inserted} product rows inserted\n")


def run_alerts():
    """Run alerting system."""
    print("=" * 60)
    print("Step 6: Running alerts...")
    print("=" * 60)
    print("⚠ Alerting not yet implemented\n")


def run_full_pipeline():
    """Run the full pipeline in order."""
    print("\n" + "=" * 60)
    print("Starting Vulnerability Management Pipeline")
    print("=" * 60 + "\n")
    
    try:
        create_tables()
        ingest_kev()
        ingest_epss()
        ingest_cve()
        build_reports()
        run_alerts()
        
        print("=" * 60)
        print("Pipeline execution complete!")
        print("=" * 60 + "\n")
    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        raise


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Vulnerability Management Pipeline")
    parser.add_argument(
        "--step",
        type=str,
        choices=["create_tables", "ingest_kev", "ingest_epss", "ingest_cve", "build_reports", "run_alerts"],
        help="Run a single step instead of the full pipeline"
    )
    
    args = parser.parse_args()
    
    if args.step:
        print(f"\nRunning single step: {args.step}\n")
        step_functions = {
            "create_tables": create_tables,
            "ingest_kev": ingest_kev,
            "ingest_epss": ingest_epss,
            "ingest_cve": ingest_cve,
            "build_reports": build_reports,
            "run_alerts": run_alerts
        }
        step_functions[args.step]()
    else:
        run_full_pipeline()


if __name__ == "__main__":
    main()

