"""
Main entry point for the vulnerability management pipeline.
"""

import argparse

import config
from pipelines.logger import get_logger
from pipelines.db import run_sql_file
from pipelines.ingest_kev import run_kev_ingest
from pipelines.ingest_epss import run_epss_ingest
from pipelines.ingest_cve import run_cve_ingest
from pipelines.build_reports import run_reports_build
from pipelines.alerting import run_alerting

logger = get_logger(__name__)


def create_tables():
    """Create database tables from SQL script."""
    logger.info("--- Step 1: Creating database tables ---")
    run_sql_file("sql/01_create_tables.sql")
    logger.info("Tables created successfully")


def ingest_kev():
    """Ingest KEV data."""
    logger.info("--- Step 2: Ingesting KEV data ---")
    inserted, updated = run_kev_ingest()
    logger.info("KEV ingestion complete: %d inserted, %d updated", inserted, updated)


def ingest_epss():
    """Ingest EPSS data."""
    logger.info("--- Step 3: Ingesting EPSS data ---")
    inserted, updated = run_epss_ingest()
    logger.info("EPSS ingestion complete: %d inserted, %d updated", inserted, updated)


def ingest_cve():
    """Ingest CVE data."""
    logger.info("--- Step 4: Ingesting CVE data ---")
    api_key = getattr(config, "NVD_API_KEY", None)
    inserted, updated = run_cve_ingest(days_back=config.CVE_DAYS_BACK, api_key=api_key)
    logger.info("CVE ingestion complete: %d inserted, %d updated", inserted, updated)


def build_reports():
    """Build daily reports."""
    logger.info("--- Step 5: Building reports ---")
    cve_inserted, cve_updated, product_inserted = run_reports_build()
    logger.info(
        "Report build complete: %d CVE rows inserted, %d risk scores updated, %d product rows inserted",
        cve_inserted, cve_updated, product_inserted,
    )


def run_alerts():
    """Run alerting system."""
    logger.info("--- Step 6: Running alerts ---")
    alert_count = run_alerting()
    logger.info("Alerting complete: %d alerts generated", alert_count)


# Single source of truth for pipeline step name -> function mapping.
# Insertion order is preserved (Python 3.7+) and defines execution order
# for --from-step and the full run. Add new steps here only.
PIPELINE_STEPS = {
    "create_tables": create_tables,
    "ingest_kev": ingest_kev,
    "ingest_epss": ingest_epss,
    "ingest_cve": ingest_cve,
    "build_reports": build_reports,
    "run_alerts": run_alerts,
}


def run_from_step(step_name):
    """Run pipeline starting from a specific step (skips previous steps)."""
    if step_name not in PIPELINE_STEPS:
        logger.error("Unknown step: %s", step_name)
        return

    logger.info("--- Resuming pipeline from: %s ---", step_name)

    step_names = list(PIPELINE_STEPS)
    start_index = step_names.index(step_name)

    try:
        for step in step_names[start_index:]:
            PIPELINE_STEPS[step]()
        logger.info("--- Pipeline execution complete ---")
    except Exception as e:
        logger.error("Pipeline failed: %s", e)
        raise


def run_full_pipeline():
    """Run the full pipeline in order."""
    logger.info("--- Starting Vulnerability Management Pipeline ---")

    try:
        for step in PIPELINE_STEPS.values():
            step()
        logger.info("--- Pipeline execution complete ---")
    except Exception as e:
        logger.error("Pipeline failed: %s", e)
        raise


def main():
    """Main function."""
    step_choices = list(PIPELINE_STEPS)

    parser = argparse.ArgumentParser(description="Vulnerability Management Pipeline")
    parser.add_argument(
        "--step",
        type=str,
        choices=step_choices,
        help="Run a single step instead of the full pipeline",
    )
    parser.add_argument(
        "--from-step",
        type=str,
        choices=step_choices,
        help="Run pipeline starting from this step (skips previous steps)",
    )

    args = parser.parse_args()

    if args.step:
        logger.info("Running single step: %s", args.step)
        PIPELINE_STEPS[args.step]()
    elif args.from_step:
        run_from_step(args.from_step)
    else:
        run_full_pipeline()


if __name__ == "__main__":
    main()
