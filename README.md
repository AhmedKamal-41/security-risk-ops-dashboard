# Vulnerability Management Pipeline

## Overview

This project provides a comprehensive pipeline for ingesting, processing, and reporting on vulnerability data from multiple sources including:
- **CVE** (Common Vulnerabilities and Exposures) from NVD
- **KEV** (Known Exploited Vulnerabilities) from CISA
- **EPSS** (Exploit Prediction Scoring System) scores

The pipeline processes this data, computes risk scores, generates daily reports, and creates alerts for high-risk vulnerabilities.

## Installation

1. **Clone the repository** (if applicable) or navigate to the project directory

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure database connection:**
   - Copy `.env.example` to `.env` (if it exists) or create a `.env` file
   - Set the following environment variables:
     ```
     DB_HOST=your-database-host
     DB_PORT=5432
     DB_NAME=your-database-name
     DB_USER=your-database-user
     DB_PASSWORD=your-database-password
     ```
   - Or edit `config.py` directly with your database credentials

## Usage

### Run Full Pipeline

Run the complete pipeline (ingestion, reports, alerts):
```bash
python run.py
```

### Run Individual Steps

Run specific pipeline steps:
```bash
# Ingest KEV data
python run.py --step ingest_kev

# Ingest EPSS data
python run.py --step ingest_epss

# Ingest CVE data
python run.py --step ingest_cve

# Build reports
python run.py --step build_reports

# Run alerts
python run.py --step alerts
```

## Configuration

The pipeline uses `config.py` for database configuration. You can either:
- Set environment variables (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD)
- Edit `config.py` directly

## Pipeline Components

### 1. Data Ingestion (`pipelines/ingest_*.py`)

- **KEV Ingestion** (`ingest_kev.py`): Fetches Known Exploited Vulnerabilities from CISA
- **EPSS Ingestion** (`ingest_epss.py`): Downloads EPSS scores (300K+ records)
- **CVE Ingestion** (`ingest_cve.py`): Fetches recent CVEs from NVD API (last 30 days)

### 2. Risk Scoring (`pipelines/scoring.py`)

Computes composite risk scores based on:
- CVSS score (weight: 0.4)
- KEV status (bonus: 2.0)
- EPSS score (weight: 5.0)
- Vulnerability age (weight: 0.01 per day, capped at 365 days)

### 3. Report Generation (`pipelines/build_reports.py`)

Generates daily reports:
- **CVE Daily Report** (`report_cve_daily`): Individual CVE records with risk scores
- **Product Daily Report** (`report_product_daily`): Aggregated metrics by vendor/product

### 4. Alerting System (`pipelines/alerting.py`)

Generates alerts for:
- High risk score CVEs (risk_score >= 8.0)
- KEV vulnerabilities (all known exploited)
- High EPSS scores (EPSS >= 0.75)
- Products with high vulnerability counts (>= 50)
- Products with high average risk scores (>= 7.0)

## Database Schema

### Raw Data Tables
- `raw_cve`: CVE data from NVD
- `raw_kev`: Known Exploited Vulnerabilities
- `raw_epss`: EPSS scores with dates

### Report Tables
- `report_cve_daily`: Daily CVE snapshots with risk scores
- `report_product_daily`: Aggregated metrics by vendor/product

### Alert Table
- `alerts`: Generated alerts with severity and metrics

See `sql/01_create_tables.sql` for complete schema definitions.

## Reports

Reports are generated daily and stored in the database. Key metrics include:
- Open vulnerabilities count
- High/Critical severity count
- KEV count
- Average EPSS scores
- Average risk scores

### Exporting Reports

You can export reports to CSV for Power BI or other tools:

```python
from pipelines.db import fetch_df
import pandas as pd

# Export product reports
df = fetch_df("SELECT * FROM report_product_daily WHERE as_of_date = CURRENT_DATE")
df.to_csv('product_reports.csv', index=False)

# Export CVE reports
df = fetch_df("SELECT * FROM report_cve_daily WHERE as_of_date = CURRENT_DATE")
df.to_csv('cve_reports.csv', index=False)

# Export alerts
df = fetch_df("SELECT * FROM alerts WHERE DATE(created_at) = CURRENT_DATE")
df.to_csv('alerts.csv', index=False)
```

## Alerting

The alerting system automatically generates alerts for high-risk situations. Alerts are stored in the `alerts` table and can be:
- Viewed in the database
- Exported to CSV
- Integrated with notification systems

### Alert Types

1. **high_risk_cve**: CVEs with risk scores >= 8.0
2. **kev_vulnerability**: All vulnerabilities in CISA KEV catalog
3. **high_epss**: CVEs with EPSS scores >= 0.75
4. **high_vuln_count**: Products with >= 50 vulnerabilities
5. **high_avg_risk**: Products with average risk scores >= 7.0

### Viewing Alerts

```sql
SELECT * FROM alerts 
WHERE DATE(created_at) = CURRENT_DATE 
ORDER BY severity DESC, created_at DESC;
```

## Performance

- **EPSS Ingestion**: Processes ~309,000 records (takes 1-2 minutes with bulk operations)
- **CVE Ingestion**: Fetches last 30 days from NVD API
- **Report Building**: Optimized with bulk operations for fast processing
- **Alerting**: Generates alerts based on configurable thresholds

## Documentation

Additional documentation:
- `docs/kpis.md`: Key Performance Indicators
- `docs/scoring.md`: Risk scoring methodology
- `docs/powerbi.md`: Power BI integration guide

## Troubleshooting

### Common Issues

1. **Database Connection Errors**: Verify database credentials in `config.py` or environment variables
2. **EPSS Ingestion Slow**: This is normal for 300K+ records. The bulk operation should complete in 1-2 minutes
3. **NULL Constraint Violations**: Ensure all required fields are populated (vendor/product use 'Unknown' for non-KEV CVEs)
4. **Decimal Type Errors**: The scoring system handles PostgreSQL Decimal types automatically

## License

[Add your license here]
