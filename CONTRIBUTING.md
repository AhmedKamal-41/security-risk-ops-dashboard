# Contributing

Thanks for your interest in this project. This guide walks through forking, setting up a local PostgreSQL instance, running the pipeline, and contributing changes back.

## Prerequisites

- Python 3.11 or newer
- PostgreSQL 14 or newer (16 is what CI uses)
- Git
- `make` is not required — every command is a plain `python` or `pip` invocation

## Fork and clone

1. Fork this repository on GitHub (top-right "Fork" button).
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/security-risk-ops-dashboard.git
   cd security-risk-ops-dashboard
   ```
3. Create a feature branch:
   ```bash
   git checkout -b my-change
   ```

## Set up a local PostgreSQL instance

### Option A — native install

macOS (Homebrew):
```bash
brew install postgresql@16
brew services start postgresql@16
createdb vuln_mgmt
```

Ubuntu / Debian:
```bash
sudo apt-get install postgresql
sudo -u postgres createdb vuln_mgmt
sudo -u postgres createuser --superuser "$USER"
```

Windows: install from [postgresql.org/download/windows](https://www.postgresql.org/download/windows/), then from `pgAdmin` or `psql`:
```sql
CREATE DATABASE vuln_mgmt;
```

### Option B — Docker

```bash
docker run --name vuln-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=vuln_mgmt \
  -p 5432:5432 \
  -d postgres:16
```

Either option gives you a database at `localhost:5432/vuln_mgmt`.

## Configure the project

1. Create your local environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and fill in the DB credentials that match your setup. The example values already assume `localhost:5432/vuln_mgmt`.
3. (Optional) Request a free NVD API key at <https://nvd.nist.gov/developers/request-an-api-key> and add it to `.env` as `NVD_API_KEY=...` — without it, CVE ingestion is rate-limited to 5 requests per 30 seconds.

## Install Python dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run the pipeline

Create the schema, then run the full pipeline:

```bash
python run.py --step create_tables
python run.py                    # full run: ingestion → reports → alerts
```

Or run one step at a time (useful while developing a single pipeline stage):

```bash
python run.py --step ingest_kev
python run.py --step build_reports
python run.py --from-step ingest_cve   # resume from this step onward
```

Logs stream to stdout and also write to `logs/pipeline.log`.

## Run the tests

```bash
pytest
```

The suite exercises the scoring math and alert-threshold classification — no database is required to run it.

## Explore the data without a database

If you just want to see the visuals, open the notebooks — they read from `data/sample_data.csv` and need no DB:

```bash
jupyter notebook notebooks/dashboard_preview.ipynb
jupyter notebook notebooks/eda_and_insights.ipynb
```

## Open a pull request

1. Commit with a descriptive message (see [COMMIT_GUIDE.md](COMMIT_GUIDE.md) for the convention used here):
   ```bash
   git commit -m "feat: add retry/backoff to NVD ingestion"
   ```
2. Push your branch and open a PR against `main`.
3. Make sure `pytest` passes. CI will run the workflow in `.github/workflows/` on your PR.

## Design decisions

Three trade-offs worth surfacing up front — the full reasoning (with the costs each choice accepts) lives in [DECISIONS.md](DECISIONS.md).

- **Rebuild pattern, not incremental updates.** `report_cve_daily`, `report_product_daily`, and today's alerts are fully rewritten on each run rather than diffed. This trades wasted compute for idempotency: rerunning the pipeline is always safe, debugging a partial run just means rerunning it, and we don't maintain merge rules for upstream CVE/EPSS revisions. Migration path to partitioned incremental is mechanical if volume forces it.
- **Risk score weights bias toward exploitation probability.** The formula `cvss*0.4 + kev*2.0 + epss*5.0 + min(age, 365)*0.01` gives EPSS the largest single contribution (max 5.0) and CVSS a smaller one (max 4.0). The bet is that "likely to be exploited this month" (EPSS) is a better operational signal than "theoretically catastrophic if exploited" (CVSS) — contentious, and explicitly not ML-derived. Adjust the constants in `pipelines/scoring.py` if you disagree.
- **PostgreSQL over SQLite / parquet.** Chosen primarily for Power BI DirectQuery support and concurrent multi-user access, at the cost of zero-setup reproducibility. The `notebooks/` escape hatch exists specifically so someone can explore the project without provisioning a database.

## Getting help

- Open an issue for bugs, with reproduction steps and the relevant snippet of `logs/pipeline.log`.
- For design discussion, reference the specific section of `DECISIONS.md` you want to push back on — it's easier to argue about documented trade-offs than unwritten ones.
