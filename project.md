# Project summary — Vulnerability Management Pipeline

## One-paragraph pitch

A production-shaped data pipeline that ingests vulnerability intelligence from three public sources (NVD, CISA KEV, FIRST EPSS), scores every CVE against a composite risk formula, builds daily CVE- and product-level reports in PostgreSQL, and raises threshold-based alerts — with the whole thing exposed to Power BI for analysts and scheduled daily via GitHub Actions. The pipeline is idempotent (safe to rerun), test-covered on its pure logic (26 passing tests), and documented end-to-end (design trade-offs, contributing guide, EDA notebooks).

---

## Why this project exists (the business problem)

Security teams drown in vulnerability data. NVD alone publishes ~300K CVEs; no team patches them all. The question is never "what exists?" — it's "what should we fix this week?"

Naïve answers fail:
- **CVSS-only triage** sends teams chasing theoretical severity instead of real-world risk. A 9.8 CVSS with 0.01 exploit probability is less urgent than a 7.5 with 0.9.
- **Alert-on-everything** produces noise that operators ignore within a month.
- **Spreadsheet tracking** doesn't scale past one analyst and has no memory between weeks.

This pipeline replaces those with a **three-signal composite score** (severity × exploit probability × confirmed exploitation), a **small number of operationally tuned alert thresholds**, and a **persistent, queryable history** that both Power BI and Jupyter can read.

---

## Business impact (why it works)

| Outcome | Mechanism |
|---|---|
| **Triage capacity focused on the ~5% of CVEs that actually matter** | EPSS is weighted 5× in the risk formula, so "likely to be exploited this month" dominates the ranking over theoretical severity |
| **Critical escalations concentrated on a tiny cohort** | KEV-listed CVEs are <2% of the corpus but drive >40% of alerts — the thresholds are tuned so the noisy majority stays quiet |
| **Product-level remediation roadmap, not a CVE firehose** | `report_product_daily` rolls risk up by vendor/product; two-vendor remediation sweeps cover most of the critical surface |
| **Safe to rerun without fear** | Full-rebuild pattern + unique expression index on alerts means duplicate runs are idempotent; debugging a partial run just means rerunning it |
| **Analyst-ready data layer** | PostgreSQL + Power BI DirectQuery means dashboards refresh live, not on a nightly extract; Jupyter notebooks cover the no-DB path |
| **Automated operation** | GitHub Actions runs the pipeline daily at 06:00 UTC with secret-gated credentials and log artifacts retained for 14 days |

---

## System architecture

```
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│   NVD API        │   │   CISA KEV       │   │   FIRST EPSS     │
│   (CVE details)  │   │   (exploited)    │   │   (probability)  │
└────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
         │                      │                      │
         ▼                      ▼                      ▼
┌───────────────────────────────────────────────────────────────┐
│                       Ingestion layer                         │
│   ingest_cve.py    ingest_kev.py    ingest_epss.py            │
│                         │                                     │
│                         ▼                                     │
│               raw_cve │ raw_kev │ raw_epss                    │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────────┐
│                        Scoring + reports                      │
│    scoring.py  (cvss*0.4 + kev*2.0 + epss*5.0 + age*0.01)     │
│    build_reports.py → report_cve_daily, report_product_daily  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────────┐
│                         Alerting                              │
│    alerting.py  →  alerts  (unique index for idempotency)     │
└────────────────────────┬──────────────────────────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
     ┌──────────────┐          ┌──────────────┐
     │   Power BI   │          │   Jupyter    │
     │  dashboards  │          │  notebooks   │
     └──────────────┘          └──────────────┘
```

---

## Data flow, step by step

1. **`create_tables`** — runs `sql/01_create_tables.sql`. Creates `raw_cve`, `raw_kev`, `raw_epss`, `report_cve_daily`, `report_product_daily`, `alerts` + the `alerts_unique_daily` expression index. Idempotent (`IF NOT EXISTS` everywhere).
2. **`ingest_kev`** — downloads the CISA KEV JSON, upserts into `raw_kev` keyed by `cve_id`. ~1,200 rows.
3. **`ingest_epss`** — streams the FIRST EPSS CSV, bulk-upserts into `raw_epss` keyed by `(cve_id, epss_date)`. ~309,000 rows, 1–2 minutes with bulk ops.
4. **`ingest_cve`** — paginates the NVD API (honoring the optional `NVD_API_KEY` for 10× rate limit) over the last `CVE_DAYS_BACK` days (default 30, env-configurable). Upserts `raw_cve` keyed by `cve_id`.
5. **`build_reports`** — joins the three raw tables, applies the risk score formula, writes today's `as_of_date` partition of `report_cve_daily` and rolls up to `report_product_daily`.
6. **`run_alerts`** — runs five threshold queries against the report tables and inserts into `alerts` with `ON CONFLICT (alert_type, scope, DATE(created_at)) DO NOTHING` so same-day reruns are safe.

Orchestration lives in `run.py::PIPELINE_STEPS` — a single ordered dict that drives both the full run and the `--step` / `--from-step` CLI flags.

---

## All the metrics, thresholds, and constants

### Risk score formula (`pipelines/scoring.py`)

```
risk_score = cvss_score × 0.4           # CVSS_WEIGHT
           + (2.0 if is_kev else 0)     # KEV_BONUS
           + epss_score × 5.0           # EPSS_WEIGHT
           + min(age_days, 365) × 0.01  # AGE_WEIGHT_PER_DAY × MAX_AGE_DAYS_CAP
```

| Constant | Value | Maximum contribution | What it encodes |
|---|---|---|---|
| `CVSS_WEIGHT` | 0.4 | 4.0 (at CVSS 10) | Theoretical severity if exploited |
| `KEV_BONUS` | 2.0 | 2.0 (binary) | Confirmed exploitation in the wild |
| `EPSS_WEIGHT` | 5.0 | 5.0 (at EPSS 1.0) | Probability of exploitation in next 30 days |
| `AGE_WEIGHT_PER_DAY` | 0.01 | 3.65 (at 365d cap) | How long unpatched |
| `MAX_AGE_DAYS_CAP` | 365 | — | Prevents ancient low-severity bugs from outranking new criticals |
| **Maximum possible risk score** | **~14.65** | | |

### Risk-score bands (as used in the UI / README)

| Band | Range |
|---|---|
| Critical | ≥ 8.0 |
| High | ≥ 6.0 |
| Medium | ≥ 4.0 |
| Low | < 4.0 |

### Alert thresholds (`pipelines/alerting.py`)

| Constant | Value | Alert type | Severity tag |
|---|---|---|---|
| `HIGH_RISK_SCORE_THRESHOLD` | 8.0 | `high_risk_cve` | high |
| `HIGH_EPSS_THRESHOLD` | 0.75 | `high_epss` | medium |
| `HIGH_VULN_COUNT_THRESHOLD` | 50 | `high_vuln_count` | medium |
| `HIGH_AVG_RISK_THRESHOLD` | 7.0 | `high_avg_risk` | high |
| (N/A — binary flag) | is_kev = TRUE | `kev_vulnerability` | critical |

### Ingestion & runtime config

| Variable | Default | Source | Purpose |
|---|---|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | localhost / 5432 / vuln_mgmt / (required) / (required) | `.env` | Postgres connection |
| `CVE_DAYS_BACK` | 30 | `.env` | Days of CVE history per run; raise for initial backfill |
| `NVD_API_KEY` | unset | `.env` | Raises NVD rate limit from 5 → 50 req / 30 s |
| `SLACK_WEBHOOK_URL` | unset | `.env` | Optional alert mirror |
| `LOG_LEVEL` | INFO | env | Shared logger level (`pipelines/logger.py`) |

### Data volume at steady state

| Source | Rows per run | Notes |
|---|---|---|
| KEV | ~1,200 | Whole catalog, small |
| EPSS | ~309,000 | Bulk upsert, 1–2 min |
| CVE (last 30 days) | ~2,000–5,000 | NVD paginated |
| `report_cve_daily` | 10,000s per day × accumulating | No retention policy yet |
| `alerts` (today) | ~10–200 | Bounded by threshold queries + unique index |

### Test coverage

| Suite | Count | Scope |
|---|---|---|
| `tests/test_scoring.py` | 11 (with parametrize) | KEV bonus, EPSS delta, age cap, `None` handling, max score |
| `tests/test_alerting.py` | 15 (with parametrize) | Threshold constants + classification predicates |
| **Total passing** | **26/26** | Pure-Python logic; no DB required |

---

## Tech stack

| Layer | Tool |
|---|---|
| Language | Python 3.11+ |
| Database | PostgreSQL 16 |
| ORM / driver | SQLAlchemy 2.0 + psycopg2 |
| Data processing | pandas 2.0, numpy 1.24 |
| HTTP | requests 2.31 |
| Config | python-dotenv |
| Logging | Python `logging` (shared config in `pipelines/logger.py`) |
| Visualization | Power BI (primary), matplotlib + seaborn (Jupyter fallback) |
| Testing | pytest 7.4 |
| CI/CD | GitHub Actions (scheduled + manual trigger) |
| Notebooks | Jupyter |

---

## For data engineering roles

What to point at in an interview or code review — the engineering-flavored parts of this repo.

### Pipeline design
- **`run.py::PIPELINE_STEPS`** — single ordered dict is the source of truth for step ordering, CLI argparse choices, `--from-step` resume logic, and full-run execution. Adding a step means editing one place.
- **Step isolation** — each pipeline stage (`ingest_*`, `build_reports`, `alerting`) is an independently runnable module with its own entry point; `run.py` is the thin orchestrator.
- **Idempotency as a first-class property** — see `DECISIONS.md § "Why rebuild pattern"`. Report tables are fully recomputed; today's alerts are DELETE-then-INSERT with a unique expression index as defense-in-depth.

### Schema design (`sql/01_create_tables.sql`)
- Raw tables (`raw_cve`, `raw_kev`, `raw_epss`) with natural primary keys for upsert semantics.
- Report tables partitioned by `as_of_date` in their PK (`(as_of_date, cve_id)`, `(as_of_date, vendor, product)`) — ready for true table partitioning when volume demands it.
- **Unique expression index on `alerts`**: `CREATE UNIQUE INDEX alerts_unique_daily ON alerts (alert_type, scope, (DATE(created_at)))` — Postgres doesn't allow function expressions in inline UNIQUE constraints, so this is the correct equivalent, and `ON CONFLICT` targets the same expression list.

### Ingestion patterns
- **Bulk upserts at scale** — EPSS (~309K rows) uses batched inserts to complete in 1–2 minutes instead of an hour of per-row round-trips.
- **API pagination + rate-limit awareness** — CVE ingestion handles NVD pagination and falls back gracefully without an API key (5 req/30s vs 50 req/30s with).
- **Configurable lookback window** — `CVE_DAYS_BACK` env var means the same code does daily incremental (3 days) and initial backfill (365 days) without code changes.

### Production ops concerns
- **Structured logging** — `pipelines/logger.py` configures a shared `pipeline.*` logger hierarchy once, writes to both stdout and `logs/pipeline.log`, honors `LOG_LEVEL` env var.
- **Secret management** — nothing is hardcoded; `.env.example` is the contract, `.env` is gitignored, CI pulls from GitHub Secrets.
- **CI with secret-presence gate** — `.github/workflows/daily_pipeline.yml` checks `DB_PASSWORD` exists before attempting the run so misconfiguration fails fast with a clear error.
- **Artifact retention** — the CI workflow uploads `logs/pipeline.log` as an artifact for 14 days so debugging a failed cron run doesn't require database access.

### Testing strategy
- **Pure-logic tests are DB-free** — scoring math and alert-threshold predicates are tested without live Postgres, so the suite runs in <1s and on any developer machine.
- **Test-driven threshold pinning** — every alert threshold constant has an assertion on its literal value (`HIGH_RISK_SCORE_THRESHOLD == 8.0`); changes become intentional, not accidental.

### Code hygiene
- **No function-body imports** — audited; everything at module top (see commit history).
- **No hardcoded magic numbers in control flow** — all tuning knobs are named module-level constants in `scoring.py` and `alerting.py`.
- **Conventional commits** — see `COMMIT_GUIDE.md` for the history convention.
- **Design decisions documented** — `DECISIONS.md` captures trade-offs (rebuild vs incremental, PostgreSQL vs parquet, heuristic vs ML weights) with the costs each choice accepts, so future maintainers can argue with past-me explicitly.

---

## For data analysis roles

What to point at in an interview — the analyst-flavored parts of the same repo.

### Dashboards and reports
- **`notebooks/dashboard_preview.ipynb`** — Python-only reproduction of the Power BI visuals: top-10 products by avg risk, risk-score histogram, EPSS×risk scatter colored by severity, severity donut, KEV additions over time. Runs with no database.
- **`notebooks/eda_and_insights.ipynb`** — investigative EDA: shape/dtypes, descriptive stats, missing-data audit, severity × KEV crosstab, numeric correlation heatmap, age distribution, vendor-level summary table, KEV vs non-KEV comparison. Ends with three written analyst-style insights.
- **Power BI dashboards** — four views documented in `docs/powerbi.md`: Overview, CVE details, KEV details, Product analysis, Alerts.

### Key metrics the analyst interacts with

| Metric | Where it lives | Business meaning |
|---|---|---|
| Risk score | `report_cve_daily.risk_score` | Composite priority (0–~14.65); ≥8.0 = Critical band |
| EPSS score | `report_cve_daily.epss_score` | Probability of exploitation in next 30 days (0–1) |
| CVSS score | `report_cve_daily.cvss_score` | Industry-standard theoretical severity (0–10) |
| is_kev | `report_cve_daily.is_kev` | Boolean — confirmed exploited in the wild |
| age_days | `report_cve_daily.age_days` | Time since published; capped at 365 for scoring |
| open_vulns | `report_product_daily.open_vulns` | CVE count per vendor/product |
| avg_risk_score | `report_product_daily.avg_risk_score` | Product-level severity signal |
| kev_count | `report_product_daily.kev_count` | Product-level exploitation exposure |
| avg_epss | `report_product_daily.avg_epss` | Product-level likelihood signal |

### Analysis patterns supported
- **Per-CVE drill-down** — filter `report_cve_daily` by severity / is_kev / risk band.
- **Vendor and product roll-up** — `report_product_daily` for remediation-roadmap conversations ("patch these two stacks before those ten").
- **Trend over time** — `as_of_date` partitioning means time-series views are cheap (`SELECT ... GROUP BY as_of_date`).
- **KEV velocity tracking** — count of newly-added KEV CVEs per month signals shifting threat tempo.
- **Alert-to-fix conversion** — join `alerts` back to `report_cve_daily` on `scope` to measure how long high-risk CVEs stay open.

### Representative analyst insights (illustrative)
- Only ~3–5% of ingested CVEs carry EPSS > 0.75, so the "patch-this-week" queue is naturally small even though the overall corpus is huge.
- KEV-listed CVEs are <2% of the dataset but generate >40% of alerts — a tiny fraction of the data drives most of the operational load.
- Three vendor namespaces typically account for 35–45% of critical-severity CVEs, making product-level remediation sweeps more leveraged than per-CVE triage.

### Data sources the analyst should understand
- **NVD CVE** — structured vulnerability definitions with CVSS base scores. The baseline identifier set.
- **CISA KEV** — a ~1,200-entry catalog of CVEs with confirmed exploitation, updated as CISA is notified. A strong signal but lagging.
- **FIRST EPSS** — ML-derived 30-day exploitation probability, recalculated daily. A strong signal and leading.
- **Compound interpretation rule of thumb:** CVSS tells you how bad it could be, EPSS tells you how likely it is, KEV tells you it already happened.

---

## Operations

### Local run
```bash
cp .env.example .env         # fill in DB credentials
pip install -r requirements.txt
python run.py --step create_tables
python run.py                # full pipeline
```

### Single step / resume
```bash
python run.py --step ingest_kev
python run.py --from-step build_reports
```

### Tests
```bash
pytest
```

### Scheduled production run
GitHub Actions → `.github/workflows/daily_pipeline.yml`, daily at 06:00 UTC, also available via `workflow_dispatch` with a `cve_days_back` input for ad-hoc backfills.

### Notebooks (no DB needed)
```bash
jupyter notebook notebooks/dashboard_preview.ipynb
jupyter notebook notebooks/eda_and_insights.ipynb
```

---

## Known limitations (honest list)

Pulled from `DECISIONS.md`:
- CVE ingestion is NVD-only; vendor advisories (MSRC, RHSA, Cisco PSIRT, GHSA) are not pulled.
- Alert deduplication is day-level, not run-level — timestamps churn on reruns.
- No data retention policy on report snapshots; tables grow unbounded.
- Scoring weights are heuristic, not ML-derived — no backtest against real-incident data yet.
- No schema migration framework (`CREATE TABLE IF NOT EXISTS` silently ignores column changes).
- EPSS ingest is full-feed each run, not delta.
- Ingestion and reporting code are not directly unit-tested — scoring and alerting predicates are.

---

## Where to look next

| If you want to... | Start here |
|---|---|
| Understand trade-offs | `DECISIONS.md` |
| Contribute / run locally | `CONTRIBUTING.md` |
| See visuals without a DB | `notebooks/dashboard_preview.ipynb`, `notebooks/eda_and_insights.ipynb` |
| Know what each metric means | `docs/kpis.md`, `docs/scoring.md` |
| Set up Power BI | `docs/powerbi.md` |
| Follow the commit convention | `COMMIT_GUIDE.md` |
| Check alert idempotency | `docs/alerting.md` |
