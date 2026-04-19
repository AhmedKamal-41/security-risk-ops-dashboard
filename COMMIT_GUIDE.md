# Commit Guide

A plan for breaking this repo into meaningful commits that tell a real development story, plus examples to use as development continues.

## Commit message style

Use Conventional Commits. Keep the subject line under 72 chars, imperative mood, no trailing period.

```
<type>: <what changed in one line>

[optional body — the *why*, not the *what*]
```

Types used here: `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `chore`, `build`.

---

## Phased history (initial commits)

Replay the repo as seven phases. Each phase can be one commit or a small series.

### Phase 1 — Project scaffold
Files: `.gitignore`, `config.py`, `requirements.txt`, `run.py`, `pipelines/__init__.py`

- `chore: initialize project structure with gitignore and requirements`
- `feat: add config module for environment and DB settings`
- `feat: add run.py orchestrator entry point`

### Phase 2 — Database schema
Files: `sql/01_create_tables.sql`, `pipelines/db.py`, `scripts/test_db.py`

- `feat: add SQL schema for cve, kev, epss, reports and alerts tables`
- `feat: add db module with connection pool and helper queries`
- `test: add db connectivity smoke script`

### Phase 3 — Data ingestion (one commit per source)
Files: `pipelines/ingest_kev.py`, `pipelines/ingest_epss.py`, `pipelines/ingest_cve.py`

- `feat: add CISA KEV ingestion pipeline`
- `feat: add FIRST EPSS ingestion pipeline with CSV streaming`
- `feat: add NVD CVE ingestion pipeline with pagination`

### Phase 4 — Risk scoring logic
Files: `pipelines/scoring.py`, `docs/scoring.md`

- `feat: add risk scoring engine combining CVSS, EPSS and KEV signals`
- `docs: document risk scoring formula and weight rationale`

### Phase 5 — Report building
Files: `pipelines/build_reports.py`, `sql/02_build_report_cve_daily.sql`, `sql/03_build_report_product_daily.sql`

- `feat: add daily CVE report builder SQL`
- `feat: add product-level daily report aggregation SQL`
- `feat: add build_reports module to run report SQL end-to-end`

### Phase 6 — Alerting system
Files: `pipelines/alerting.py`, `sql/04_insert_alerts.sql`

- `feat: add alerts SQL for critical KEV and high-risk CVEs`
- `feat: add alerting module to emit and persist alerts`

### Phase 7 — Documentation and dashboard
Files: `README.md`, `docs/kpis.md`, `docs/powerbi.md`, `images/*.png`, `DECISIONS.md`, `PROJECT_STATUS.md`, `scripts/smoke_test.py`

- `docs: add README with architecture and quickstart`
- `docs: add KPI and Power BI dashboard guides`
- `docs: add dashboard screenshots`
- `test: add end-to-end smoke test for full pipeline`
- `docs: add design decisions and project status notes`

---

## Ongoing commit message examples

Use these as templates as you extend the project.

1. `feat: add EPSS bulk upsert optimization`
2. `fix: handle NULL vendor in product report aggregation`
3. `perf: batch CVE ingestion inserts to reduce round trips`
4. `fix: retry KEV download on transient 503 from CISA`
5. `feat: add Slack webhook notifier to alerting module`
6. `refactor: extract CVSS parser into shared utility`
7. `fix: prevent duplicate alert rows when rerunning pipeline`
8. `feat: add CLI flag to run.py for single-phase execution`
9. `docs: clarify scoring weights for exploited-in-wild CVEs`
10. `test: add unit tests for scoring edge cases (missing EPSS)`
11. `chore: pin requirements.txt versions for reproducible builds`
12. `feat: expose daily report as JSON export for Power BI refresh`
13. `fix: correct timezone handling in KEV date_added parsing`
14. `refactor: move SQL templates out of Python into sql/ files`
15. `perf: add index on cve.published_date for report queries`
16. `feat: add severity filter to alert SQL (>= High only)`
17. `fix: escape vendor strings in product_daily SQL insert`
18. `docs: add Power BI connection string example to powerbi.md`
19. `chore: add GitHub Actions workflow for linting and smoke tests`
20. `feat: add email digest summarizing overnight high-risk CVEs`

---

## Reminders for future work

- Commit per logical change, not per file. A scoring tweak + its test + doc update is **one** commit.
- If you catch yourself writing "and" in a subject line, split the commit.
- `fix:` requires a root cause in the body. "Handled NoneType" is a symptom; "EPSS API omits score when CVE is reserved" is a cause.
- Never mix schema changes (`sql/`) with pipeline code in the same commit unless the pipeline would break without the schema change — then say so in the body.
- Screenshots and large binary updates go in their own commit (`docs: refresh dashboard screenshots`) so code diffs stay reviewable.
