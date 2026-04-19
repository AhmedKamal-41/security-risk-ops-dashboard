# Design decisions

Engineer's notes on the trade-offs behind how this pipeline is built. These are the choices I'd expect a reviewer to push back on — documented here so we can argue about them explicitly instead of rediscovering the reasoning six months later.

## Why rebuild pattern instead of incremental updates

The report tables (`report_cve_daily`, `report_product_daily`) are fully recomputed each run rather than diffed against the previous snapshot. Same for alerts: today's rows are deleted and reinserted before the unique index kicks in.

Upsides that made this the right call for v1:
- **Idempotent by construction.** Running the pipeline twice in a day produces the same end state. Debugging a partial run just means rerunning it — no reconciliation script, no "what state am I in" question.
- **No merge logic to maintain.** CVE records mutate upstream (CVSS gets revised, KEV adds products, EPSS recalculates daily). Incremental updates would need field-by-field merge rules and a way to detect upstream re-revisions. Full rebuild sidesteps all of that.
- **Day-grain snapshots are the actual product.** Power BI asks "what did the world look like on 2026-03-15?" — that's a partitioned append-only shape, not a mutable row shape.

The costs I'm accepting:
- Wasted work. Most of the data a rebuild touches is identical to yesterday's. At current volume (~300K EPSS, tens of thousands of CVEs) this is fine; at 10× the volume it starts to hurt.
- Alert rewrites. If an alert's message text changes mid-day (e.g., risk score updates), the first run's DELETE clears it and the second inserts the new text. Operators see timestamp churn on otherwise-identical alerts.
- Nothing captures deletions. If NVD retracts a CVE, we won't notice — the row just stops appearing in the next rebuild.

If rebuild time becomes a problem, the migration path is per-day partitioning on `as_of_date` and only rebuilding the current partition. That's a mechanical change, not a redesign.

## Why this risk score formula

The weights in `pipelines/scoring.py` look arbitrary, and they partly are. The logic behind them:

```
risk = cvss*0.4 + (2.0 if kev else 0) + epss*5.0 + min(age_days, 365)*0.01
```

Maximum contribution per signal:
| Signal | Max | What it measures |
|---|---|---|
| EPSS × 5.0 | 5.0 | Probability of exploitation in the next 30 days |
| CVSS × 0.4 | 4.0 | Theoretical severity if exploited |
| Age × 0.01 (capped 365) | 3.65 | How long this has been unpatched |
| KEV bonus | 2.0 | Confirmed exploitation in the wild |

**EPSS is the heaviest single signal on purpose.** CVSS tells you how bad a hypothetical exploit would be; EPSS tells you how likely you are to actually get hit this month. For a risk-operations queue — which is what this dashboard drives — "likely today" beats "theoretically catastrophic" as a prioritization signal. A 9.8 CVSS with EPSS 0.01 is genuinely lower operational risk than a 7.5 with EPSS 0.9, and the formula reflects that.

**KEV is a flat bonus, not a multiplier.** KEV is binary and well-correlated with high EPSS anyway. Making it multiplicative would double-count the exploitation signal. Keeping it additive means KEV nudges a borderline CVE into the "escalate" band without dominating.

**Age has low weight and a cap.** Without the 365-day cap, a 10-year-old CVSS-4 bug would score above a 30-day-old CVSS-9 KEV — obviously wrong. The cap bounds stale CVEs at 3.65 points, which is below the KEV bonus alone.

What the formula is *not*:
- Not ML-derived. No training data, no backtest. The weights are a judgment call.
- Not calibrated against any ground truth of "vulnerabilities that actually caused incidents." That'd be the right v2.
- Not bounded to [0, 10]. The max is ~14.65. The alert threshold (8.0) and severity cutoffs in the UI assume this wider range; don't "normalize" the score without also moving the thresholds.

## Why PostgreSQL instead of a file-based approach

Considered SQLite and parquet + DuckDB before landing on Postgres. The deciding factors:

- **Power BI DirectQuery.** Parquet means extract-refresh; Postgres means DirectQuery with live data. For an ops dashboard where "did that alert clear?" should answer in seconds, that mattered more than any ingestion-side convenience.
- **Multi-table joins over `report_cve_daily ⨝ report_product_daily ⨝ alerts` at the query layer.** SQLite handles this fine for one user; Postgres handles it for a team hitting the dashboard concurrently.
- **The ingestion side already wants a database.** UPSERTs on `(cve_id)`, partial unique indexes for alert idempotency, `ON CONFLICT` semantics — we'd end up reimplementing a chunk of this on top of files. Not worth it.
- **Operational familiarity.** Postgres is the most boring, well-understood choice. No exotic features used; a junior engineer can inherit this without a primer.

What I gave up:
- Zero-setup reproducibility. You can't `git clone && python run.py` without provisioning a database first. The notebook at `notebooks/dashboard_preview.ipynb` is the escape hatch for anyone who just wants to see the visuals.
- Cost at rest. A managed Postgres instance is meaningfully more expensive than an S3 bucket of parquet. For personal/demo use this might be overkill.

## Known limitations and future improvements

Honest list of things I know are broken or under-served, not a roadmap:

- **CVE ingestion only covers NVD.** Vendor advisories (Microsoft MSRC, Red Hat RHSA, Cisco PSIRT, GitHub Security Advisories) are not pulled in. For vulnerabilities that are reserved but not yet NVD-published, we're blind. Fix would be per-source ingesters that feed a shared `raw_cve` with a `source` column.
- **Alert deduplication is day-level, not run-level.** The unique index on `(alert_type, scope, DATE(created_at))` prevents *duplicate rows* per day, but the DELETE-then-INSERT in `generate_alerts` still churns timestamps on every run. If we ever depend on `created_at` for "first-seen" semantics, this is a footgun.
- **No data retention policy for old report snapshots.** `report_cve_daily` grows unbounded — ~tens of thousands of rows per day × forever. There's no pruning job, no partitioning, no archive-to-cold-storage. At ~6 months in, this is fine; at 3 years it's a problem.
- **Scoring weights are heuristic, not ML-derived.** See the formula section above. Once we have ~12 months of "did this CVE actually get exploited in our environment" data, the right move is to fit weights against that outcome rather than defending the current numbers.
- **No schema migrations.** `sql/01_create_tables.sql` uses `CREATE TABLE IF NOT EXISTS`, which is fine for first-run but silently ignores column additions. First time we need to change a column type, we'll be hand-writing ALTER TABLE scripts. Alembic or sqitch would pay for itself at that point.
- **EPSS ingest is full-feed, not delta.** Every run re-reads all ~300K rows. The EPSS CSV doesn't expose a "changed since" filter, so a delta would have to diff against what we stored yesterday — not obviously faster than just re-upserting.
- **Tests don't cover ingestion or reporting.** The suite covers scoring math and alert thresholds — the pure-Python logic — because the DB-touching code is awkward to test without either live Postgres or a docker fixture. Worth fixing before the next major change to `build_reports.py`.
