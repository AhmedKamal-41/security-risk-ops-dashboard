# Alerting

## Idempotency

**The pipeline is safe to run multiple times per day — duplicate alerts are silently skipped.**

Uniqueness is enforced by a partial-key unique index on the `alerts` table:

```sql
CREATE UNIQUE INDEX alerts_unique_daily
    ON alerts (alert_type, scope, (DATE(created_at)));
```

This allows **one row per `(alert_type, scope)` per calendar day**. Every `INSERT` into `alerts` — whether from `pipelines/alerting.py` or `sql/04_insert_alerts.sql` — ends in:

```sql
ON CONFLICT (alert_type, scope, (DATE(created_at))) DO NOTHING
```

so a rerun that would produce the same alert is a no-op at the row level, not an error.

### Why an expression index (and not `UNIQUE (...)` on the table)

Postgres does not allow function expressions like `DATE(created_at)` inside inline table-level `UNIQUE` constraints — only bare column references are permitted there. A `CREATE UNIQUE INDEX` on an expression is the supported equivalent, and `ON CONFLICT` can target the same expression list. The `DATE(created_at)` expression is immutable because `created_at` is declared `TIMESTAMP` (without time zone), which is required for the index to be valid.

### Defense-in-depth, not the only layer

`pipelines/alerting.py::generate_alerts` still opens with a `DELETE FROM alerts WHERE DATE(created_at) = CURRENT_DATE` so reruns can refresh today's message text. The unique index sits behind that delete as a safety net: if two pipeline runs race, or the delete ever fails or is removed, the index still guarantees no duplicate `(alert_type, scope)` rows for that day.

### Operator impact

- Running `python run.py` or `python run.py --step run_alerts` twice on the same day is safe.
- Running the SQL file twice (`psql -f sql/04_insert_alerts.sql`) is safe.
- `alert_count` returned by `run_alerting()` reflects rows *attempted*, not rows actually written — on a pure rerun with no data change, the alerts table is unchanged even though `alert_count > 0`.
