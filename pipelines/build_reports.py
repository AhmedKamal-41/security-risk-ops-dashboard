"""
Report generation pipeline.
"""

from pipelines.db import run_sql_file, fetch_df, get_engine
from pipelines.scoring import compute_risk_score
from sqlalchemy import text


def run_reports_build():
    """
    Build daily reports by executing SQL scripts and computing risk scores.
    
    Returns:
        tuple: (cve_rows_inserted, cve_rows_updated, product_rows_inserted)
    """
    # Step 1: Run CVE daily report SQL (inserts today's rows)
    run_sql_file("sql/02_build_report_cve_daily.sql")
    
    # Step 2: Fetch today's rows where risk_score is NULL
    query = """
        SELECT as_of_date, cve_id, cvss_score, is_kev, epss_score, age_days
        FROM report_cve_daily
        WHERE as_of_date = CURRENT_DATE AND risk_score IS NULL
    """
    df = fetch_df(query)
    
    # Step 3: Compute and update risk scores (bulk operation)
    if not df.empty:
        # Compute all risk scores at once
        df['risk_score'] = df.apply(
            lambda row: compute_risk_score(
                cvss_score=row["cvss_score"],
                is_kev=row["is_kev"],
                epss_score=row["epss_score"],
                age_days=row["age_days"]
            ),
            axis=1
        )
        
        # Bulk update using temporary table approach (much faster)
        engine = get_engine()
        with engine.begin() as conn:
            # Create temporary table with risk scores
            df[['as_of_date', 'cve_id', 'risk_score']].to_sql(
                'temp_risk_scores',
                conn,
                if_exists='replace',
                index=False,
                method='multi'
            )
            
            # Update report_cve_daily using temp table
            update_query = text("""
                UPDATE report_cve_daily r
                SET risk_score = t.risk_score
                FROM temp_risk_scores t
                WHERE r.as_of_date = t.as_of_date 
                  AND r.cve_id = t.cve_id
            """)
            result = conn.execute(update_query)
            updated_count = result.rowcount
            
            # Drop temporary table
            conn.execute(text("DROP TABLE IF EXISTS temp_risk_scores"))
    else:
        updated_count = 0
    
    # Get count of inserted CVE rows (before updates)
    cve_count_query = """
        SELECT COUNT(*) as count
        FROM report_cve_daily
        WHERE as_of_date = CURRENT_DATE
    """
    cve_count_df = fetch_df(cve_count_query)
    cve_rows_inserted = cve_count_df.iloc[0]["count"]
    
    # Step 4: Run product daily report SQL
    run_sql_file("sql/03_build_report_product_daily.sql")
    
    # Get count of product rows inserted
    product_count_query = """
        SELECT COUNT(*) as count
        FROM report_product_daily
        WHERE as_of_date = CURRENT_DATE
    """
    product_count_df = fetch_df(product_count_query)
    product_rows_inserted = product_count_df.iloc[0]["count"]
    
    return cve_rows_inserted, updated_count, product_rows_inserted
