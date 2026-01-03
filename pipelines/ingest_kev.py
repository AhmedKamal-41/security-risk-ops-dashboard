"""
KEV (Known Exploited Vulnerabilities) data ingestion pipeline.
"""

import pandas as pd
import requests
import json
from datetime import datetime
from pipelines.db import get_engine
from sqlalchemy import text


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_data():
    """
    Download KEV catalog from CISA.
    
    Returns:
        dict: Raw JSON data from CISA KEV catalog
        
    Raises:
        requests.RequestException: If network request fails
    """
    try:
        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise Exception(f"Failed to fetch KEV data: {e}") from e


def normalize_kev(raw_data):
    """
    Parse and normalize KEV data into DataFrame.
    
    Args:
        raw_data: Raw JSON data from CISA
        
    Returns:
        pandas.DataFrame: Normalized KEV data
    """
    vulnerabilities = raw_data.get("vulnerabilities", [])
    
    records = []
    for vuln in vulnerabilities:
        record = {
            "cve_id": vuln.get("cveID"),
            "date_added": vuln.get("dateAdded"),
            "due_date": vuln.get("dueDate"),
            "vendor": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "source_json": json.dumps(vuln),
            "ingested_at": datetime.now()
        }
        records.append(record)
    
    df = pd.DataFrame(records)
    return df


def upsert_kev(df):
    """
    Upsert KEV data into raw_kev table.
    
    Args:
        df: DataFrame with KEV data
        
    Returns:
        tuple: (inserted_count, updated_count)
    """
    if df.empty:
        return 0, 0
    
    engine = get_engine()
    inserted_count = 0
    updated_count = 0
    
    with engine.begin() as conn:
        for _, row in df.iterrows():
            # Check if cve_id exists
            check_query = text("SELECT cve_id FROM raw_kev WHERE cve_id = :cve_id")
            result = conn.execute(check_query, {"cve_id": row["cve_id"]})
            exists = result.fetchone() is not None
            
            if exists:
                # Update existing record
                update_query = text("""
                    UPDATE raw_kev
                    SET date_added = :date_added,
                        due_date = :due_date,
                        vendor = :vendor,
                        product = :product,
                        source_json = :source_json,
                        ingested_at = :ingested_at
                    WHERE cve_id = :cve_id
                """)
                conn.execute(update_query, {
                    "cve_id": row["cve_id"],
                    "date_added": row["date_added"],
                    "due_date": row["due_date"],
                    "vendor": row["vendor"],
                    "product": row["product"],
                    "source_json": row["source_json"],
                    "ingested_at": row["ingested_at"]
                })
                updated_count += 1
            else:
                # Insert new record
                insert_query = text("""
                    INSERT INTO raw_kev 
                    (cve_id, date_added, due_date, vendor, product, source_json, ingested_at)
                    VALUES (:cve_id, :date_added, :due_date, :vendor, :product, :source_json, :ingested_at)
                """)
                conn.execute(insert_query, {
                    "cve_id": row["cve_id"],
                    "date_added": row["date_added"],
                    "due_date": row["due_date"],
                    "vendor": row["vendor"],
                    "product": row["product"],
                    "source_json": row["source_json"],
                    "ingested_at": row["ingested_at"]
                })
                inserted_count += 1
    
    return inserted_count, updated_count


def run_kev_ingest():
    """
    Main entry point for KEV ingestion.
    
    Returns:
        tuple: (inserted_count, updated_count)
    """
    raw_data = fetch_kev_data()
    df = normalize_kev(raw_data)
    inserted, updated = upsert_kev(df)
    return inserted, updated
