"""
EPSS (Exploit Prediction Scoring System) data ingestion pipeline.
"""

import pandas as pd
import requests
import json
import gzip
import io
from datetime import datetime
from pipelines.db import get_engine
from sqlalchemy import text


EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def fetch_epss_data():
    """
    Download EPSS current scores data.
    
    Returns:
        pandas.DataFrame: Raw EPSS data
        
    Raises:
        requests.RequestException: If network request fails
        Exception: If decompression or parsing fails
    """
    try:
        response = requests.get(EPSS_URL, timeout=60)
        response.raise_for_status()
        
        # Decompress gzip content
        compressed_data = io.BytesIO(response.content)
        with gzip.open(compressed_data, 'rt') as f:
            df = pd.read_csv(f)
        
        return df
    except requests.RequestException as e:
        raise Exception(f"Failed to fetch EPSS data: {e}") from e
    except (gzip.BadGzipFile, pd.errors.EmptyDataError) as e:
        raise Exception(f"Failed to parse EPSS data: {e}") from e


def normalize_epss(df):
    """
    Parse and normalize EPSS data into DataFrame.
    
    Args:
        df: Raw EPSS DataFrame from CSV
        
    Returns:
        pandas.DataFrame: Normalized EPSS data
    """
    # Get current date for epss_date
    epss_date = datetime.now().date()
    
    records = []
    for _, row in df.iterrows():
        # Convert row to dict for JSON storage
        source_record = row.to_dict()
        
        record = {
            "cve_id": row.get("cve"),
            "epss_date": epss_date,
            "epss_score": row.get("epss"),
            "percentile": row.get("percentile"),
            "source_json": json.dumps(source_record),
            "ingested_at": datetime.now()
        }
        records.append(record)
    
    normalized_df = pd.DataFrame(records)
    return normalized_df


def upsert_epss(df):
    """
    Upsert EPSS data into raw_epss table.
    
    Args:
        df: DataFrame with EPSS data
        
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
            # Check if (cve_id, epss_date) exists
            check_query = text("""
                SELECT cve_id FROM raw_epss 
                WHERE cve_id = :cve_id AND epss_date = :epss_date
            """)
            result = conn.execute(check_query, {
                "cve_id": row["cve_id"],
                "epss_date": row["epss_date"]
            })
            exists = result.fetchone() is not None
            
            if exists:
                # Update existing record
                update_query = text("""
                    UPDATE raw_epss
                    SET epss_score = :epss_score,
                        percentile = :percentile,
                        source_json = :source_json,
                        ingested_at = :ingested_at
                    WHERE cve_id = :cve_id AND epss_date = :epss_date
                """)
                conn.execute(update_query, {
                    "cve_id": row["cve_id"],
                    "epss_date": row["epss_date"],
                    "epss_score": row["epss_score"],
                    "percentile": row["percentile"],
                    "source_json": row["source_json"],
                    "ingested_at": row["ingested_at"]
                })
                updated_count += 1
            else:
                # Insert new record
                insert_query = text("""
                    INSERT INTO raw_epss 
                    (cve_id, epss_date, epss_score, percentile, source_json, ingested_at)
                    VALUES (:cve_id, :epss_date, :epss_score, :percentile, :source_json, :ingested_at)
                """)
                conn.execute(insert_query, {
                    "cve_id": row["cve_id"],
                    "epss_date": row["epss_date"],
                    "epss_score": row["epss_score"],
                    "percentile": row["percentile"],
                    "source_json": row["source_json"],
                    "ingested_at": row["ingested_at"]
                })
                inserted_count += 1
    
    return inserted_count, updated_count


def run_epss_ingest():
    """
    Main entry point for EPSS ingestion.
    
    Returns:
        tuple: (inserted_count, updated_count)
    """
    raw_df = fetch_epss_data()
    df = normalize_epss(raw_df)
    inserted, updated = upsert_epss(df)
    return inserted, updated
