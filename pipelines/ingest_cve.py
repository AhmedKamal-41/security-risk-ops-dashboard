"""
CVE data ingestion pipeline.
"""

import pandas as pd
import requests
import json
import time
from datetime import datetime, timedelta
from pipelines.db import get_engine
from sqlalchemy import text


# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD API rate limit: 5 requests per 30 seconds (without API key)
# With API key: 50 requests per 30 seconds
RATE_LIMIT_DELAY = 6.5  # Seconds between requests (safe for 5 req/30sec)


def fetch_cve_data(days_back=365, api_key=None):
    """
    Download CVE data from NVD API with pagination support.
    Note: NVD API limits date ranges to 120 days per request.
    
    Args:
        days_back: Number of days to look back (default 365 for full year)
        api_key: Optional NVD API key for higher rate limits
        
    Returns:
        dict: Dictionary with vulnerabilities list
        
    Raises:
        requests.RequestException: If network request fails
    """
    try:
        # Calculate date range (last N days)
        # Use yesterday as end date to avoid issues with today's data not being available yet
        end_date = datetime.now() - timedelta(days=1)
        start_date = end_date - timedelta(days=days_back)
        
        all_vulnerabilities = []
        max_date_range = 120  # NVD API limit: 120 days per request
        
        print(f"  Fetching CVEs from {start_date.date()} to {end_date.date()}...")
        print(f"  Note: NVD API limits to 120 days per request, splitting into chunks...")
        
        # Split into 120-day chunks
        # Ensure we don't go beyond available data - use yesterday as max end date
        max_end_date = datetime.now() - timedelta(days=1)
        current_end = min(end_date, max_end_date)
        chunk_num = 1
        total_chunks = (days_back + max_date_range - 1) // max_date_range  # Ceiling division
        
        while current_end > start_date:
            # Calculate chunk start (120 days back from current_end, or start_date if closer)
            chunk_start = max(start_date, current_end - timedelta(days=max_date_range))
            
            # Format dates for NVD API (ISO 8601 with Z timezone - REQUIRED)
            pub_start_date = chunk_start.strftime("%Y-%m-%dT00:00:00.000") + "Z"
            pub_end_date = current_end.strftime("%Y-%m-%dT23:59:59.999") + "Z"
            
            print(f"  Chunk {chunk_num}/{total_chunks}: {chunk_start.date()} to {current_end.date()}")
            
            # Fetch all pages for this chunk
            start_index = 0
            results_per_page = 2000
            chunk_total_results = None
            page = 0
            chunk_vulnerabilities = []
            
            while True:
                params = {
                    "pubStartDate": pub_start_date,
                    "pubEndDate": pub_end_date,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index
                }
                
                headers = {}
                if api_key:
                    headers["apiKey"] = api_key
                
                # Rate limiting: wait between requests
                if page > 0:
                    time.sleep(RATE_LIMIT_DELAY)
                
                response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
                
                # Check for errors with better messaging
                if response.status_code == 404:
                    error_msg = f"NVD API returned 404 for date range {chunk_start.date()} to {current_end.date()}\n"
                    error_msg += f"URL: {response.url}\n"
                    if not api_key:
                        error_msg += "Note: NVD API may require an API key. Get one at: https://nvd.nist.gov/developers/request-an-api-key\n"
                        error_msg += "Then add NVD_API_KEY to your .env file.\n"
                    error_msg += "Trying with a smaller date range (last 30 days) as fallback..."
                    print(f"  ⚠ {error_msg}")
                    
                    # Fallback: try last 30 days only
                    if days_back > 30:
                        print(f"  Falling back to last 30 days instead of {days_back} days...")
                        return fetch_cve_data(days_back=30, api_key=api_key)
                    else:
                        raise Exception(f"NVD API 404 error. Please check:\n1. API endpoint is correct\n2. Date range is valid\n3. API key is set (if required)")
                
                response.raise_for_status()
                
                data = response.json()
                
                # Get total results on first page
                if chunk_total_results is None:
                    chunk_total_results = data.get("totalResults", 0)
                    print(f"    Total in chunk: {chunk_total_results:,}")
                
                # Extract vulnerabilities
                vulnerabilities = data.get("vulnerabilities", [])
                chunk_vulnerabilities.extend(vulnerabilities)
                
                page += 1
                print(f"    Page {page}: Fetched {len(vulnerabilities)} CVEs (Chunk total: {len(chunk_vulnerabilities):,})")
                
                # Check if we've fetched all results for this chunk
                if len(vulnerabilities) == 0 or start_index + len(vulnerabilities) >= chunk_total_results:
                    break
                
                # Move to next page
                start_index += results_per_page
            
            all_vulnerabilities.extend(chunk_vulnerabilities)
            print(f"    ✓ Chunk {chunk_num} complete: {len(chunk_vulnerabilities):,} CVEs")
            
            # Move to next chunk (go back 120 days)
            current_end = chunk_start - timedelta(days=1)  # Overlap by 1 day to avoid gaps
            chunk_num += 1
            
            # Rate limit between chunks
            if current_end > start_date:
                time.sleep(RATE_LIMIT_DELAY)
        
        print(f"  ✓ Fetched {len(all_vulnerabilities):,} CVEs total across all chunks")
        
        # Return in same format as before
        return {"vulnerabilities": all_vulnerabilities}
        
    except requests.RequestException as e:
        raise Exception(f"Failed to fetch CVE data: {e}") from e


def normalize_cve(raw_data):
    """
    Parse and normalize CVE data into DataFrame.
    
    Args:
        raw_data: Raw JSON data from NVD API
        
    Returns:
        pandas.DataFrame: Normalized CVE data
    """
    vulnerabilities = raw_data.get("vulnerabilities", [])
    
    records = []
    for vuln_item in vulnerabilities:
        cve_item = vuln_item.get("cve", {})
        cve_id = cve_item.get("id")
        
        if not cve_id:
            continue
        
        # Extract published date
        published_date = None
        if "published" in cve_item:
            try:
                published_date = datetime.fromisoformat(cve_item["published"].replace("Z", "+00:00")).date()
            except:
                pass
        
        # Extract CVSS score and severity
        cvss_score = None
        severity = None
        
        if "metrics" in cve_item:
            # Try CVSS v3.1 first
            if "cvssMetricV31" in cve_item["metrics"]:
                cvss_data = cve_item["metrics"]["cvssMetricV31"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                severity = cvss_data.get("cvssData", {}).get("baseSeverity")
            # Fall back to CVSS v3.0
            elif "cvssMetricV30" in cve_item["metrics"]:
                cvss_data = cve_item["metrics"]["cvssMetricV30"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                severity = cvss_data.get("cvssData", {}).get("baseSeverity")
            # Fall back to CVSS v2
            elif "cvssMetricV2" in cve_item["metrics"]:
                cvss_data = cve_item["metrics"]["cvssMetricV2"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
        
        # Extract description (English)
        description = None
        if "descriptions" in cve_item:
            for desc in cve_item["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
        
        record = {
            "cve_id": cve_id,
            "published_date": published_date,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description,
            "source_json": json.dumps(cve_item),
            "ingested_at": datetime.now()
        }
        records.append(record)
    
    df = pd.DataFrame(records)
    return df


def upsert_cve(df):
    """
    Upsert CVE data into raw_cve table using bulk operations.
    
    Args:
        df: DataFrame with CVE data
        
    Returns:
        tuple: (inserted_count, updated_count)
    """
    if df.empty:
        return 0, 0
    
    engine = get_engine()
    
    # Count existing records
    cve_ids = df['cve_id'].tolist()
    if cve_ids:
        # Check existing in batches
        existing_count = 0
        batch_size = 1000
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i+batch_size]
            placeholders = ','.join([f"'{cve}'" for cve in batch])
            check_query = text(f"SELECT COUNT(*) FROM raw_cve WHERE cve_id IN ({placeholders})")
            with engine.connect() as conn:
                result = conn.execute(check_query)
                existing_count += result.fetchone()[0]
        
        updated_count = existing_count
        inserted_count = len(df) - updated_count
    else:
        updated_count = 0
        inserted_count = len(df)
    
    # Bulk upsert: delete existing, then insert all
    with engine.begin() as conn:
        # Delete existing records in batches
        if cve_ids:
            batch_size = 1000
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i+batch_size]
                placeholders = ','.join([f"'{cve}'" for cve in batch])
                delete_query = text(f"DELETE FROM raw_cve WHERE cve_id IN ({placeholders})")
                conn.execute(delete_query)
        
        # Bulk insert all records
        df.to_sql('raw_cve', conn, if_exists='append', index=False, method='multi', chunksize=5000)
    
    return inserted_count, updated_count


def run_cve_ingest(days_back=365, api_key=None):
    """
    Main entry point for CVE ingestion.
    
    Args:
        days_back: Number of days to look back (default 365 for full year)
        api_key: Optional NVD API key for higher rate limits
        
    Returns:
        tuple: (inserted_count, updated_count)
    """
    raw_data = fetch_cve_data(days_back=days_back, api_key=api_key)
    df = normalize_cve(raw_data)
    inserted, updated = upsert_cve(df)
    return inserted, updated
