# Power BI Integration

## Overview

Connect Power BI to the PostgreSQL database to create interactive dashboards for vulnerability management.

## Data Sources

Connect to these tables:
- **report_cve_daily** - Daily CVE-level data with risk scores
- **report_product_daily** - Daily product-level aggregations
- **alerts** - Alert records (when implemented)

## Connection Details

1. Use PostgreSQL connector in Power BI
2. Server: Your database host
3. Database: Your database name
4. Authentication: Use database credentials
5. Import mode: DirectQuery recommended for real-time data

## Dashboard Layout

### Page 1: Executive Summary
- Total open vulnerabilities (KPI card)
- High/Critical count (KPI card)
- KEV count (KPI card)
- Average risk score trend (line chart)
- Top 10 products by risk (bar chart)

### Page 2: Patch Prioritization
- CVE list table with filters (severity, KEV, vendor, product)
- Risk score distribution (histogram)
- Age vs Risk scatter plot
- EPSS vs CVSS comparison chart
- Top vulnerabilities requiring immediate attention

### Page 3: Monitoring
- Product risk matrix (risk score vs vulnerability count)
- Product comparison table (all KPIs)
- Vendor breakdown (pie chart)
- Recent alerts timeline
- Risk score trends over time

## Table Relationships

- `report_cve_daily` and `report_product_daily` are linked by `vendor` and `product` fields
- Both tables use `as_of_date` for time-based filtering
- Use `as_of_date = MAX(as_of_date)` to show latest snapshot
