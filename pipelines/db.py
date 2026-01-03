"""
Database connection and utility functions.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import pandas as pd
from pathlib import Path
import config


_engine = None


def get_engine() -> Engine:
    """
    Get SQLAlchemy engine for PostgreSQL.
    
    Returns:
        SQLAlchemy engine instance
    """
    global _engine
    if _engine is None:
        connection_string = (
            f"postgresql://{config.DB_USER}:{config.DB_PASSWORD}"
            f"@{config.DB_HOST}:{config.DB_PORT}/{config.DB_NAME}"
        )
        _engine = create_engine(connection_string)
    return _engine


def run_sql_file(path: str) -> None:
    """
    Execute a SQL file.
    
    Args:
        path: Path to SQL file
    """
    engine = get_engine()
    sql_path = Path(path)
    
    if not sql_path.exists():
        raise FileNotFoundError(f"SQL file not found: {path}")
    
    with open(sql_path, 'r') as f:
        sql_content = f.read()
    
    with engine.begin() as conn:
        conn.execute(text(sql_content))


def fetch_df(query: str, params: dict = None) -> pd.DataFrame:
    """
    Execute a query and return results as pandas DataFrame.
    
    Args:
        query: SQL query string
        params: Optional query parameters
        
    Returns:
        pandas DataFrame with query results
    """
    engine = get_engine()
    with engine.connect() as conn:
        if params:
            result = conn.execute(text(query), params)
        else:
            result = conn.execute(text(query))
        df = pd.DataFrame(result.fetchall(), columns=result.keys())
    return df


def execute(query: str, params: dict = None) -> None:
    """
    Execute a query (for INSERT/UPDATE/DELETE).
    
    Args:
        query: SQL query string
        params: Optional query parameters
    """
    engine = get_engine()
    with engine.begin() as conn:
        if params:
            conn.execute(text(query), params)
        else:
            conn.execute(text(query))

