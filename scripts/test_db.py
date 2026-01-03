"""
Simple database connection test.
"""

from pipelines.db import get_engine
from sqlalchemy import text


def main():
    """Test database connection."""
    try:
        engine = get_engine()
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
        print("DB OK")
    except Exception as e:
        print(f"DB connection failed: {e}")
        raise


if __name__ == "__main__":
    main()

