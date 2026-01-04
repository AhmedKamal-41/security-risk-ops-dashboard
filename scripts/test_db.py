"""
Simple database connection test.
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

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

