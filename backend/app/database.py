from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings


# ============================================================
# DATABASE ENGINE
# ============================================================

database_url = settings.database_url

# SQLite requires a special connection argument when used
# with FastAPI's request handling.
if database_url.startswith("sqlite"):
    engine = create_engine(
        database_url,
        connect_args={
            "check_same_thread": False
        },
    )

else:
    # MySQL, PostgreSQL, and other SQLAlchemy databases
    # do not need SQLite's check_same_thread option.
    engine = create_engine(
        database_url,
        pool_pre_ping=True,
    )


# ============================================================
# DATABASE SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ============================================================
# BASE MODEL
# ============================================================

Base = declarative_base()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    """
    Create a database session for a request and close it
    automatically when the request finishes.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()