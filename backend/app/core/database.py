from pathlib import Path
import os

# Some Windows application-control policies block SQLAlchemy native C extensions.
# SQLAlchemy officially supports disabling those optional extensions at runtime.
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT_RUNTIME", "1")

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = Path(os.getenv("SENTINELX_DB_PATH", str(DATA_DIR / "sentinelx.db")))
DB_FILE.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DB_FILE.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
