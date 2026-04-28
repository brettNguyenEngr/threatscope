from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# In Docker, 'db' is the hostname from docker-compose.yml
# We default to the hardcoded credentials from the compose file for now
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:postgres@db:5432/threatscope"
)

# The Engine is the core interface to the database
engine = create_engine(DATABASE_URL)

# The SessionLocal class is a factory for generating new database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our future table models
Base = declarative_base()

# Dependency to yield a database session for our API routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()