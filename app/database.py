"""
Database models and session management for RedSurface.
Uses SQLAlchemy with SQLite for zero-config persistence.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Boolean, Float,
    ForeignKey, JSON, Enum as SAEnum, select
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import enum

# Database path
DB_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "redsurface.db"

# SQLAlchemy setup
engine = None
AsyncSessionLocal = None
Base = declarative_base()


class ScanStatus(str, enum.Enum):
    """Scan lifecycle states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Represents a scan job."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    target_type = Column(String(50), default="domain", nullable=False)
    status = Column(String(20), default=ScanStatus.PENDING.value, nullable=False)
    mode = Column(String(20), default="passive")  # passive / active
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)

    # Scan configuration (JSON blob of enabled modules + API keys)
    config = Column(JSON, nullable=True)

    # Relationships
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "target_type": self.target_type,
            "status": self.status,
            "mode": self.mode,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "config": self.config,
            "result_count": len(self.results) if self.results else 0,
        }


class ScanResult(Base):
    """Stores individual findings from a scan."""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module_name = Column(String(100), nullable=False)
    result_type = Column(String(50), nullable=False)  # subdomain, email, ip, tech, vuln, etc.
    value = Column(Text, nullable=False)
    parent_value = Column(String(255), nullable=True)  # For linking to parent (e.g., subdomain -> ip)
    metadata_json = Column(JSON, nullable=True)  # Extra structured data
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    scan = relationship("Scan", back_populates="results")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module_name": self.module_name,
            "result_type": self.result_type,
            "value": self.value,
            "parent_value": self.parent_value,
            "metadata": self.metadata_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ModuleConfig(Base):
    """Stores API keys and per-module settings."""
    __tablename__ = "module_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    module_name = Column(String(100), unique=True, nullable=False)
    enabled = Column(Boolean, default=True)
    api_key = Column(String(500), nullable=True)
    extra_config = Column(JSON, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "module_name": self.module_name,
            "enabled": self.enabled,
            "has_api_key": bool(self.api_key),
            "extra_config": self.extra_config,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


async def init_db():
    """Initialize the database asynchronously."""
    global engine, AsyncSessionLocal

    DB_DIR.mkdir(parents=True, exist_ok=True)

    # Use aiosqlite driver
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    AsyncSessionLocal = async_sessionmaker(
        bind=engine, 
        class_=AsyncSession, 
        autocommit=False, 
        autoflush=False, 
        expire_on_commit=False
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Get an async database session. Use as a dependency in FastAPI routes."""
    if AsyncSessionLocal is None:
        await init_db()
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
