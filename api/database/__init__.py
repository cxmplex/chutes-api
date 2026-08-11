import uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from api.config import settings
from typing import AsyncGenerator
from contextlib import asynccontextmanager

engine = create_async_engine(
    settings.sqlalchemy,
    echo=settings.debug,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_overflow,
    pool_pre_ping=True,
    pool_reset_on_return="rollback",
    pool_timeout=30,
    pool_recycle=900,
    pool_use_lifo=True,
    connect_args={"ssl": settings.db_ssl},
)

SessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

ro_engine = (
    engine
    if not settings.postgres_ro
    else create_async_engine(
        settings.postgres_ro,
        echo=settings.debug,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_overflow,
        pool_pre_ping=True,
        pool_reset_on_return="rollback",
        pool_timeout=30,
        pool_recycle=900,
        pool_use_lifo=True,
        connect_args={"ssl": settings.db_ssl},
    )
)
SessionLocalRead = sessionmaker(
    bind=ro_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


def create_application_tables(sync_connection) -> None:
    """Create ORM-owned tables without materializing mapped database views as tables.

    SQLAlchemy models such as ``UserCurrentBalance`` are useful for querying a view, but
    ``MetaData.create_all`` otherwise creates a same-named ordinary table.  Every process that
    bootstraps ORM tables must use this helper so a worker cannot race the migration owner and
    replace a production materialized-view contract with an empty cache table.
    """

    tables = [table for table in Base.metadata.tables.values() if not table.info.get("is_view")]
    Base.metadata.create_all(sync_connection, tables=tables)


@asynccontextmanager
async def get_session(readonly=False) -> AsyncGenerator[AsyncSession, None]:
    session_maker = SessionLocalRead if readonly else SessionLocal
    async with session_maker() as session:
        try:
            yield session
            if not readonly:
                await session.commit()
        except Exception:
            if not readonly:
                try:
                    await session.rollback()
                except Exception:
                    pass
            raise


async def get_db_session():
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            try:
                await session.rollback()
            except Exception:
                pass
            raise


async def get_db_ro_session():
    async with SessionLocalRead() as session:
        yield session


async def db_scalar(stmt, *, readonly=True):
    """
    Execute a SELECT in its own short-lived session and return scalar_one_or_none().

    Use this (not a request-scoped ``Depends(get_db_session)`` session) for any DB
    access inside a ``StreamingResponse`` generator or other long-lived task: the
    transaction opens and closes per call, so the connection is never left "idle in
    transaction" for the life of the stream.
    """
    async with get_session(readonly=readonly) as session:
        return (await session.execute(stmt)).unique().scalar_one_or_none()


async def db_scalars(stmt, *, readonly=True):
    """
    Execute a SELECT in its own short-lived session and return scalars().all().

    See :func:`db_scalar` for why streaming endpoints must use this instead of a
    request-scoped session.
    """
    async with get_session(readonly=readonly) as session:
        return (await session.execute(stmt)).unique().scalars().all()


def generate_uuid():
    """
    Helper for uuid generation.
    """
    return str(uuid.uuid4())
