#!/usr/bin/env python3
"""
Database initialization script for integration tests.
Uses SQLAlchemy to create tables from your actual ORM models.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, Mock


DEFAULT_TEST_DATABASE_URL = (
    "postgresql+asyncpg://testuser:testpass@localhost:5432/chutes_test"
)
# Production constructs its engine while importing ``api.database``. Point that same serialized
# migration owner at the explicitly disposable test database before any API import can cache the
# settings object or engine.
test_database_url = os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)
# TEST_DATABASE_URL is the explicit disposable-test boundary. Never let a pre-existing
# production-style POSTGRESQL variable redirect this migration owner to another database.
os.environ["POSTGRESQL"] = test_database_url
os.environ.setdefault("DB_SSL", "disable")

# Mock Redis and taskiq before any imports that might trigger events
sys.modules["redis.asyncio"] = Mock()
sys.modules["taskiq"] = Mock()
sys.modules["taskiq_redis"] = Mock()

# Mock the forge task specifically
mock_forge = AsyncMock()
mock_forge.kiq = AsyncMock()

# Patch the forge import before any ORM imports
import api.image.forge  # noqa

api.image.forge.forge = mock_forge

from api.image.schemas import Image  # noqa
from api.user.schemas import User  # noqa

from sqlalchemy.engine import make_url  # noqa
from sqlalchemy.ext.asyncio import AsyncSession  # noqa
from sqlalchemy.orm import sessionmaker  # noqa
from api.database import engine  # noqa
from api.database.migrations import run_database_migrations  # noqa
from api.config import settings  # noqa

# Import all ORM modules exactly like production does
import api.database.orms  # noqa
from api.util import gen_random_token  # noqa


async def create_test_database():
    """Build the test schema through the same serialized production migration owner."""
    test_db_url = settings.sqlalchemy
    print(
        "Connecting to test database: "
        f"{make_url(test_db_url).render_as_string(hide_password=True)}"
    )

    try:
        print("Applying the complete production-base and dbmate migration chain...")
        await run_database_migrations()

        print("Database schema migrated successfully!")

        # Create test data
        await create_test_data(engine)

        await create_test_bucket()

    except Exception as e:
        print(f"Error creating database: {e}")
        raise
    finally:
        await engine.dispose()


async def create_test_bucket():
    async with settings.s3_client() as s3:
        await s3.create_bucket(Bucket="chutes")


async def create_test_data(engine):
    """Create test data for integration tests."""
    print("Creating test data...")

    # Create async session
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as session:
        try:
            # Create test users using the proper User.create() method
            test_users_data = [
                {
                    "username": "testuser1",
                    "coldkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",  # Example Substrate address
                    "hotkey": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",  # Example hotkey
                },
                {
                    "username": "testuser2",
                    "coldkey": "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y",
                    "hotkey": "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
                },
                {
                    "username": "integrationtest",
                    "coldkey": "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw",
                    "hotkey": None,  # Some users may not have hotkeys
                },
            ]

            created_users = []
            for user_data in test_users_data:
                # Use the User.create() class method which handles fingerprint generation
                user, fingerprint = User.create(
                    username=user_data["username"],
                    coldkey=user_data["coldkey"],
                    hotkey=user_data["hotkey"],
                )

                # Add some test wallet addresses and balance
                user.payment_address = (
                    f"bc1q{gen_random_token(k=20).lower()}"  # Mock BTC address
                )
                user.balance = 100.0 if user_data["username"] == "testuser1" else 0.0

                session.add(user)
                created_users.append(user)

            # Commit users first so we can reference them in foreign keys
            await session.commit()

            # Query back the committed users to get their actual user_ids
            from sqlalchemy import select

            user_result = await session.execute(
                select(User).where(
                    User.username.in_(["testuser1", "testuser2", "integrationtest"])
                )
            )
            committed_users = {
                user.username: user.user_id for user in user_result.scalars().all()
            }

            # Create test images using the actual user_ids
            test_images = [
                Image(
                    image_id="test-image-1",
                    user_id=committed_users["testuser1"],
                    name="test-app",
                    tag="latest",
                    readme="Test application image for integration tests",
                    logo_id=None,  # Explicitly None like production does
                    public=True,
                    chutes_version="0.3.11.rc3",
                    # Remove: status, patch_version, build_started_at, build_completed_at
                ),
                Image(
                    image_id="test-image-2",
                    user_id=committed_users["testuser2"],
                    name="private-app",
                    tag="v1.0",
                    readme="Private test image",
                    logo_id=None,
                    public=False,
                    chutes_version="0.3.11.rc3",
                ),
                Image(
                    image_id="test-image-signed",
                    user_id=committed_users["integrationtest"],
                    name="signed-app",
                    tag="latest",
                    readme="Image for testing cosign signing workflow",
                    logo_id=None,
                    public=True,
                    chutes_version="0.3.11.rc3",
                ),
            ]

            for image in test_images:
                session.add(image)

            await session.commit()
            print("Test data created successfully!")

        except Exception as e:
            await session.rollback()
            print(f"Error creating test data: {e}")
            raise


async def cleanup_test_data(engine):
    """Clean up test data - useful for running between tests."""
    print("Cleaning up test data...")

    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as session:
        try:
            from sqlalchemy import delete

            # Delete in reverse order of dependencies to avoid foreign key errors

            # Delete instances first (if they exist)
            try:
                from api.instance.schemas import Instance

                await session.execute(
                    delete(Instance).where(Instance.instance_id.like("test-instance-%"))
                )
            except ImportError:
                pass

            # Delete chutes
            try:
                from api.chute.schemas import Chute

                await session.execute(
                    delete(Chute).where(Chute.chute_id.like("test-chute-%"))
                )
            except ImportError:
                pass

            # Delete images
            await session.execute(
                delete(Image).where(Image.image_id.like("test-image-%"))
            )

            # Delete logos
            try:
                from api.logo.schemas import Logo

                await session.execute(
                    delete(Logo).where(Logo.logo_id.like("test-logo-%"))
                )
            except ImportError:
                pass

            # Delete users
            await session.execute(delete(User).where(User.user_id.like("test-user-%")))

            await session.commit()
            print("Test data cleanup completed!")

        except Exception as e:
            await session.rollback()
            print(f"Error during cleanup: {e}")
            raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Database operations for integration tests"
    )
    parser.add_argument("--cleanup", action="store_true", help="Cleanup test data only")
    parser.add_argument(
        "--create", action="store_true", help="Create schema and test data"
    )
    parser.add_argument(
        "--recreate", action="store_true", help="Drop, create, and populate database"
    )

    args = parser.parse_args()

    if args.cleanup:
        # Just cleanup
        asyncio.run(cleanup_test_data(engine))
    elif args.recreate:
        parser.error(
            "--recreate cannot safely infer a disposable database boundary; recreate the "
            "explicit test database externally, then run --create"
        )
    elif args.create or len(sys.argv) == 1:
        asyncio.run(create_test_database())
    else:
        parser.print_help()
