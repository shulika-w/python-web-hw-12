import configparser
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    AsyncEngine,
    async_sessionmaker,
)

current_file_path = Path(__file__).resolve()
project_dir = current_file_path.parents[2]
config_path = Path.joinpath(project_dir, "config.ini")

config = configparser.ConfigParser()
config.read(config_path)

driver_sync = config.get("DB", "driver_sync")
driver_async = config.get("DB", "driver_async")
user = config.get("DB", "user")
password = config.get("DB", "password")
host = config.get("DB", "host")
port = config.get("DB", "port")
dbname = config.get("DB", "dbname")

url = f"{driver_sync}://{user}:{password}@{host}:{port}/{dbname}"

engine: AsyncEngine = create_async_engine(
    f"{driver_sync}+{driver_async}://{user}:{password}@{host}:{port}/{dbname}",
    echo=False,
)
AsyncDBSession = async_sessionmaker(
    engine, autoflush=False, expire_on_commit=False, class_=AsyncSession
)


# Dependency
async def get_session():
    session = AsyncDBSession()
    try:
        yield session
    finally:
        await session.close()
