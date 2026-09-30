import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings:
    # Project metadata
    PROJECT_NAME: str = "VaultDB"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Cryptographically Immutable Database Middleware with PostgreSQL & immudb"

    # PostgreSQL Configuration
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "127.0.0.1")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "postgres")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "vault_user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "vault123")
    POSTGRES_ADMIN_USER: str = os.getenv("POSTGRES_ADMIN_USER", "postgres")
    POSTGRES_ADMIN_PASSWORD: str = os.getenv("POSTGRES_ADMIN_PASSWORD", "nimit8222")
    POSTGRES_POOL_MIN: int = int(os.getenv("POSTGRES_POOL_MIN", "2"))
    POSTGRES_POOL_MAX: int = int(os.getenv("POSTGRES_POOL_MAX", "10"))

    # immudb Configuration
    IMMUDB_HOST: str = os.getenv("IMMUDB_HOST", "127.0.0.1")
    IMMUDB_PORT: int = int(os.getenv("IMMUDB_PORT", "3322"))
    IMMUDB_USER: str = os.getenv("IMMUDB_USER", "immudb")
    IMMUDB_PASSWORD: str = os.getenv("IMMUDB_PASSWORD", "immudb")
    IMMUDB_DATABASE: str = os.getenv("IMMUDB_DATABASE", "defaultdb")

    # API / Server Configuration
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

    @property
    def postgres_conninfo(self) -> str:
        return f"host={self.POSTGRES_HOST} port={self.POSTGRES_PORT} dbname={self.POSTGRES_DB} user={self.POSTGRES_USER} password={self.POSTGRES_PASSWORD}"

    @property
    def postgres_admin_conninfo(self) -> str:
        return f"host={self.POSTGRES_HOST} port={self.POSTGRES_PORT} dbname={self.POSTGRES_DB} user={self.POSTGRES_ADMIN_USER} password={self.POSTGRES_ADMIN_PASSWORD}"

    @property
    def immudb_address(self) -> str:
        return f"{self.IMMUDB_HOST}:{self.IMMUDB_PORT}"

settings = Settings()
