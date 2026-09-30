"""
VaultDB Application Server
Entrypoint to serve the FastAPI web API and Dashboard UI.
"""

import uvicorn
from config.settings import settings
from src.vault_db.api.app import app

def main():
    print("=" * 65)
    print(f" VaultDB Dashboard running at http://localhost:{settings.APP_PORT}")
    print(f" Interactive Swagger API Docs at http://localhost:{settings.APP_PORT}/docs")
    print("=" * 65)

    uvicorn.run(
        app,
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        log_level="info"
    )

if __name__ == "__main__":
    main()
