import sys
import uvicorn
from backend.database import init_db
from seed_demo import seed_demo_data

def main():
    print("=" * 65)
    print("[+] Automated SQL Injection Detection and Prevention System")
    print("=" * 65)
    print("[+] Initializing SQLite database...")
    init_db()

    # Automatically populate initial demo data if database is empty
    seed_demo_data()

    print("[+] Starting Uvicorn Web Server (100% Local Execution)...")
    print("    URL: http://127.0.0.1:8000")
    print("=" * 65)

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )

if __name__ == "__main__":
    main()
