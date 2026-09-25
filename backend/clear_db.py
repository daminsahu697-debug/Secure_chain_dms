import sys
import os
from sqlalchemy import text

sys.path.insert(0, r"c:\Users\Admin\Documents\clone\backend")

from app.db.session import SessionLocal
from app.db.seed_demo_users import seed_demo_users
from app.core.config import settings

def clear_and_seed():
    db = SessionLocal()
    try:
        # Tables to truncate
        tables = [
            "audit_logs",
            "tamper_alerts",
            "edit_requests",
            "document_versions",
            "documents",
            "cases",
            "users",
            "merkle_trees",
            "merkle_nodes"
        ]
        
        for table in tables:
            try:
                db.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
                print(f"Truncated {table}")
            except Exception as e:
                print(f"Could not truncate {table}: {e}")
                db.rollback()
                
        db.commit()
        
        print("Seeding demo users and case...")
        seed_demo_users(db)
        print("Database cleared and seeded successfully.")
    finally:
        db.close()

if __name__ == "__main__":
    clear_and_seed()
