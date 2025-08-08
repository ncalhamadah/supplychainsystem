import os
from app import create_app, db, seed_data, create_admin
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

app = create_app()

if __name__ == "__main__":
    # Simple CLI usage:
    #   python manage.py initdb
    #   python manage.py seed
    #   python manage.py create-admin
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else None
    with app.app_context():
        if cmd == "initdb":
            db.create_all()
            print("Database initialized.")
        elif cmd == "seed":
            seed_data()
            print("Seed data inserted.")
        elif cmd == "create-admin":
            create_admin()
            print("Admin ensured/updated.")
        else:
            print("Usage: python manage.py [initdb|seed|create-admin]")
