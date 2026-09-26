"""
seed_users.py — Create one demo user for every role in SecureChain DMS.
Run once: python seed_users.py
"""
import psycopg2
import uuid
import bcrypt

def hash_pwd(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
conn = psycopg2.connect("postgresql://postgres.buvjudpqfzscxoeqwnay:Securechaindms%40123@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres")
cur  = conn.cursor()

# Fetch all role IDs
cur.execute("SELECT id, name FROM roles")
roles = {name: rid for rid, name in cur.fetchall()}

users = [
    # --- POLICE PILLAR ---
    {
        "role":        "INVESTIGATING_OFFICER",
        "name":        "Suresh Kumar",
        "employee_id": "DL-IO-001",
        "password":    "IO@SecureChain1",
        "jurisdiction":"South Delhi",
        "email":       "suresh.kumar@police.gov.in",
    },
    {
        "role":        "STATION_HOUSE_OFFICER",
        "name":        "Ravi Sharma",
        "employee_id": "DL-SHO-001",
        "password":    "SHO@SecureChain1",
        "jurisdiction":"South Delhi",
        "email":       "ravi.sharma@police.gov.in",
    },
    {
        "role":        "SENIOR_POLICE_OFFICER",
        "name":        "Anil Singh",
        "employee_id": "DL-SPO-001",
        "password":    "SPO@SecureChain1",
        "jurisdiction":"South Delhi",
        "email":       "anil.singh@police.gov.in",
    },
    # --- FORENSIC PILLAR ---
    {
        "role":        "FORENSIC_EXPERT",
        "name":        "Dr. Priya Mehta",
        "employee_id": "DL-FE-001",
        "password":    "FSL@SecureChain1",
        "jurisdiction":"South Delhi FSL",
        "email":       "priya.mehta@fsl.gov.in",
    },
    {
        "role":        "FORENSIC_LAB_HEAD",
        "name":        "Dr. Rajesh Patel",
        "employee_id": "DL-FLH-001",
        "password":    "FLH@SecureChain1",
        "jurisdiction":"South Delhi FSL",
        "email":       "rajesh.patel@fsl.gov.in",
    },
    {
        "role":        "FORENSIC_AUDITOR",
        "name":        "Neha Gupta",
        "employee_id": "DL-FA-001",
        "password":    "FA@SecureChain1",
        "jurisdiction":"South Delhi FSL",
        "email":       "neha.gupta@fsl.gov.in",
    },
    # --- JUDICIARY PILLAR ---
    {
        "role":        "MAGISTRATE",
        "name":        "Hon. P.K. Verma",
        "employee_id": "DL-MAG-001",
        "password":    "MAG@SecureChain1",
        "jurisdiction":"Delhi District Court",
        "email":       "pk.verma@courts.gov.in",
    },
    {
        "role":        "JUDGE",
        "name":        "Hon. Justice A.K. Bose",
        "employee_id": "DL-JDG-001",
        "password":    "JDG@SecureChain1",
        "jurisdiction":"Delhi High Court",
        "email":       "ak.bose@courts.gov.in",
    },
    {
        "role":        "PUBLIC_PROSECUTOR",
        "name":        "Advocate Sanjay Rao",
        "employee_id": "DL-PP-001",
        "password":    "PP@SecureChain1",
        "jurisdiction":"Delhi District Court",
        "email":       "sanjay.rao@prosecution.gov.in",
    },
    {
        "role":        "COURT_REGISTRAR",
        "name":        "Meera Joshi",
        "employee_id": "DL-CR-001",
        "password":    "CR@SecureChain1",
        "jurisdiction":"Delhi District Court",
        "email":       "meera.joshi@courts.gov.in",
    },
    # --- ADMIN PILLAR ---
    {
        "role":        "SYSTEM_ADMIN",
        "name":        "System Administrator",
        "employee_id": "SYS-ADMIN-001",
        "password":    "Admin@SecureChain1",
        "jurisdiction":"National",
        "email":       "admin@securechain.gov.in",
    },
    {
        "role":        "AUDITOR",
        "name":        "Compliance Auditor",
        "employee_id": "SYS-AUD-001",
        "password":    "Audit@SecureChain1",
        "jurisdiction":"National",
        "email":       "auditor@securechain.gov.in",
    },
    {
        "role":        "SUPER_ADMIN",
        "name":        "Super Administrator",
        "employee_id": "SYS-SUPER-001",
        "password":    "Super@SecureChain1",
        "jurisdiction":"National",
        "email":       "super@securechain.gov.in",
    },
]

print("\n======================================================")
print("  SecureChain DMS — Seeding Demo Users")
print("======================================================")

for u in users:
    uid  = str(uuid.uuid4())
    hash = hash_pwd(u["password"])
    rid  = roles[u["role"]]
    try:
        cur.execute("""
            INSERT INTO users
              (id, full_name, employee_id, email, password_hash, role_id, jurisdiction, is_active, failed_logins)
            VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, 0)
            ON CONFLICT (employee_id) DO UPDATE SET password_hash = EXCLUDED.password_hash
        """, (uid, u["name"], u["employee_id"], u["email"], hash, rid, u["jurisdiction"]))
        conn.commit()
        print(f"[OK] {u['role']:<30} | ID: {u['employee_id']:<18} | Pass: {u['password']}")
    except Exception as e:
        conn.rollback()
        print(f"[ERR] {u['role']} -> {e}")

conn.commit()
conn.close()
print("======================================================")
print("  All users created successfully!")
print("======================================================\n")
