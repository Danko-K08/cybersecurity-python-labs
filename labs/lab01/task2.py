import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

users = {
    "risk_manager": {"role": "risk_analyst", "clearance": 4, "department": "Risk Management", "active": True},
    "business_analyst": {"role": "business_analyst", "clearance": 2, "department": "Business", "active": True},
    "legal_counsel": {"role": "legal", "clearance": 3, "department": "Legal", "active": True},
    "contractor_dev": {"role": "contractor", "clearance": 2, "department": "Contract", "active": True},
    "obsolete_system": {"role": "legacy_system", "clearance": 1, "department": "Legacy", "active": False}
}

resources = [
    ("risk_registers", 4), 
    ("business_requirements", 2),
    ("legal_documents", 3), 
    ("contract_code", 2), 
    ("governance_framework", 4),
    ("meeting_minutes", 1), 
    ("regulatory_reports", 3), 
    ("executive_dashboards", 4),
    ("project_specs", 2), 
    ("public_statements", 1)
]

security_levels = ("Public", "Internal Use", "Restricted", "Highly Restricted")

blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}

all_test_users = list(users.keys()) + ["contract_expired", "unknown_user"]

print("Лабораторна робота No1 — Завдання 2")
print("=" * 60)
print("СПИСОК РЕСУРСІВ СИСТЕМИ")
print("=" * 60)

for res_name, level_code in resources:
    text_level = security_levels[level_code - 1]
    print("Ресурс:", res_name, " " * (22 - len(res_name)), "| Рівень безпеки:", text_level)

print("\n" + "=" * 60)
print("РЕЗУЛЬТАТИ ПЕРЕВІРКИ ДОСТУПУ")
print("=" * 60)

def check_access(username: str, resource_name: str, resource_level: int) -> str:
    if username not in users:
        return "DENY (User not found)"
    
    if username in blocked_users:
        return "DENY (User is blocked)"
    
    user_info = users[username]
    
    if not user_info.get("active", False):
        return "DENY (Account inactive)"
    
    user_clearance = user_info.get("clearance", 0)
    
    if user_clearance >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"

for username in all_test_users:
    for res_name, res_level in resources:
        result = check_access(username, res_name, res_level)
        print("user=" + username + " resource=" + res_name + " -> " + result)