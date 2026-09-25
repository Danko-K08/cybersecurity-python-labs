import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "APT@Detect10n", "simple", "Red@Team2023", "participant",
    "Blue@T3am", "common123", "Purple@T34m", "regular123", 
    "Gr33n@Team", "normal123"
]

criteria = {
    "min_length": 7, 
    "require_digits": True, 
    "require_upper": True, 
    "require_special": True
}

forbidden_passwords = {
    "simple", "participant", "common123", 
    "regular123", "normal123", "test"
}


def evaluate_password(password: str, all_passwords: list, criterias: dict, forbidden: set) -> str:
    if password in forbidden or len(password) < criterias["min_length"]:
        return "Заборонений"

    active_requirements = []
    
    if criterias.get("require_digits", False):
        active_requirements.append(any(char.isdigit() for char in password))
        
    if criterias.get("require_upper", False):
        active_requirements.append(any(char.isupper() for char in password))
        
    if criterias.get("require_special", False):
        active_requirements.append(any(char in string.punctuation for char in password))

    met_count = sum(active_requirements)
    total_required = len(active_requirements)

    if met_count == 1 and total_required > 1:
        return "Слабкий"

    all_criteria_met = (met_count == total_required) if total_required > 0 else True
    is_unique = all_passwords.count(password) == 1

    if all_criteria_met and len(password) >= criterias["min_length"] + 4 and is_unique:
        return "Дуже сильний"
    
    if all_criteria_met:
        return "Сильний"

    return "Середній"

print(f"{'№':<4} | {'Пароль':<20} | {'Довжина':<8} | {'Оцінка надійності'}")
print("-" * 55)

for idx, haslo in enumerate(passwords, start=1):
    status = evaluate_password(haslo, passwords, criteria, forbidden_passwords)
    print(f"{idx:<4} | {haslo:<20} | {len(haslo):<8} | {status}")
def main():
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")
    print("Лабораторна робота No1 — Завдання 1\n")

    for _ in range(3):
        random_index = random.randrange(len(passwords))
        passwords.append(passwords[random_index])

    print(f"{'№':<4} | {'Пароль':<20} | {'Довжина':<8} | {'Оцінка надійності'}")
    print("-" * 55)

    for idx, haslo in enumerate(passwords, start=1):
        status = evaluate_password(haslo, passwords, criteria, forbidden_passwords)
        print(f"{idx:<4} | {haslo:<20} | {len(haslo):<8} | {status}")


if __name__ == "__main__":
    main()