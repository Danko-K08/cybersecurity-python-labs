import sys
import os
import csv
import json
import secrets
import hashlib
from datetime import datetime
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
MIN_PASS_LENGTH: int = 12

class ValidationError(Exception):
    pass


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

os.makedirs(DATA_DIR, exist_ok=True)

PERSONAL_SALT = str(VARIANT_NUMBER)

users_to_register = (
    ("admin", "AdminSecret12!"),
    ("risk_manager", "RiskPass2026!"),
    ("developer", "DevCode321#12"),
    ("analyst_user", "AnalystPass99!"),
    ("auditor_sec", "AuditSecure77#"),
    ("sec_officer", "OfficerPass55!"),
    ("net_admin", "NetAdminPass88!"),
    ("db_operator", "DatabasePass33#"),
    ("support_tech", "SupportTech11!"),
    ("guest_user", "GuestAccount00!")
)


def generate_hash(password: str, salt: str = PERSONAL_SALT) -> str:
    """Хешує пароль із сіллю за допомогою алгоритму hashlib.blake2b."""
    if not password:
        raise ValueError("Пароль не може бути порожнім!")
    if len(password) < MIN_PASS_LENGTH:
        raise ValidationError("Пароль занадто малий для хешування (менше 8 символів)!")

    data = (password + salt).encode('utf-8')
    hasher = hashlib.blake2b(data)
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Викликає generate_hash з персональною сіллю та повертає (username, hash_value)."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list: tuple):
    """Обробляє весь список користувачів та записує їх у файл users.csv."""
    try:
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            
            for uname, pwd in users_list:
                user_tuple = create_user(uname, pwd)
                writer.writerow(user_tuple)
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"[ПОМИЛКА create_users] Помилка роботи з файлом: {e}")
    except Exception as e:
        print(f"[НЕОЧІКУВАНА ПОМИЛКА create_users]: {e}")


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") if "username" in kwargs else (args[0] if args else "unknown")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        result_status = "failure"
        error_msg = None
        
        try:
            res = func(*args, **kwargs)
            if res:
                result_status = "success"
            return res
        except Exception as e:
            error_msg = str(e)
            raise e
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs
            }
            if error_msg:
                log_entry["error"] = error_msg
                
            logs = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []
            
            logs.append(log_entry)
            
            try:
                with open(LOG_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except IOError as e:
                print(f"[ПОМИЛКА log_event] Не вдалося записати лог: {e}")
                
    return wrapper


def read_users_db() -> list:
    users_db = []
    try:
        with open(CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                users_db.append(row)
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"[ПОМИЛКА read_users_db] Не вдалося прочитати файл бази даних: {e}")
    except Exception as e:
        print(f"[НЕОЧІКУВАНА ПОМИЛКА read_users_db]: {e}")
        
    return users_db


def display_users_table(users_db: list):
    try:
        print("=" * 65)
        print("БАЗА ДАНИХ КОРИСТУВАЧІВ (users.csv)")
        print("=" * 65)
        print("Username             | Password Hash (BLAKE2b)")
        print("-" * 65)
        for u in users_db:
            uname = u["username"]
            phash = u["password_hash"][:30] + "..."
            print(uname, " " * (20 - len(uname)), "|", phash)
        print("=" * 65 + "\n")
    except KeyError as e:
        print(f"[ПОМИЛКА display_users_table] Відсутнє необхідне поле в даних: {e}")
    except Exception as e:
        print(f"[НЕОЧІКУВАНА ПОМИЛКА display_users_table]: {e}")


@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username or not password:
            raise ValueError("Логін та пароль не можуть бути порожніми!")
            
        if len(password) < MIN_PASS_LENGTH:
            raise ValidationError("Пароль повинен містити щонайменше 12 символів!")
            
        users_db = read_users_db()
        
        for user_row in users_db:
            if user_row["username"] == username:
                expected_hash = user_row["password_hash"]
                computed_hash = generate_hash(password, PERSONAL_SALT)
                
                return computed_hash == expected_hash
                    
        return False

    except (ValidationError, ValueError) as e:
        print(f" Перехоплено виняток валідації: {e}")
        raise e
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"[ПОМИЛКА login] Помилка доступу до файлу: {e}")
        raise e
    except Exception as e:
        print(f"[НЕОЧІКУВАНА ПОМИЛКА login]: {e}")
        raise e


def main():
    print("Лабораторна робота No1 — Завдання 3")
    print("Студент:", STUDENT_NAME, "| Група:", GROUP_NAME, "| Варіант:", VARIANT_NUMBER, "\n")
    
    create_users(users_to_register)
    
    db_content = read_users_db()
    display_users_table(db_content)
    
    print("Спроби входу в систему:\n")
    
    # Спроба 1: Успішний вхід
    res1 = login("admin", "AdminSecret12!")
    print("Спроба 1 [admin]:", "УСПІШНО" if res1 else "ПОМИЛКА ПАРОЛЯ")
        
    # Спроба 2: Невірний пароль
    res2 = login("admin", "WrongPass1234")
    print("Спроба 2 [admin]:", "УСПІШНО" if res2 else "НЕВІРНИЙ ПАРОЛЬ")

    # Спроба 3: Занадто короткий пароль
    print("Спроба 3:")
    login("risk_manager", "short")
        
    # Спроба 4: Порожні поля
    print("Спроба 4:")
    login("", "")
        
    print("\nУсі події авторизації успішно записані у файл:", LOG_PATH)


if __name__ == "__main__":
    main()