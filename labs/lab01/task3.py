import sys
import os
import csv
import json
import secrets
import hashlib
from datetime import datetime
from functools import wraps

# Додаємо кореневу папку проєкту до sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


# Спеціальне виключення для перевірки валідації
class ValidationError(Exception):
    pass


# Визначення шляхів до файлів та папок
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

# Крок 3 (Завдання 3): Автоматичне створення папки data
os.makedirs(DATA_DIR, exist_ok=True)


# Допоміжна функція хешування за допомогою blake2b
def hash_password_blake2b(password: str, salt: str) -> str:
    """Хешує пароль із сіллю за допомогою алгоритму hashlib.blake2b."""
    # Перетворюємо пароль та сіль у байти (utf-8)
    data = (password + salt).encode('utf-8')
    # Використовуємо blake2b
    hasher = hashlib.blake2b(data)
    return hasher.hexdigest()


# Створення початкової бази даних CSV (якщо файл ще не існує)
def init_db():
    if not os.path.exists(CSV_PATH):
        initial_users = [
            ("admin", "AdminSecret12!"),
            ("risk_manager", "RiskPass2026!"),
            ("developer", "DevCode321#")
        ]
        
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "salt", "password_hash"])
            
            for username, pwd in initial_users:
                # Генеруємо 16 байт солі в hex-форматі
                salt = secrets.token_hex(16)
                pwd_hash = hash_password_blake2b(pwd, salt)
                writer.writerow([username, salt, pwd_hash])


# Крок 6: Декоратор для логування подій авторизації у JSON
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
                
            # Зчитуємо існуючий лог або створюємо новий список
            logs = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []
            
            logs.append(log_entry)
            
            with open(LOG_PATH, mode="w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)
                
    return wrapper


# Крок 4: Читання бази даних
def read_users_db() -> list:
    users_db = []
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            users_db.append(row)
    return users_db


def display_users_table(users_db: list):
    print("=" * 65)
    print("БАЗА ДАНИХ КОРИСТУВАЧІВ (users.csv)")
    print("=" * 65)
    print("Username             | Salt                             | Password Hash (BLAKE2b)")
    print("-" * 65)
    for u in users_db:
        uname = u["username"]
        salt = u["salt"][:10] + "..."  # скорочуємо для кращого вигляду
        phash = u["password_hash"][:15] + "..."
        print(uname, " " * (20 - len(uname)), "|", salt, " " * (32 - len(salt)), "|", phash)
    print("=" * 65 + "\n")


# Крок 5: Функція автентифікації
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми!")
        
    # Встановлюємо жорстку вимогу до довжини пароля (12 символів)
    if len(password) < 12:
        raise ValidationError("Пароль повинен містити щонайменше 12 символів!")
        
    users_db = read_users_db()
    
    for user_row in users_db:
        if user_row["username"] == username:
            salt = user_row["salt"]
            expected_hash = user_row["password_hash"]
            computed_hash = hash_password_blake2b(password, salt)
            
            if computed_hash == expected_hash:
                return True
            else:
                return False
                
    return False


# Крок 7 та 8: Головна функція з обробкою винятків
def main():
    try:
        print("Лабораторна робота No1 — Завдання 3")
        print("Студент:", STUDENT_NAME, "| Група:", GROUP_NAME, "| Варіант:", VARIANT_NUMBER, "\n")
        
        # Ініціалізація баз даних
        init_db()
        
        # Читання та відображення таблиці користувачів
        db_content = read_users_db()
        display_users_table(db_content)
        
        # Тестування автентифікації
        print("Спроби входу в систему:\n")
        
        # 1. Успішний вхід (пароль 12+ символів)
        try:
            res1 = login("admin", "AdminSecret12!")
            print("Спроба 1 [admin]:", "УСПІШНО" if res1 else "ПОМИЛКА ПАРОЛЯ")
        except Exception as e:
            print("Спроба 1 Помилка:", e)
            
        # 2. Неправильний пароль
        try:
            res2 = login("admin", "WrongPass1234")
            print("Спроба 2 [admin]:", "УСПІШНО" if res2 else "НЕВІРНИЙ ПАРОЛЬ")
        except Exception as e:
            print("Спроба 2 Помилка:", e)

        # 3. Помилка валідації (пароль менше 12 символів)
        try:
            login("risk_manager", "short")
        except (ValidationError, ValueError) as e:
            print("Спроба 3 Перехоплено виняток валідації:", e)

        # 4. Порожні значення
        try:
            login("", "")
        except ValueError as e:
            print("Спроба 4 Перехоплено виняток порожніх полів:", e)
            
        print("\nУсі події авторизації успішно записані у файл:", LOG_PATH)

    except FileNotFoundError as e:
        print("[ПОМИЛКА] Файл не знайдено:", e)
    except PermissionError as e:
        print("[ПОМИЛКА] Відсутні права доступу до файлу:", e)
    except IOError as e:
        print("[ПОМИЛКА] Помилка вводу/виводу файлу:", e)
    except Exception as e:
        print("[НЕОЧІКУВАНА ПОМИЛКА]:", e)


if __name__ == "__main__":
    main()