import argparse
from labs.lab02.task1 import User, Admin, UserAccount
from labs.lab02.task2 import analyze_arp

def run_demo():
    print("--- Демонстрація Завдання 1 ---")
    admin = Admin("root_admin", "admin@company.com")
    admin.set_password("SecureP@ss123")
    admin.grant_permission("sudo")

    account = UserAccount(admin)
    print(f"Спроба входу з неправильним паролем: {account.login('wrong', '192.168.1.10')}")
    print(f"Успішний вхід: {account.login('SecureP@ss123', '192.168.1.10')}")
    print(f"Перевірка аутентифікації: {account.is_authenticated()}")
    
    print(f"Дозволи адміністратора: {account['user'].permissions}")
    account.logout()
    print("\nЖурнал аудиту:")
    account['audit_log'].show_all()

def main():
    parser = argparse.ArgumentParser(description="Кібербезпекові утиліти (ЛР №2)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Демонстрація ООП-моделей користувачів")

    analyze_parser = subparsers.add_parser("analyze", help="Аудит ARP-таблиць")
    analyze_parser.add_argument("--arp-file", required=True, help="Шлях до файлу ARP-таблиці")
    analyze_parser.add_argument("--output-json", help="Шлях для збереження JSON-звіту")
    analyze_parser.add_argument("--detect-spoofing", action="store_true", help="Увімкнути перевірку ARP-Spoofing")
    analyze_parser.add_argument("--log-file", help="Шлях до лог-файлу")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_arp(args.arp_file, args.output_json, args.detect_spoofing, args.log_file)

if __name__ == "__main__":
    main()