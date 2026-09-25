import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from task1 import main as run_task1
from task2 import main as run_task2
from task3 import main as run_task3


def main():
    print("\n" + "=" * 70)
    print("      ЗАПУСК ЛАБОРАТОРНОЇ РОБОТИ №1 (УСІ ЗАВДАННЯ)")
    print("=" * 70 + "\n")

    print("\n>>> ЗАПУСК ЗАВДАННЯ 1 <<<\n")
    try:
        run_task1()
    except Exception as e:
        print(f"[ПОМИЛКА під час виконання Завдання 1]: {e}")

    print("\n" + "-" * 70)
    print("\n>>> ЗАПУСК ЗАВДАННЯ 2 <<<\n")
    try:
        run_task2()
    except Exception as e:
        print(f"[ПОМИЛКА під час виконання Завдання 2]: {e}")

    print("\n" + "-" * 70)
    print("\n>>> ЗАПУСК ЗАВДАННЯ 3 <<<\n")
    try:
        run_task3()
    except Exception as e:
        print(f"[ПОМИЛКА під час виконання Завдання 3]: {e}")

    print("\n" + "=" * 70)
    print("      УСІ ЗАВДАННЯ УСПІШНО ВИКОНАНО")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()