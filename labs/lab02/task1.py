import re
import os
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

class User:
    def __init__(self, username: str, email: str, role: str = "user", active: bool = True):
        self.username = username
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""
        self.email = email  # Викличе setter з валідацією

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value: str):
        # Локальна частина 3-64 символи, починається з літери, домен з крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError("Неправильний формат email")
        self._email = value

    def set_password(self, password: str):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), self.__password_salt, 100000)

    def check_password(self, password: str) -> bool:
        if not self.__password_salt:
            return False
        test_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), self.__password_salt, 100000)
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return f"User({self.username}, role={self.role}, active={self.active})"

class Admin(User):
    def __init__(self, username: str, email: str, active: bool = True):
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self):
        return f"Admin({self.username}, active={self.active}, permissions={self.permissions})"

class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            return False
        return (datetime.now(timezone.utc) - self.last_activity) <= timedelta(seconds=timeout_sec)

@dataclass
class LogEntry:
    time_utc: datetime
    username: str
    action: str

class AuditLog:
    def __init__(self):
        self.logs: list[LogEntry] = []

    def add_log(self, username: str, action: str):
        self.logs.append(LogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self):
        for log in self.logs:
            print(f"[{log.time_utc.isoformat()}] {log.username} - {log.action}")

class UserAccount:
    SESSION_TIMEOUT_SEC = 900

    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session = None
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure: inactive")
            return False
        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        self.audit_log.add_log(self.user.username, "login_failure: wrong password")
        return False

    def is_authenticated(self) -> bool:
        if self.session and self.session.is_active(self.SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        return False

    def logout(self):
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key == "user": return self.user
        if key == "session": return self.session
        if key == "audit_log": return self.audit_log
        raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key, value):
        if key == "user" and isinstance(value, User): self.user = value
        elif key == "session" and isinstance(value, Session): self.session = value
        elif key == "audit_log" and isinstance(value, AuditLog): self.audit_log = value
        else:
            raise TypeError("Неправильний тип значення або заборонений ключ")