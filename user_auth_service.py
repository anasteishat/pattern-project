import json
from abc import ABC, abstractmethod

MAX_FAILED_ATTEMPTS = 3
USER_FILE = 'users.json'

# ===== Strategy: Authentication Methods =====
class AuthStrategy(ABC):
    @abstractmethod
    def authenticate(self, user, data):
        pass

class PasswordAuth(AuthStrategy):
    def authenticate(self, user, data):
        return user.password == data.get('password')

class OAuthAuth(AuthStrategy):
    def authenticate(self, user, data):
        return data.get('oauth_token') == 'VALID_TOKEN'

# ===== Factory Method: Users =====
class User(ABC):
    def __init__(self, username, password, roles=None, secret_question=None, secret_answer=None,
                 failed_attempts=0, blocked=False):
        self.username = username
        self.password = password
        self.roles = roles or ['user']
        self.secret_question = secret_question
        self.secret_answer = secret_answer
        self.failed_attempts = failed_attempts
        self.blocked = blocked

    def __str__(self):
        status = ' (BLOCKED)' if self.blocked else ''
        roles_str = ', '.join(self.roles)
        return f'User: {self.username} [{roles_str}]{status}'
    
    def has_role(self, role):
        return role in self.roles
    
    def to_dict(self):
        return {
            'username': self.username,
            'password': self.password,
            'roles': self.roles,
            'secret_question': self.secret_question,
            'secret_answer': self.secret_answer,
            'failed_attempts': self.failed_attempts,
            'blocked': self.blocked
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['username'], d['password'], d.get('roles', ['user']),
            d.get('secret_question'), d.get('secret_answer'),
            d.get('failed_attempts', 0), d.get('blocked', False)
        )

class Admin(User):
    def __init__(self, username, password, secret_question=None, secret_answer=None,
                 failed_attempts=0, blocked=False):
        super().__init__(username, password, ['admin', 'user'], secret_question, secret_answer, failed_attempts, blocked)

    def __str__(self):
        status = ' (BLOCKED)' if self.blocked else ''
        return f'Admin: {self.username} [{", ".join(self.roles)}]{status}'

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['username'],
            d['password'],
            d.get('secret_question'),
            d.get('secret_answer'),
            d.get('failed_attempts', 0),
            d.get('blocked', False)
        )
    
class UserFactory:
    @staticmethod
    def create_user(user_type, username, password, secret_question, secret_answer):
        if user_type == "admin":
            return Admin(username, password, secret_question, secret_answer)
        return UserImpl(username, password, secret_question, secret_answer)

class UserImpl(User):
    def __init__(self, username, password, secret_question=None, secret_answer=None,
                 failed_attempts=0, blocked=False):
        super().__init__(username, password, ['user'], secret_question, secret_answer, failed_attempts, blocked)

    def __str__(self):
        status = ' (BLOCKED)' if self.blocked else ''
        return f'Regular User: {self.username} [{", ".join(self.roles)}]{status}'

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['username'],
            d['password'],
            d.get('secret_question'),
            d.get('secret_answer'),
            d.get('failed_attempts', 0),
            d.get('blocked', False)
        )
    
# ===== Singleton: User Session =====
class Session:
    __instance = None

    def __init__(self):
        if Session.__instance:
            raise Exception("Session is singleton!")
        self.current_user = None

    @staticmethod
    def get_instance():
        if not Session.__instance:
            Session.__instance = Session()
        return Session.__instance

    def login(self, user):
        self.current_user = user

    def logout(self):
        self.current_user = None

    def get_user(self):
        return self.current_user

# ===== User Manager (SOLID: Single Responsibility) =====
class UserManager:
    def __init__(self, filename=USER_FILE):
        self.filename = filename
        self.users = {}
        self.load_users()

    def register(self, user_type, username, password, secret_question, secret_answer):
        if username in self.users:
            raise Exception("Username already exists!")
        user = UserFactory.create_user(user_type, username, password, secret_question, secret_answer)
        self.users[username] = user
        self.save_users()
        return user

    def get_user(self, username):
        return self.users.get(username)
    
    def load_users(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for u in data:
                    if 'admin' in u.get('roles', []):
                        user = Admin.from_dict(u)
                    else:
                        user = UserImpl.from_dict(u)
                    self.users[user.username] = user
        except FileNotFoundError:
            # Default admin
            admin = Admin('admin', 'adminpass', 'First pet name?', 'admin')
            self.users['admin'] = admin
            self.save_users()

    def save_users(self):
        to_save = [user.to_dict() for user in self.users.values()]
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(to_save, f, indent=4)

    def add_role(self, username, role):
        user = self.get_user(username)
        if user and role not in user.roles:
            user.roles.append(role)
            self.save_users()
            return True
        return False
    
    def reset_failed_attempts(self, username):
        user = self.get_user(username)
        if user:
            user.failed_attempts = 0
            user.blocked = False
            self.save_users()

    def set_new_password(self, username, new_password):
        user = self.get_user(username)
        if user:
            user.password = new_password
            self.save_users()
            return True
        return False

# ======= Console UI =======
def main():
    user_manager = UserManager()
    session = Session.get_instance()

    print("Welcome to the Authentication System!")
    print("Available commands: [register], [login], [logout], [whoami], [addrole], [restricted], [exit]")
    while True:
        action = input("> ").strip().lower()
        if action == "register":
            utype = input("Type (user/admin): ").strip().lower()
            uname = input("Username: ")
            upass = input("Password: ")
            sq = input("Set your secret question (e.g. Your pet's name?): ")
            sa = input("Set your secret answer: ").strip().lower()
            try:
                user_manager.register(utype, uname, upass, sq, sa)
                print("User created successfully.")
            except Exception as ex:
                print("Error:", ex)
        elif action == "login":
            uname = input("Username: ")
            method = input("Authentication method (password/oauth): ").strip().lower()
            user = user_manager.get_user(uname)
            if not user:
                print("User not found.")
                continue
            if user.blocked:
                print("Account is blocked due to too many failed login attempts. Please reset your password.")
                continue

            if method == "password":
                upass = input("Password: ")
                strategy = PasswordAuth()
                data = {'password': upass}
            elif method == "oauth":
                token = input("Enter OAuth token (VALID_TOKEN): ")
                strategy = OAuthAuth()
                data = {'oauth_token': token}
            else:
                print("Unknown authentication method.")
                continue

            if strategy.authenticate(user, data):
                session.login(user)
                print(f"Login successful! Welcome, {user}")
                user.failed_attempts = 0
                user_manager.save_users()
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.blocked = True
                    print("Too many failed attempts. Account is now BLOCKED!")
                else:
                    print(f"Invalid login data. Attempts left: {MAX_FAILED_ATTEMPTS - user.failed_attempts}")
                user_manager.save_users()
        elif action == "logout":
            session.logout()
            print("You have been logged out.")
        elif action == "whoami":
            user = session.get_user()
            if user:
                print(f"Logged in as: {user}")
            else:
                print("You are not logged in.")
        elif action == "addrole":
            current = session.get_user()
            if not current or not current.has_role('admin'):
                print("Only admin can assign roles.")
                continue
            target = input("Enter username to modify: ")
            role = input("Enter role to add: ").strip().lower()
            if user_manager.add_role(target, role):
                print(f"Role '{role}' added to {target}.")
            else:
                print("Failed to add role (user not found or role exists).")
        elif action == "reset_password":
            uname = input("Username: ")
            user = user_manager.get_user(uname)
            if not user:
                print("User not found.")
                continue
            print(f"Secret question: {user.secret_question}")
            answer = input("Answer: ").strip().lower()
            if answer == (user.secret_answer or '').strip().lower():
                new_password = input("Enter new password: ")
                user_manager.set_new_password(uname, new_password)
                user_manager.reset_failed_attempts(uname)
                print("Password reset successfully. You can now login.")
            else:
                print("Incorrect answer. Password not reset.")
        elif action == "exit":
            print("Goodbye!")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()