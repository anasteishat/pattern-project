import json
from abc import ABC, abstractmethod

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
    def __init__(self, username, password, roles=None):
        self.username = username
        self.password = password
        self.roles = roles or ['user']

    def __str__(self):
        roles_str = ', '.join(self.roles)
        return f'User: {self.username} [{roles_str}]'
    
    def has_role(self, role):
        return role in self.roles

class Admin(User):
    def __init__(self, username, password):
        super().__init__(username, password, roles=['admin', 'user'])

    def __str__(self):
        return f'Admin: {self.username} [{", ".join(self.roles)}]'

class UserFactory:
    @staticmethod
    def create_user(user_type, username, password):
        if user_type == "admin":
            return Admin(username, password)
        return UserImpl(username, password)

class UserImpl(User):
    def __init__(self, username, password):
        super().__init__(username, password, roles=['user'])

    def __str__(self):
        return f'Regular User: {self.username} [{", ".join(self.roles)}]'

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
    def __init__(self, filename='users.json'):
        self.filename = filename
        self.users = {}
        self.load_users()

    def register(self, user_type, username, password):
        if username in self.users:
            raise Exception("Username already exists!")
        user = UserFactory.create_user(user_type, username, password)
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
                    roles = u.get('roles', ['user'])
                    # Restore correct class based on roles
                    if 'admin' in roles:
                        user = Admin(u['username'], u['password'])
                    else:
                        user = UserImpl(u['username'], u['password'])
                    user.roles = roles
                    self.users[u['username']] = user
        except FileNotFoundError:
            # On first run - create default admin
            default_admin = Admin('admin', 'adminpass')
            self.users['admin'] = default_admin
            self.save_users()

    def save_users(self):
        to_save = []
        for user in self.users.values():
            to_save.append({
                'username': user.username,
                'password': user.password,
                'roles': user.roles
            })
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(to_save, f, indent=4)

    def add_role(self, username, role):
        user = self.get_user(username)
        if user and role not in user.roles:
            user.roles.append(role)
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
            try:
                user_manager.register(utype, uname, upass)
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
            else:
                print("Invalid login data.")
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
        elif action == "restricted":
            user = session.get_user()
            if user and user.has_role('admin'):
                print("Admin-only command executed!")
            else:
                print("You don't have permission for this action.")
        elif action == "exit":
            print("Goodbye!")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()