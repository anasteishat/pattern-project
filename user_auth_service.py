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
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __str__(self):
        return f'User: {self.username}'

class Admin(User):
    def __str__(self):
        return f'Admin: {self.username}'

class UserFactory:
    @staticmethod
    def create_user(user_type, username, password):
        if user_type == "admin":
            return Admin(username, password)
        return UserImpl(username, password)

class UserImpl(User):
    def __str__(self):
        return f'Regular User: {self.username}'

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
    def __init__(self):
        self.users = {}

    def register(self, user_type, username, password):
        if username in self.users:
            raise Exception("Username already exists!")
        user = UserFactory.create_user(user_type, username, password)
        self.users[username] = user
        return user

    def get_user(self, username):
        return self.users.get(username)

# ======= Console UI =======
def main():
    user_manager = UserManager()
    session = Session.get_instance()

    user_manager.register('admin', 'admin', 'adminpass')
    user_manager.register('user', 'alice', 'alicepass')

    print("Welcome to the Authentication System!")
    print("Available commands: [register], [login], [logout], [whoami], [exit]")
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
        elif action == "exit":
            print("Goodbye!")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()