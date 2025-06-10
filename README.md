# pattern-project
This is a simple console-based user authentication system in Python.  
It supports registration, login, password reset, user roles (admin/user), and account lockout after multiple failed login attempts.  
User data is stored persistently in a `users.json` file.

## Design Patterns Used

This project demonstrates the application of classic design patterns and principles:

- **Factory Method** (GoF):  
  Used in `UserFactory` to create different user types (`Admin`, `UserImpl`) based on input.
- **Strategy** (GoF):  
  Used for authentication methods (`PasswordAuth`, `OAuthAuth`), enabling extensible login options.
- **Singleton** (GoF):  
  `Session` class ensures only one session instance manages the logged-in user.
- **SOLID Principles:**  
  Single Responsibility (separation of concerns: authentication, session, user management), Open/Closed (easy to extend auth/user types), Liskov Substitution, etc.
- **GRASP Patterns:**  
  Creator (UserManager creates and manages users), Controller (main() as command controller).