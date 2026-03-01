import sqlite3
import bcrypt

# 1. Database Setup
def setup_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 2. Register User
def register_user(username, password):
    # Hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed))
        conn.commit()
        print(f"User '{username}' registered successfully!")
    except sqlite3.IntegrityError:
        print("Error: Username already exists.")
    finally:
        conn.close()

# 3. Verify Login
def login_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_hash = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            print("Login successful!")
            return True
    print("Invalid username or password.")
    return False

# --- Main Logic ---
setup_database()

# Example usage:
action = input("Type 'register' or 'login': ").lower()
user = input("Username: ")
pwd = input("Password: ")

if action == 'register':
    register_user(user, pwd)
elif action == 'login':
    login_user(user, pwd)