#pip install bcrypt
import bcrypt

def hash_password(password: str):
    # Generate a salt and hash the password
    # The 'rounds' parameter determines how slow the hash is (higher is safer)
    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(bytes_password, salt)
    return hashed

def check_password(password: str, hashed_password: bytes):
    # Compare the provided password with the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# --- Example Usage ---
user_input = "MySuperSecret123!"

# 1. Hashing
hashed_val = hash_password(user_input)
print(f"Hashed Password: {hashed_val.decode('utf-8')}")

# 2. Verifying
is_correct = check_password("MySuperSecret123!", hashed_val)
print(f"Password Match: {is_correct}")