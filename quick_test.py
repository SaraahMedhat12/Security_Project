# quick_test.py

from user_manager import setup_master_password, verify_master_password, load_users, save_users

password = input("Enter master password: ")

if not verify_master_password(password):
    setup_master_password(password)  # First-time setup
    print("Master password set. Run again.")

users, key = load_users(password)
print("Users loaded:", users)

# Example: add/update user
users["newuser"] = {"info": "test"}
save_users(users, key)
print("User data saved securely.")
