import socket
import os
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import crypto_utils
import json
import base64

HOST = '127.0.0.1'
PORT = 8000

session_token = None
username = None
derived_key = None
master_password = None
FILE_KEYS_PATH = "file_keys.json"

PINK = "#f8c8dc"
WHITE = "#ffffff"
FONT = ("Helvetica", 11)

def connect_to_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s

def show_auth_dialog(title):
    popup = tk.Toplevel()
    popup.title(title)
    popup.geometry("300x200")
    popup.configure(bg=PINK)
    popup.grab_set()

    tk.Label(popup, text="Username", bg=PINK, font=FONT).pack(pady=5)
    username_entry = tk.Entry(popup, font=FONT)
    username_entry.pack(pady=5)

    tk.Label(popup, text="Password", bg=PINK, font=FONT).pack(pady=5)
    password_entry = tk.Entry(popup, show="*", font=FONT)
    password_entry.pack(pady=5)

    result = {"username": None, "password": None}

    def submit():
        result["username"] = username_entry.get()
        result["password"] = password_entry.get()
        popup.destroy()

    tk.Button(popup, text="Submit", command=submit, bg=WHITE, font=FONT).pack(pady=10)
    popup.wait_window()
    return result["username"], result["password"]

def save_encrypted_file_key(filename, file_key, allowed_users):
    if os.path.exists(FILE_KEYS_PATH):
        with open(FILE_KEYS_PATH, "r") as f:
            file_keys = json.load(f)
    else:
        file_keys = {}

    encrypted_keys = {}
    for user in allowed_users:
        user_key = crypto_utils.get_user_derived_aes_key(user)
        encrypted_key = crypto_utils.encrypt_data(user_key, file_key)
        encrypted_keys[user] = base64.b64encode(encrypted_key).decode()

    file_keys[filename] = {"keys": encrypted_keys}

    with open(FILE_KEYS_PATH, "w") as f:
        json.dump(file_keys, f, indent=2)

def load_encrypted_file_key(filename, derived_key, username):
    if not os.path.exists(FILE_KEYS_PATH):
        raise ValueError("File key database not found.")
    with open(FILE_KEYS_PATH, "r") as f:
        file_keys = json.load(f)
    if filename not in file_keys or username not in file_keys[filename]["keys"]:
        raise ValueError(f"No key entry for user '{username}' and file '{filename}'")

    encrypted_key_b64 = file_keys[filename]["keys"][username]
    encrypted_key = base64.b64decode(encrypted_key_b64)
    return crypto_utils.decrypt_data(derived_key, encrypted_key)

def register():
    global username
    s = connect_to_server()
    s.sendall(b"REGISTER")
    s.recv(1024)
    u, p = show_auth_dialog("Register")
    if not u or not p:
        s.close()
        return
    username = u
    s.sendall(u.encode())
    s.recv(1024)
    s.sendall(p.encode())
    response = s.recv(1024).decode()
    s.close()
    messagebox.showinfo("Register", response)

def login():
    global session_token, username, derived_key, master_password

    if session_token:
        messagebox.showwarning("Already logged in", f"You're already logged in as {username}.")
        return

    s = connect_to_server()
    s.sendall(b"LOGIN")
    s.recv(1024)
    u, p = show_auth_dialog("Login")
    if not u or not p:
        s.close()
        return

    username = u
    s.sendall(u.encode())
    s.recv(1024)
    s.sendall(p.encode())
    response = s.recv(4096).decode()
    s.close()

    try:
        # ✅ Only change: decode base64 instead of hex
        with open("users.json", "r") as f:
            users = json.load(f)
        if username not in users:
            raise ValueError("User not found in users.json.")

        password_hash_b64 = users[username]["hashed_pw"]
        salt_b64 = users[username]["salt"]
        password_hash = base64.b64decode(password_hash_b64)
        salt = base64.b64decode(salt_b64)
        derived_key = crypto_utils.derive_aes_key_from_password_hash(password_hash, salt)

        print(f"[DEBUG] Login: username: {username}")
        print(f"[DEBUG] Derived encryption key (hex): {derived_key.hex()}")

    except Exception as e:
        messagebox.showerror("Key Derivation Error", str(e))
        return

    if "SESSION_TOKEN:" in response:
        session_token = response.split("SESSION_TOKEN:")[1].strip()
        os.makedirs(f"received_files_{username}", exist_ok=True)
        messagebox.showinfo("Login", f"🎉 Login successful!\n\nSession Token:\n{session_token}")
        status_label.config(text=f"Logged in as: {username}", fg="green")
    else:
        messagebox.showerror("Login Failed", response)

def list_files():
    if not session_token:
        messagebox.showerror("Not logged in", "Please login first.")
        return
    s = connect_to_server()
    s.sendall(f"LIST {session_token}".encode())
    response = s.recv(4096).decode()
    s.close()
    print(f"[DEBUG] Files listed from server: {response}")
    messagebox.showinfo("Files on Server", response)

def upload_file(server_ip, port, token, filepath, allowed_users):
    if derived_key is None:
        messagebox.showerror("Error", "Encryption key is missing. Please login first.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        raw_data = f.read()
    print(f"[DEBUG] Uploading file: {filename}")
    print(f"[DEBUG] Original file size: {len(raw_data)} bytes")

    file_key = os.urandom(32)
    save_encrypted_file_key(filename, file_key, allowed_users.split(","))
    print(f"[DEBUG] File key encrypted and saved for {filename}.")

    encrypted_data = crypto_utils.encrypt_data(file_key, raw_data)
    print(f"[DEBUG] Encrypted data size: {len(encrypted_data)} bytes")
    print("[DEBUG] File encryption completed successfully.")

    os.makedirs(f"shared_files_{username}", exist_ok=True)
    with open(os.path.join(f"shared_files_{username}", filename), 'wb') as f:
        f.write(raw_data)

    file_hash = crypto_utils.compute_file_hash(filepath)
    os.makedirs("hashes", exist_ok=True)
    hash_file_path = os.path.join("hashes", filename + ".hash")
    with open(hash_file_path, 'w') as f:
        f.write(file_hash)
    print(f"[DEBUG] Hash saved at: {hash_file_path}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))
        sock.sendall(f"UPLOAD {token} {filename}\n".encode())

        response = sock.recv(1024).decode()
        if "Enter usernames" in response:
            sock.sendall(f"{allowed_users}\n".encode())
            print(f"[DEBUG] Allowed users sent to server: {allowed_users}")

        ready = sock.recv(1024).decode()
        if "READY" in ready:
            sock.sendall(encrypted_data)
            sock.shutdown(socket.SHUT_WR)

        final = sock.recv(1024).decode()
        print(final)

def upload():
    if not session_token:
        messagebox.showerror("Not logged in", "Please login first.")
        return

    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    allowed_users = simpledialog.askstring("Allowed Users", "Enter comma-separated usernames allowed to access this file:")
    if allowed_users is None:
        return

    try:
        upload_file(HOST, PORT, session_token, filepath, allowed_users)
        messagebox.showinfo("Upload", f"✅ File uploaded and encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Upload Error", str(e))

def download():
    if not session_token:
        messagebox.showerror("Not logged in", "Please login first.")
        return
    if derived_key is None:
        messagebox.showerror("Error", "Decryption key is missing. Please login first.")
        return

    filename = simpledialog.askstring("Download", "Enter filename to download:")
    if not filename:
        return

    s = connect_to_server()
    s.sendall(f"DOWNLOAD {session_token} {filename}".encode())
    encrypted_data = s.recv(10_000_000)
    s.close()

    if b"ERROR" in encrypted_data:
        messagebox.showerror("Download", encrypted_data.decode())
    else:
        try:
            print(f"[DEBUG] Encrypted file size received: {len(encrypted_data)} bytes")
            file_key = load_encrypted_file_key(filename, derived_key, username)
            print(f"[DEBUG] File key decrypted for user: {username}")
            decrypted = crypto_utils.decrypt_data(file_key, encrypted_data)
            print(f"[DEBUG] Decrypted file size: {len(decrypted)} bytes")
            print("[DEBUG] File decryption completed successfully.")

            os.makedirs(f"received_files_{username}", exist_ok=True)
            save_path = os.path.join(f"received_files_{username}", filename)
            with open(save_path, 'wb') as f:
                f.write(decrypted)

            messagebox.showinfo("Download", f"✅ File '{filename}' decrypted and downloaded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"❌ Decryption or save failed: {str(e)}")

def main():
    global status_label
    root = tk.Tk()
    root.title("💖 CipherShare GUI Client")
    root.geometry("330x420")
    root.configure(bg=PINK)

    tk.Label(root, text="📂 CipherShare Client", font=("Helvetica", 16, "bold"), bg=PINK).pack(pady=15)

    buttons = [
        ("Register", register),
        ("Login", login),
        ("List Files", list_files),
        ("Upload File", upload),
        ("Download File", download),
        ("Exit", root.quit),
    ]

    for text, command in buttons:
        tk.Button(root, text=text, command=command, width=25, height=2, bg=WHITE, font=FONT).pack(pady=7)

    status_label = tk.Label(root, text="Not logged in", bg=PINK, fg="red", font=FONT)
    status_label.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
