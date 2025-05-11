import socket
import threading
import os
import json
import uuid
import crypto_utils
from user_manager import load_users, save_users

MASTER_PASSWORD = "pass"
ACCESS_CONTROL_FILE = "file_access.json"

class FileSharePeer:
    def __init__(self, port):
        self.host = '0.0.0.0'
        self.port = port
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users, self.key = load_users(MASTER_PASSWORD)
        if self.users is None:
            print("[FATAL] Failed to load users. Exiting.")
            exit(1)
        self.sessions = {}  # token => {username, key}
        self.logged_in_users = set()
        os.makedirs("shared_files", exist_ok=True)
        self.load_access_control()

    def load_access_control(self):
        if os.path.exists(ACCESS_CONTROL_FILE):
            try:
                with open(ACCESS_CONTROL_FILE, 'r') as f:
                    self.file_access = json.load(f)
            except:
                self.file_access = {}
        else:
            self.file_access = {}

    def save_access_control(self):
        with open(ACCESS_CONTROL_FILE, 'w') as f:
            json.dump(self.file_access, f, indent=2)

    def save_users_securely(self):
        save_users(self.users, self.key)

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"[PEER] Listening on {self.host}:{self.port}")
        while True:
            client_socket, _ = self.peer_socket.accept()
            threading.Thread(target=self.handle_client_connection, args=(client_socket,)).start()

    def handle_client_connection(self, sock):
        logged_in_token = None
        logged_in_username = None

        try:
            while True:
                command = sock.recv(1024).decode().strip()
                if not command:
                    return

                if command == "REGISTER":
                    if logged_in_token is not None:
                        sock.send(b"ERROR: Already logged in.\n")
                        continue

                    sock.send(b"USERNAME:")
                    username = sock.recv(1024).decode().strip()
                    sock.send(b"PASSWORD:")
                    password = sock.recv(1024).decode().strip()

                    if username in self.users:
                        sock.send(b"ERROR: Username already exists.")
                    else:
                        hashed_pw = crypto_utils.argon2_hash_password(password)
                        self.users[username] = {"argon2": hashed_pw}
                        self.save_users_securely()
                        os.makedirs(f"shared_files_{username}", exist_ok=True)
                        sock.send(b"Registration successful.")

                elif command == "LOGIN":
                    if logged_in_token is not None:
                        sock.send(b"ERROR: Already logged in.\n")
                        continue

                    sock.send(b"USERNAME:")
                    username = sock.recv(1024).decode().strip()
                    sock.send(b"PASSWORD:")
                    password = sock.recv(1024).decode().strip()

                    if username not in self.users or "argon2" not in self.users[username]:
                        sock.send(b"ERROR: User not found.")
                    elif username in self.logged_in_users:
                        sock.send(b"ERROR: User already logged in elsewhere.\n")
                    else:
                        hashed_pw = self.users[username]["argon2"]
                        if crypto_utils.argon2_verify_password(password, hashed_pw):
                            salt = b"static_salt_16bytes"
                            session_key = crypto_utils.derive_key_from_password(password, salt)

                            token = str(uuid.uuid4())
                            self.sessions[token] = {
                                "username": username,
                                "key": session_key
                            }
                            self.logged_in_users.add(username)

                            logged_in_token = token
                            logged_in_username = username

                            print(f"[DEBUG] User '{username}' logged in.")
                            sock.send(f"Login successful. SESSION_TOKEN:{token}\n".encode())
                        else:
                            sock.send(b"ERROR: Invalid password.")

                elif command.startswith("LIST"):
                    try:
                        _, token = command.split(" ", 1)
                    except:
                        sock.send(b"ERROR: Invalid command format.\n")
                        continue

                    if token not in self.sessions:
                        sock.send(b"ERROR: Invalid or no session.\n")
                        continue

                    username = self.sessions[token]["username"]
                    visible_files = []

                    for fname, meta in self.file_access.items():
                        if meta.get("owner") == username or username in meta.get("allowed_users", []):
                            visible_files.append(fname)

                    if visible_files:
                        sock.send(("\n".join(visible_files) + "\n").encode())
                    else:
                        sock.send(b"No accessible files.\n")

                elif command.startswith("DOWNLOAD"):
                    try:
                        _, token, filename = command.split(" ", 2)
                    except:
                        sock.send(b"ERROR: Invalid command format.\n")
                        continue

                    if token not in self.sessions:
                        sock.send(b"ERROR: Invalid or no session.\n")
                        continue

                    username = self.sessions[token]["username"]

                    if filename not in self.file_access:
                        sock.send(b"ERROR: File not found.")
                        continue

                    meta = self.file_access[filename]
                    if username != meta["owner"] and username not in meta.get("allowed_users", []):
                        sock.send(b"ERROR: Access denied.")
                        continue

                    filepath = os.path.join("shared_files", filename)
                    if not os.path.exists(filepath):
                        sock.send(b"ERROR: File not found")
                        continue

                    with open(filepath, 'rb') as f:
                        sock.sendall(f.read())

                elif command.startswith("UPLOAD"):
                    try:
                        _, token, filename = command.split(" ", 2)
                    except:
                        sock.send(b"ERROR: Invalid command format.\n")
                        continue

                    if token not in self.sessions:
                        sock.send(b"ERROR: Invalid or no session.\n")
                        continue

                    username = self.sessions[token]["username"]
                    user_dir = f"shared_files_{username}"
                    os.makedirs(user_dir, exist_ok=True)

                    filepath_global = os.path.join("shared_files", filename)
                    filepath_user = os.path.join(user_dir, filename)

                    # Step 1: Ask for allowed users
                    sock.send(b"Enter usernames to share with (comma separated):")
                    allowed_data = sock.recv(2048).decode().strip()
                    allowed_users = [
                        u.strip() for u in allowed_data.split(',')
                        if u.strip() in self.users and u.strip() != username
                    ]

                    # Step 2: Tell client to send file
                    sock.send(b"READY")  # Client sends file now

                    # Step 3: Receive file data
                    file_data = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        file_data += chunk

                    with open(filepath_global, 'wb') as f:
                        f.write(file_data)  # encrypted version stored globally

                    try:
                        decrypted_data = crypto_utils.decrypt_data(
                            b'secure_shared_key_1234567890abcd', file_data
                        )
                        with open(filepath_user, 'wb') as f:
                            f.write(decrypted_data)  # plaintext stored in user folder
                    except Exception as e:
                        print(f"[ERROR] Failed to decrypt for user folder: {e}")
                        sock.send(b"ERROR: Failed to decrypt and store file.\n")
                        return

                    # Save access metadata
                    self.file_access[filename] = {
                        "owner": username,
                        "allowed_users": allowed_users
                    }
                    self.save_access_control()

                    sock.send(b"Upload successful.\n")
                    print(f"[UPLOAD] '{filename}' uploaded by '{username}' with access for {allowed_users}")

                else:
                    sock.send(b"ERROR: Invalid command.\n")

        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            if logged_in_username:
                self.logged_in_users.discard(logged_in_username)
            sock.close()

if __name__ == "__main__":
    PORT = 8000
    FileSharePeer(PORT).start_peer()

