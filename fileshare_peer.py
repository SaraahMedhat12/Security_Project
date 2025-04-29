import socket
import threading
import os
import json
import uuid
import crypto_utils

USERS_FILE = "users.json"
GLOBAL_SYMMETRIC_KEY = b'secure_shared_key_1234567890abcd'

class FileSharePeer:
    def __init__(self, port):
        self.host = '0.0.0.0'
        self.port = port
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users = self.load_users()
        self.sessions = {}
        os.makedirs("shared_files", exist_ok=True)

    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                data = json.load(f)
                return {u: (bytes.fromhex(info['hashed_pw']), bytes.fromhex(info['salt'])) for u, info in data.items()}
        return {}

    def save_users(self):
        data = {u: {'hashed_pw': hashed.hex(), 'salt': salt.hex()} for u, (hashed, salt) in self.users.items()}
        with open(USERS_FILE, 'w') as f:
            json.dump(data, f, indent=2)

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"[PEER] Listening on {self.host}:{self.port}")
        while True:
            client_socket, _ = self.peer_socket.accept()
            threading.Thread(target=self.handle_client_connection, args=(client_socket,)).start()

    def handle_client_connection(self, sock):
        try:
            command = sock.recv(1024).decode().strip()
            if not command:
                return

            if command == "REGISTER":
                sock.send(b"USERNAME:")
                username = sock.recv(1024).decode().strip()
                sock.send(b"PASSWORD:")
                password = sock.recv(1024).decode().strip()

                if username in self.users:
                    sock.send(b"ERROR: Username already exists.")
                else:
                    hashed_pw, salt = crypto_utils.hash_password(password)
                    self.users[username] = (hashed_pw, salt)
                    self.save_users()
                    os.makedirs(f"shared_files_{username}", exist_ok=True)
                    sock.send(b"Registration successful.")

            elif command == "LOGIN":
                sock.send(b"USERNAME:")
                username = sock.recv(1024).decode().strip()
                sock.send(b"PASSWORD:")
                password = sock.recv(1024).decode().strip()

                if username not in self.users:
                    sock.send(b"ERROR: User not found.")
                else:
                    hashed_pw, salt = self.users[username]
                    if crypto_utils.verify_password(password, hashed_pw, salt):
                        token = str(uuid.uuid4())
                        self.sessions[token] = username
                        sock.send(f"Login successful. SESSION_TOKEN:{token}".encode())
                        print(f"[DEBUG] User '{username}' logged in successfully.")
                    else:
                        sock.send(b"ERROR: Invalid password.")

            elif command.startswith("LIST"):
                _, token = command.split(" ", 1)
                if token not in self.sessions:
                    sock.send(b"ERROR: Invalid session token.")
                    return
                files = os.listdir("shared_files")
                sock.send("\n".join(files).encode())

            elif command.startswith("DOWNLOAD"):
                _, token, filename = command.split(" ", 2)
                if token not in self.sessions:
                    sock.send(b"ERROR: Invalid session token.")
                    return
                filepath = os.path.join("shared_files", filename)
                if not os.path.exists(filepath):
                    sock.send(b"ERROR: File not found")
                    return

                with open(filepath, 'rb') as f:
                    encrypted_data = f.read()

                sock.sendall(encrypted_data)

            else:
                sock.send(b"ERROR: Invalid command.")
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            sock.close()

if __name__ == "__main__":
    PORT = 8000
    FileSharePeer(PORT).start_peer()
