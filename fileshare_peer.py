import socket
import threading
import os
import uuid
import json
import crypto_utils

SHARED_FOLDER = "shared_files"
USERS_FILE = "users.json"

class FileSharePeer:
    def __init__(self, port):
        self.host = '0.0.0.0'
        self.port = port
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_files = self.load_shared_files()
        self.users = self.load_users()
        self.sessions = {}  # token: username

    def load_shared_files(self):
        if not os.path.exists(SHARED_FOLDER):
            os.makedirs(SHARED_FOLDER)
        return {f: os.path.join(SHARED_FOLDER, f) for f in os.listdir(SHARED_FOLDER)}

    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                data = json.load(f)
                return {
                    u: (bytes.fromhex(info['hashed_pw']), bytes.fromhex(info['salt']))
                    for u, info in data.items()
                }
        return {}

    def save_users(self):
        data = {
            u: {
                'hashed_pw': hashed.hex(),
                'salt': salt.hex()
            }
            for u, (hashed, salt) in self.users.items()
        }
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
                    sock.send(b"ERROR: Username already exists. Try logging in.")
                else:
                    hashed_pw, salt = crypto_utils.hash_password(password)
                    self.users[username] = (hashed_pw, salt)
                    self.save_users()
                    print(f"[DEBUG] Hashed password for {username}: {hashed_pw.hex()}")
                    sock.send(b"Registration successful.")

            elif command == "LOGIN":
                sock.send(b"USERNAME:")
                username = sock.recv(1024).decode().strip()
                sock.send(b"PASSWORD:")
                password = sock.recv(1024).decode().strip()

                if username not in self.users:
                    sock.send(b"ERROR: User not found. Please register first.")
                else:
                    hashed_pw, salt = self.users[username]
                    if crypto_utils.verify_password(password, hashed_pw, salt):
                        if username in self.sessions.values():
                            sock.send(b"You are already logged in.")
                        else:
                            token = str(uuid.uuid4())
                            self.sessions[token] = username
                            sock.send(f"Login successful. SESSION_TOKEN:{token}".encode())
                    else:
                        sock.send(b"ERROR: Invalid password")

            elif command.startswith("LIST"):
                _, token = command.split(" ", 1)
                if token not in self.sessions:
                    sock.send(b"ERROR: Invalid or expired session token.")
                    return
                file_list = "\n".join(self.shared_files.keys())
                sock.send(file_list.encode())

            elif command.startswith("DOWNLOAD"):
                _, token, filename = command.split(" ", 2)
                if token not in self.sessions:
                    sock.send(b"ERROR: Invalid or expired session token.")
                    return
                if filename in self.shared_files:
                    with open(self.shared_files[filename], 'rb') as f:
                        sock.sendall(f.read())
                else:
                    sock.send(b"ERROR: File not found")

            else:
                sock.send(b"ERROR: Invalid command")
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            sock.close()


if __name__ == "__main__":
    PORT = 8000
    FileSharePeer(PORT).start_peer()
