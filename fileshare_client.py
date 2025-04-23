import socket
import os
import crypto_utils

class FileShareClient:
    def __init__(self, peer_ip='127.0.0.1', port=8000):
        self.peer_ip = peer_ip
        self.port = port
        self.session_token = None
        self.username = None
        self.download_path = "received_files"

    def connect_to_peer(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.peer_ip, self.port))
            return sock
        except Exception as e:
            print(f"[ERROR] Failed to connect to peer: {e}")
            return None

    def register_user(self):
        username = input("Enter a username: ").strip()
        password = input("Enter a password: ").strip()
        if not username or not password:
            print("❌ Missing credentials! Please enter both username and password.")
            return

        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(b"REGISTER")
            sock.recv(1024)
            sock.send(username.encode())
            sock.recv(1024)
            sock.send(password.encode())
            response = sock.recv(1024).decode()
            print("[REGISTER]", response)
        finally:
            sock.close()

    def login_user(self):
        if self.session_token:
            print("⚠ You are already logged in.")
            return
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()
        if not username or not password:
            print("❌ Missing credentials! Please enter both username and password.")
            return

        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(b"LOGIN")
            sock.recv(1024)
            sock.send(username.encode())
            sock.recv(1024)
            sock.send(password.encode())
            response = sock.recv(1024).decode()
            if "SESSION_TOKEN:" in response:
                self.session_token = response.split("SESSION_TOKEN:")[1].strip()
                self.username = username
                self.download_path = f"received_files_{username}"
                os.makedirs(self.download_path, exist_ok=True)
                print("✅ Login successful.")
            else:
                print("[LOGIN]", response)
        finally:
            sock.close()

    def list_files(self):
        if not self.session_token:
            print("❌ You must log in before listing files.")
            return
        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(f"LIST {self.session_token}".encode())
            response = sock.recv(4096).decode()
            if response.startswith("ERROR"):
                print("[LIST]", response)
            else:
                print("\n📂 Files Available:\n" + response)
        finally:
            sock.close()

    def download_file(self):
        if not self.session_token:
            print("❌ You must log in before downloading files.")
            return
        filename = input("Enter the file name to download: ").strip()
        if not filename:
            print("❗ No file name entered.")
            return
        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(f"DOWNLOAD {self.session_token} {filename}".encode())
            data = sock.recv(10_000_000)
            if data.startswith(b"ERROR"):
                print("[DOWNLOAD]", data.decode())
            else:
                with open(os.path.join(self.download_path, filename), 'wb') as f:
                    f.write(data)
                print(f"✅ Downloaded: {filename} to {self.download_path}/")
        finally:
            sock.close()


if __name__ == "__main__":
    print("=== CipherShare Client (Persistent Login Edition) ===")
    client = FileShareClient()

    while True:
        print("\nOptions: register | login | list | download | quit")
        cmd = input("Enter command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "register":
            client.register_user()
        elif cmd == "login":
            client.login_user()
        elif cmd == "list":
            client.list_files()
        elif cmd == "download":
            client.download_file()
        else:
            print("❗ Invalid command.")
