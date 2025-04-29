import socket
import os
import crypto_utils

GLOBAL_SYMMETRIC_KEY = b'secure_shared_key_1234567890abcd'

class FileShareClient:
    def __init__(self, peer_ip='127.0.0.1', port=8000):
        self.peer_ip = peer_ip
        self.port = port
        self.session_token = None
        self.username = None
        os.makedirs("hashes", exist_ok=True)

    def connect_to_peer(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.peer_ip, self.port))
            return sock
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return None

    def register_user(self):
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(b"REGISTER")
            sock.recv(1024)
            sock.send(username.encode())
            sock.recv(1024)
            sock.send(password.encode())
            print(sock.recv(1024).decode())
        finally:
            sock.close()

    def login_user(self):
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

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
                os.makedirs(f"received_files_{username}", exist_ok=True)
                print("✅ Login successful.")
            else:
                print("[LOGIN]", response)
        finally:
            sock.close()

    def list_files(self):
        if not self.session_token:
            print("❌ You must login first.")
            return

        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(f"LIST {self.session_token}".encode())
            response = sock.recv(4096).decode()
            print("\n📂 Shared Files:\n" + response)
        finally:
            sock.close()

    def upload_file(self):
        if not self.session_token:
            print("❌ You must login first.")
            return

        filename = input("Enter new filename to upload: ").strip()
        content = input("Enter content for the file: ").encode()

        encrypted_content = crypto_utils.encrypt_data(GLOBAL_SYMMETRIC_KEY, content)
        content_hash = crypto_utils.hash_data(content)

        os.makedirs(f"shared_files_{self.username}", exist_ok=True)
        with open(os.path.join(f"shared_files_{self.username}", filename), 'wb') as f:
            f.write(content)

        os.makedirs("shared_files", exist_ok=True)
        with open(os.path.join("shared_files", filename), 'wb') as f:
            f.write(encrypted_content)

        os.makedirs("hashes", exist_ok=True)
        with open(os.path.join("hashes", filename + ".hash"), 'wb') as f:
            f.write(content_hash)

        print(f"✅ File '{filename}' uploaded successfully.")
        print(f"[DEBUG] Uploaded plain content hash: {content_hash.hex()}")

    def download_file(self):
        if not self.session_token:
            print("❌ You must login first.")
            return

        filename = input("Enter filename to download: ").strip()

        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(f"DOWNLOAD {self.session_token} {filename}".encode())
            data = sock.recv(10_000_000)

            if data.startswith(b"ERROR"):
                print("[DOWNLOAD]", data.decode())
            else:
                decrypted_content = crypto_utils.decrypt_data(GLOBAL_SYMMETRIC_KEY, data)
                downloaded_hash = crypto_utils.hash_data(decrypted_content)

                expected_hash_path = os.path.join("hashes", filename + ".hash")
                if not os.path.exists(expected_hash_path):
                    print("❌ No stored hash found for file. Cannot verify.")
                    return

                with open(expected_hash_path, 'rb') as f:
                    expected_hash = f.read()

                if downloaded_hash == expected_hash:
                    with open(os.path.join(f"received_files_{self.username}", filename), 'wb') as f:
                        f.write(decrypted_content)
                    print(f"✅ File '{filename}' downloaded and verified successfully!")
                else:
                    print("❌ Decryption failed! File may be corrupted or tampered.")
        finally:
            sock.close()

if __name__ == "__main__":
    print("=== CipherShare Client (P2P + Upload + Corrected Final Phase 3) ===")
    client = FileShareClient()

    while True:
        print("\nOptions: register | login | list | upload | download | quit")
        cmd = input("Enter command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "register":
            client.register_user()
        elif cmd == "login":
            client.login_user()
        elif cmd == "list":
            client.list_files()
        elif cmd == "upload":
            client.upload_file()
        elif cmd == "download":
            client.download_file()
        else:
            print("Invalid command.")
