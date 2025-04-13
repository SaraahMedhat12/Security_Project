import socket
import os
import crypto_utils  # Placeholder for future use

RECEIVED_FOLDER = "received_files"


class FileShareClient:
    def __init__(self, peer_ip='127.0.0.1', port=8000):
        self.peer_ip = peer_ip
        self.port = port
        self.username = None
        self.session_key = None  # Placeholder for future encryption

    def connect_to_peer(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.peer_ip, self.port))
            return client_socket
        except Exception as e:
            print(f"[ERROR] Failed to connect to peer at {self.peer_ip}:{self.port} → {e}")
            return None

    def list_files(self):
        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(b"LIST")
            data = sock.recv(4096).decode()
            print("\n📄 Files shared by peer:\n" + data)
        except Exception as e:
            print(f"[ERROR] Could not retrieve file list: {e}")
        finally:
            sock.close()

    def download_file(self, filename):
        sock = self.connect_to_peer()
        if not sock:
            return
        try:
            sock.send(f"DOWNLOAD {filename}".encode())
            data = sock.recv(10_000_000)  # Max ~10 MB
            if data.startswith(b"ERROR"):
                print("[!] " + data.decode())
            else:
                os.makedirs(RECEIVED_FOLDER, exist_ok=True)
                with open(os.path.join(RECEIVED_FOLDER, filename), 'wb') as f:
                    f.write(data)
                print(f"[✔] Downloaded '{filename}' and saved to '{RECEIVED_FOLDER}/'")
        except Exception as e:
            print(f"[ERROR] Failed to download file: {e}")
        finally:
            sock.close()

    def register_user(self, username, password):
        """
        Placeholder for future user registration in Phase 2.
        """
        print("[INFO] Registration is not implemented in Phase 1.")

    def login_user(self, username, password):
        """
        Placeholder for future login/authentication in Phase 2.
        """
        print("[INFO] Login is not implemented in Phase 1.")

    def upload_file(self, filepath):
        """
        Placeholder for file upload in future versions.
        """
        print("[INFO] Upload is not implemented in Phase 1.")

    def search_files(self, keyword):
        """
        Placeholder for file search functionality in a future phase.
        """
        print("[INFO] Search is not implemented in Phase 1.")

    def list_shared_files(self):
        """
        Local method to show which files are being shared from the client's own machine (optional).
        """
        print("[INFO] File sharing from client is not active in Phase 1.")


if __name__ == "__main__":
    print("=== CipherShare Client (Phase 1) ===")
    client = FileShareClient()

    while True:
        cmd = input("\nEnter command (list / download <filename> / quit): ").strip()
        if cmd == "quit":
            break
        elif cmd == "list":
            client.list_files()
        elif cmd.startswith("download "):
            _, filename = cmd.split(" ", 1)
            client.download_file(filename)
        else:
            print("Invalid command. Try again.")
