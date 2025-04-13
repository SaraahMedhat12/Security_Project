import socket
import threading
import os
import crypto_utils  # Not used in Phase 1, placeholder for future use

SHARED_FOLDER = "shared_files"


class FileSharePeer:
    def __init__(self, port):
        self.host = '0.0.0.0'
        self.port = port
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_files = self.load_shared_files()

    def load_shared_files(self):
        """
        Scans the SHARED_FOLDER and builds a dictionary of available files.
        """
        files = {}
        if not os.path.exists(SHARED_FOLDER):
            os.makedirs(SHARED_FOLDER)
        for fname in os.listdir(SHARED_FOLDER):
            files[fname] = os.path.join(SHARED_FOLDER, fname)
        return files

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"[PEER] Listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            print(f"[PEER] Connection from {client_address}")
            threading.Thread(target=self.handle_client_connection, args=(client_socket,)).start()

    def handle_client_connection(self, client_socket):
        try:
            command = client_socket.recv(1024).decode().strip()
            if not command:
                return

            if command == "LIST":
                file_list = "\n".join(self.shared_files.keys())
                client_socket.send(file_list.encode())

            elif command.startswith("DOWNLOAD"):
                _, filename = command.split(" ", 1)
                if filename in self.shared_files:
                    with open(self.shared_files[filename], 'rb') as f:
                        data = f.read()
                        client_socket.sendall(data)
                    print(f"[PEER] Sent '{filename}' to client")
                else:
                    client_socket.send(b"ERROR: File not found")

            else:
                client_socket.send(b"ERROR: Invalid command")

        except Exception as e:
            print(f"[ERROR] Error handling client: {e}")
        finally:
            client_socket.close()


if __name__ == "__main__":
    PORT = 8000  # You can change this if needed
    peer = FileSharePeer(PORT)
    peer.start_peer()
