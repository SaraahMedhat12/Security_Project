import socket
import os
import crypto_utils  # Make sure this module includes encrypt_data, decrypt_data, hash_data

HOST = '127.0.0.1'
PORT = 8000
GLOBAL_SYMMETRIC_KEY = b'secure_shared_key_1234567890abcd'

def send_and_receive(sock, message):
    sock.sendall(message.encode())
    return sock.recv(4096).decode()

def main():
    session_token = None
    username = None
    print("=== CipherShare Client (P2P + Upload + Corrected Final Phase 3) ===")

    while True:
        print("\nOptions: register | login | list | upload | download | quit")
        command = input("Enter command: ").strip().lower()

        if command == "quit":
            break

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))

            if command == "register":
                sock.sendall(b"REGISTER")
                print(sock.recv(1024).decode(), end='')  # USERNAME:
                username = input()
                sock.sendall(username.encode())
                print(sock.recv(1024).decode(), end='')  # PASSWORD:
                password = input()
                sock.sendall(password.encode())
                print(sock.recv(1024).decode())

            elif command == "login":
                if session_token is not None:
                    print(f"⚠️ Already logged in as '{username}'. Please restart to switch users.")
                    continue

                sock.sendall(b"LOGIN")
                print(sock.recv(1024).decode(), end='')  # USERNAME:
                username = input()
                sock.sendall(username.encode())
                print(sock.recv(1024).decode(), end='')  # PASSWORD:
                password = input()
                sock.sendall(password.encode())
                response = sock.recv(1024).decode()
                print(response)

                if "SESSION_TOKEN:" in response:
                    session_token = response.split("SESSION_TOKEN:")[1].strip()
                    os.makedirs(f"received_files_{username}", exist_ok=True)

            elif command == "list":
                if session_token is None:
                    print("[LIST] ❌ ERROR: Not logged in.")
                    continue

                list_command = f"LIST {session_token}"
                sock.sendall(list_command.encode())
                response = sock.recv(4096).decode()
                print("[FILES]\n" + response)

            elif command == "download":
                if session_token is None:
                    print("[DOWNLOAD] ❌ ERROR: Not logged in.")
                    continue

                filename = input("Enter filename to download: ").strip()
                download_command = f"DOWNLOAD {session_token} {filename}"
                sock.sendall(download_command.encode())

                data = sock.recv(10_000_000)
                if b"ERROR" in data:
                    print("[DOWNLOAD]", data.decode())
                else:
                    try:
                        decrypted = crypto_utils.decrypt_data(GLOBAL_SYMMETRIC_KEY, data)
                        downloaded_hash = crypto_utils.hash_data(decrypted)

                        hash_path = os.path.join("hashes", filename + ".hash")
                        if not os.path.exists(hash_path):
                            print("⚠️ No stored hash found. Skipping integrity check.")
                        else:
                            with open(hash_path, 'rb') as f:
                                expected_hash = f.read()
                            if downloaded_hash != expected_hash:
                                print("❌ Integrity check failed! File may be corrupted.")
                                continue

                        os.makedirs(f"received_files_{username}", exist_ok=True)
                        with open(os.path.join(f"received_files_{username}", filename), 'wb') as f:
                            f.write(decrypted)
                        print(f"[DOWNLOAD] ✅ File '{filename}' downloaded and verified successfully.")

                    except Exception as e:
                        print("❌ Decryption failed or corrupted file:", str(e))

            elif command == "upload":
                if session_token is None:
                    print("[UPLOAD] ❌ ERROR: Not logged in.")
                    continue

                filename = input("Enter new filename to upload: ").strip()
                content = input("Enter content for the file:\n").encode()

                encrypted_content = crypto_utils.encrypt_data(GLOBAL_SYMMETRIC_KEY, content)
                content_hash = crypto_utils.hash_data(content)

                # Save locally in both folders
                os.makedirs(f"shared_files_{username}", exist_ok=True)
                os.makedirs("shared_files", exist_ok=True)
                os.makedirs("hashes", exist_ok=True)

                with open(os.path.join(f"shared_files_{username}", filename), 'wb') as f:
                    f.write(content)
                with open(os.path.join("shared_files", filename), 'wb') as f:
                    f.write(encrypted_content)
                with open(os.path.join("hashes", filename + ".hash"), 'wb') as f:
                    f.write(content_hash)

                print(f"[UPLOAD] ✅ File '{filename}' created and stored.")
                print(f"[DEBUG] Uploaded content hash: {content_hash.hex()}")

            else:
                print("❌ Invalid command.")

if __name__ == "__main__":
    main()
