import socket
import os
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import crypto_utils  

HOST = '127.0.0.1'
PORT = 8000

session_token = None
username = None
derived_key = None  # 🔑 Store the per-user derived encryption key

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

def register():
    global username
    s = connect_to_server()
    s.sendall(b"REGISTER")
    s.recv(1024)  # USERNAME:
    u, p = show_auth_dialog("Register")
    if not u or not p:
        s.close()
        return
    username = u
    s.sendall(u.encode())
    s.recv(1024)  # PASSWORD:
    s.sendall(p.encode())
    response = s.recv(1024).decode()
    s.close()
    messagebox.showinfo("Register", response)

def login():
    global session_token, username, derived_key
    if session_token:
        messagebox.showwarning("Already logged in", f"You're already logged in as {username}.")
        return

    s = connect_to_server()
    s.sendall(b"LOGIN")
    s.recv(1024)  # USERNAME:
    u, p = show_auth_dialog("Login")
    if not u or not p:
        s.close()
        return
    username = u
    s.sendall(u.encode())
    s.recv(1024)  # PASSWORD:
    s.sendall(p.encode())
    response = s.recv(2048).decode()

    # 🔑 Derive encryption key from password
    salt = b'static_salt_16bytes'  # ⚠️ Must match the server salt
    derived_key = crypto_utils.derive_key_from_password(p, salt)
    print(f"[DEBUG] Login: username: {username}")
    print(f"[DEBUG] Using salt: {salt}")
    print(f"[DEBUG] Derived encryption key (hex): {derived_key.hex()}")

    s.close()
    if "SESSION_TOKEN:" in response:
        session_token = response.split("SESSION_TOKEN:")[1].strip()
        print(f"[DEBUG] Session token received: {session_token}")  # NEW DEBUG
        os.makedirs(f"received_files_{username}", exist_ok=True)
        messagebox.showinfo("Login", f"\U0001F389 Login successful!\n\nSession Token:\n{session_token}")

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
    print(f"[DEBUG] Files listed from server: {response}")  # NEW DEBUG
    messagebox.showinfo("Files on Server", response)

def upload_file(server_ip, port, token, filepath, allowed_users):
    if derived_key is None:
        messagebox.showerror("Error", "Encryption key is missing. Please login first.")
        return

    filename = os.path.basename(filepath)

    # Step 1: Read original data (raw data from the file)
    with open(filepath, "rb") as f:
        raw_data = f.read()
    print(f"[DEBUG] Uploading file: {filename}")
    print(f"[DEBUG] Original file size: {len(raw_data)} bytes")  # [DEBUG]

    # Step 2: Encrypt the data before sending using derived key
    encrypted_data = crypto_utils.encrypt_data(derived_key, raw_data)
    print(f"[DEBUG] Encrypted data size: {len(encrypted_data)} bytes")  # [DEBUG]
    print("[DEBUG] File encrypted successfully before upload.")  # [DEBUG]
    print(f"[DEBUG] Upload: using derived key: {derived_key.hex()}")  # [DEBUG]

    # Step 3: Save the original (raw) file content locally in "shared_files_username"
    os.makedirs(f"shared_files_{username}", exist_ok=True)
    with open(os.path.join(f"shared_files_{username}", filename), 'wb') as f:
        f.write(raw_data)

    # Step 4: Save hash of original (not encrypted) file locally
    file_hash = crypto_utils.hash_data(raw_data)
    os.makedirs("hashes", exist_ok=True)
    hash_file_path = os.path.join("hashes", filename + ".hash")
    with open(hash_file_path, 'wb') as f:
        f.write(file_hash)
    print(f"[DEBUG] Hash saved at: {hash_file_path}")

    # Step 5: Send the encrypted file to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))
        sock.sendall(f"UPLOAD {token} {filename}\n".encode())

        response = sock.recv(1024).decode()
        if "Enter usernames" in response:
            sock.sendall(f"{allowed_users}\n".encode())
            print(f"[DEBUG] Allowed users sent to server: {allowed_users}")  # NEW DEBUG

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
        messagebox.showinfo("Upload", f"✅ File uploaded successfully.")
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
    data = s.recv(10_000_000)
    s.close()

    if b"ERROR" in data:
        messagebox.showerror("Download", data.decode())
    else:
        try:
            print(f"[DEBUG] Encrypted file size received: {len(data)} bytes")  # [DEBUG]
            decrypted = crypto_utils.decrypt_data(derived_key, data)
            print(f"[DEBUG] Decrypted file size: {len(decrypted)} bytes")      # [DEBUG]
            print("[DEBUG] File decrypted successfully after download.")        # [DEBUG]
            print(f"[DEBUG] Download: using derived key: {derived_key.hex()}")  # [DEBUG]

            downloaded_hash = crypto_utils.hash_data(decrypted)

            hash_path = os.path.join("hashes", filename + ".hash")
            print(f"[DEBUG] Looking for hash file at: {hash_path}")
            if os.path.exists(hash_path):
                with open(hash_path, 'rb') as f:
                    expected = f.read()
                if downloaded_hash != expected:
                    messagebox.showerror("Integrity Check", "❌ Integrity check failed!")
                    print("[DEBUG] Integrity check FAILED.")                    # [DEBUG]
                    return
                else:
                    print("[DEBUG] Integrity check passed!")                   # [DEBUG]
            else:
                messagebox.showwarning("Hash Missing", "⚠️ No stored hash found.")
                print("[DEBUG] No stored hash file found.")

            os.makedirs(f"received_files_{username}", exist_ok=True)
            with open(os.path.join(f"received_files_{username}", filename), 'wb') as f:
                f.write(decrypted)
            messagebox.showinfo("Download", f"✅ File '{filename}' downloaded successfully.")
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
