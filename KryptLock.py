import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from threading import Thread
from queue import Queue
import logging
import base64
import threading

# Set up logging
logging.basicConfig(filename='kryptlock.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


class KryptLockApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KryptLock")
        self.root.configure(bg='blue')
        self.create_widgets()
        self.key = None
        self.root.geometry("400x600")
        
    def create_widgets(self):
        self.krypt_data_button = tk.Button(self.root, text="Krypt Data", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.krypt_data)
        self.krypt_data_button.pack(pady=10)

        self.dekrypt_data_button = tk.Button(self.root, text="DeKrypt Data", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.dekrypt_data)
        self.dekrypt_data_button.pack(pady=10)

        self.krypt_directory_button = tk.Button(self.root, text="Krypt Directory", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.krypt_directory)
        self.krypt_directory_button.pack(pady=10)

        self.dekrypt_directory_button = tk.Button(self.root, text="DeKrypt Directory", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.dekrypt_directory)
        self.dekrypt_directory_button.pack(pady=10)

        self.create_key_button = tk.Button(self.root, text="Create a New Key", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.create_key)
        self.create_key_button.pack(pady=10)

        self.save_key_button = tk.Button(self.root, text="Save Key", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.save_key)
        self.save_key_button.pack(pady=10)

        self.load_key_button = tk.Button(self.root, text="Load Key", bg='black', fg='dark red', font=("Old English Text MT", 12, "bold"), width=20, height=2, command=self.load_key)
        self.load_key_button.pack(pady=10)

    def load_key(self):
        file_path = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=(("Key Files", "*.key"), ("All Files", "*.*"))
        )
        if file_path:
            password = simpledialog.askstring("Password", "Enter password:", show='*')
            if not password:
                messagebox.showerror("Error", "Password is required to load the key.")
                return

            try:
                with open(file_path, 'rb') as file:
                    salt = file.read(16) 
                    encrypted_key = file.read()

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                self.key = fernet.decrypt(encrypted_key)
                messagebox.showinfo("Success", "Key loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def save_key(self):
        try:
            if not hasattr(self, 'key'):
                messagebox.showerror("Error", "No key to save. Please create a key first.")
                return

            password = simpledialog.askstring("Password", "Enter password:", show='*')
            if not password:
                messagebox.showerror("Error", "Password is required to save the key.")
                return
            
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            encrypted_key = fernet.encrypt(self.key)

            file_path = filedialog.asksaveasfilename(
                title="Save Key File",
                defaultextension=".key",
                filetypes=(("Key Files", "*.key"), ("All Files", "*.*"))
            )
            if file_path:
                with open(file_path, 'wb') as file:
                    file.write(salt)
                    file.write(encrypted_key)
                messagebox.showinfo("Success", "Key saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {e}")

    def krypt_data(self):
        try:
            file_path = filedialog.askopenfilename()
            if not file_path:
                return

            with open(file_path, 'rb') as file:
                data = file.read()

            encrypted_data = self.encrypt(data)

            with open(file_path + '.krypt', 'wb') as file:
                file.write(encrypted_data)

            os.remove(file_path)

            messagebox.showinfo("Krypt Data", "Data encrypted successfully.")
            logging.info("Data encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during data encryption: {e}")

    def dekrypt_data(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[("Krypt files", "*.krypt")])
            if not file_path:
                return

            with open(file_path, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = self.decrypt(encrypted_data)

            original_extension = os.path.splitext(file_path)[0].split('.')[-1]
            new_file_path = file_path.replace('.krypt', '')

            with open(new_file_path, 'wb') as file:
                file.write(decrypted_data)

            os.remove(file_path)

            messagebox.showinfo("DeKrypt Data", "Data decrypted successfully.")
            logging.info("Data decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during data decryption: {e}")

    def krypt_directory(self):
        try:
            dir_path = filedialog.askdirectory()
            if not dir_path:
                return

            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        data = f.read()

                    encrypted_data = self.encrypt(data)

                    with open(file_path + '.krypt', 'wb') as f:
                        f.write(encrypted_data)

                    os.remove(file_path)

            messagebox.showinfo("Krypt Directory", "Directory encrypted successfully.")
            logging.info("Directory encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during directory encryption: {e}")

    def dekrypt_directory(self):
        try:
            dir_path = filedialog.askdirectory()
            if not dir_path:
                return

            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.endswith('.krypt'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()

                        decrypted_data = self.decrypt(encrypted_data)

                        original_extension = os.path.splitext(file_path)[0].split('.')[-1]
                        new_file_path = file_path.replace('.krypt', '')

                        with open(new_file_path, 'wb') as f:
                            f.write(decrypted_data)

                        os.remove(file_path)

            messagebox.showinfo("DeKrypt Directory", "Directory decrypted successfully.")
            logging.info("Directory decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during directory decryption: {e}")

    def create_key(self):
        try:
            self.key = AESGCM.generate_key(bit_length=256)
            messagebox.showinfo("Create Key", "Key created successfully.")
            logging.info("Key created successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during key creation: {e}")

    def encrypt(self, data):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        return nonce + encrypted_data

    def decrypt(self, encrypted_data):
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, None)

if __name__ == "__main__":
    root = tk.Tk()
    app = KryptLockApp(root)
    root.mainloop()
