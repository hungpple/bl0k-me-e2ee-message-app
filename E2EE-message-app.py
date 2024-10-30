##### ---------------------------------------------------------------------------------------
##### Author: Hung Le
##### Create Date: 12th October 2024
##### Description: Simple E2EE Messaging Application Applied BL0K-ME Protocol
##### ---------------------------------------------------------------------------------------

import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, scrolledtext
from tkcalendar import DateEntry
from PIL import Image, ImageTk
import requests
from io import BytesIO
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import os

def set_window_icon(window, icon_path="e2eemessage.ico"):
    try:
        icon_path = os.path.join(os.path.dirname(__file__), icon_path)
        window.iconbitmap(icon_path)
    except Exception as e:
        print(f"Error setting window icon: {e}")


def load_user_icon(root):
    url = "https://img.icons8.com/?size=100&id=98957&format=png&color=000000"
    response = requests.get(url)
    icon_image = Image.open(BytesIO(response.content)).resize((30, 30))
    return ImageTk.PhotoImage(icon_image, master=root)


class BloomFilter:
    def __init__(self, size=1000, hash_count=5):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size

    def _hash(self, item, seed):
        hash_object = hashlib.md5((item + str(seed)).encode())
        return int(hash_object.hexdigest(), 16) % self.size

    def add(self, item):
        for i in range(self.hash_count):
            index = self._hash(item, i)
            self.bit_array[index] = 1

    def check(self, item):
        for i in range(self.hash_count):
            index = self._hash(item, i)
            if self.bit_array[index] == 0:
                return False
        return True


class Account:
    def __init__(self, username):
        self.username = username
        # RSA encryption algorithm
        self.private_key = rsa.generate_private_key( 
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt_message(self, message, recipient_public_key):
        encrypted = recipient_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_message(self, encrypted_message):
        try:
            decoded_message = base64.b64decode(encrypted_message)
            return self.private_key.decrypt(
                decoded_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
                ),
            ).decode()
        except ValueError:
            return "[Decryption Failed]"


class MessageApp:
    def __init__(self):
        self.messages = []
        self.bloom_filter = BloomFilter()

    def generate_key(self, username, timestamp, content):
        return f"{username}-{timestamp}-{content}"

    def send_message(self, sender, recipient, content):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        encrypted_message = sender.encrypt_message(content, recipient.public_key)
        self.messages.append(
            {
                "sender": sender.username,
                "recipient": recipient.username,
                "plain_content": content,
                "encrypted_content": encrypted_message,
                "timestamp": timestamp,
            }
        )
        key = self.generate_key(sender.username, timestamp, content)
        self.bloom_filter.add(key)

    def get_all_messages(self):
        return self.messages

    def delete_message(self, index):
        if 0 <= index < len(self.messages):
            del self.messages[index]
            return True
        return False

class UserWindow:
    def __init__(self, root, app, user, peer, user_icon):
        self.app = app
        self.user = user
        self.peer = peer

        root.title(f"E2EE Message - {user.username}")

        main_frame = tk.Frame(root)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        header_frame = tk.Frame(main_frame)
        header_frame.pack(fill="x", pady=5)

        tk.Label(header_frame, text="E2EE Message", font=("Arial", 16, "bold")).pack(side=tk.TOP)

        user_frame = tk.Frame(header_frame)
        user_frame.pack(side=tk.RIGHT)

        tk.Label(user_frame, image=user_icon).pack(side=tk.LEFT, padx=5)
        tk.Label(user_frame, text=user.username, font=("Arial", 14)).pack(side=tk.LEFT)

        self.message_list = tk.Text(main_frame, width=60, height=15, state=tk.DISABLED)
        self.message_list.pack(pady=5)

        self.message_list.tag_configure("received", foreground="blue", justify="left")
        self.message_list.tag_configure("sent", foreground="green", justify="right")

        delete_frame = tk.Frame(main_frame)
        delete_frame.pack(anchor="w", pady=5)
        tk.Label(delete_frame, text="Delete Message (index):").pack(side=tk.LEFT)
        self.delete_entry = tk.Entry(delete_frame, width=5)
        self.delete_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(delete_frame, text="Delete", command=self.delete_message).pack(side=tk.LEFT)

        input_frame = tk.Frame(main_frame)
        input_frame.pack(pady=5, fill="x")
        self.message_entry = tk.Entry(input_frame, width=45)
        self.message_entry.pack(side=tk.LEFT, padx=5, fill="x", expand=True)
        tk.Button(input_frame, text="Send", command=self.send_message).pack(side=tk.LEFT)

        self.update_messages()

    def send_message(self):
        content = self.message_entry.get()
        if not content.strip():
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        self.app.send_message(self.user, self.peer, content)
        self.message_entry.delete(0, tk.END)

    def update_messages(self):
        self.message_list.config(state=tk.NORMAL)
        self.message_list.delete(1.0, tk.END)

        for i, msg in enumerate(self.app.get_all_messages()):
            sender = msg["sender"]
            recipient = msg["recipient"]
            timestamp = msg["timestamp"]

            if recipient == self.user.username:
                decrypted_message = self.user.decrypt_message(msg["encrypted_content"])
                display_text = f"{i + 1}. From {sender} [{timestamp}]: {decrypted_message}\n"
                self.message_list.insert(tk.END, display_text, "received")
            elif sender == self.user.username:
                display_text = f"{i + 1}. To {recipient} [{timestamp}]: {msg['plain_content']}\n"
                self.message_list.insert(tk.END, display_text, "sent")

        self.message_list.config(state=tk.DISABLED)
        self.message_list.after(500, self.update_messages)

    def delete_message(self):
        try:
            index = int(self.delete_entry.get()) - 1
            if self.app.delete_message(index):
                messagebox.showinfo("Success", "Message deleted!")
            else:
                messagebox.showerror("Error", "Invalid index.")
        except ValueError:
            messagebox.showerror("Error", "Invalid input.")
        self.delete_entry.delete(0, tk.END)


class ProviderWindow:
    def __init__(self, root, app):
        self.app = app

        root.title("E2EE Message Provider")

        main_frame = tk.Frame(root)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        tk.Label(main_frame, text="E2EE Message Provider", font=("Arial", 18, "bold")).pack(pady=10)

        tk.Button(main_frame, text="Message Log", command=self.open_message_log).pack(pady=5)
        tk.Button(main_frame, text="Verify Message", command=self.open_verify_window).pack(pady=5)

    def open_message_log(self):
        log_window = Toplevel()
        log_window.title("Message Log")

        log_text = scrolledtext.ScrolledText(log_window, width=80, height=20)
        log_text.pack(padx=10, pady=10)
        set_window_icon(log_window)
        messages = self.app.get_all_messages()
        for msg in messages:
            log_text.insert(
                tk.END,
                f"{msg['timestamp']} | From: {msg['sender']} To: {msg['recipient']} - [Encrypted Content]\n"
            )

    def open_verify_window(self):
        verify_window = Toplevel()
        verify_window.title("Verify Message")

        form_frame = ttk.Frame(verify_window, padding=10)
        form_frame.pack(fill="both", expand=True)
        set_window_icon(verify_window)
        ttk.Label(form_frame, text="User:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        user_entry = ttk.Entry(form_frame, width=30)
        user_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Date:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        date_picker = DateEntry(form_frame, width=28, date_pattern='yyyy-mm-dd')
        date_picker.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Time (HH:MM:SS):").grid(row=2, column=0, padx=5, pady=5, sticky="w")

        time_frame = ttk.Frame(form_frame)
        time_frame.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        hour_entry = ttk.Entry(time_frame, width=3)
        hour_entry.grid(row=0, column=0)
        ttk.Label(time_frame, text=":").grid(row=0, column=1)

        minute_entry = ttk.Entry(time_frame, width=3)
        minute_entry.grid(row=0, column=2)
        ttk.Label(time_frame, text=":").grid(row=0, column=3)

        second_entry = ttk.Entry(time_frame, width=3)
        second_entry.grid(row=0, column=4)

        ttk.Label(form_frame, text="Content:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        content_entry = ttk.Entry(form_frame, width=30)
        content_entry.grid(row=3, column=1, padx=5, pady=5)

        def check_message():
            timestamp = f"{date_picker.get()} {hour_entry.get()}:{minute_entry.get()}:{second_entry.get()}"
            key = f"{user_entry.get()}-{timestamp}-{content_entry.get()}"
            if self.app.bloom_filter.check(key):
                messagebox.showinfo("Result", "The message was sent.")
            else:
                messagebox.showinfo("Result", "The message was NOT sent.")

        ttk.Button(form_frame, text="Check", command=check_message).grid(row=4, columnspan=2, pady=10)



def main():
    alice = Account("Alice")
    bob = Account("Bob")

    app = MessageApp()

    # Create chatting windows
    alice_root = tk.Tk()
    bob_root = Toplevel(alice_root)

    # Set custom app icons
    set_window_icon(alice_root)
    set_window_icon(bob_root)

    user_icon = load_user_icon(alice_root)

    # Pass the larger icon to UserWindow
    UserWindow(alice_root, app, alice, bob, user_icon)
    UserWindow(bob_root, app, bob, alice, user_icon)

    # Create Provider Window
    provider_root = Toplevel(alice_root)
    set_window_icon(provider_root)
    ProviderWindow(provider_root, app)

    alice_root.mainloop()


if __name__ == "__main__":
    main()
