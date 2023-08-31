import tkinter as tk
import tkinter.messagebox
from PIL import ImageTk, Image
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = (ord(clear[i]) + ord(key_c)) % 256
        enc.append(enc_c)
    encoded_bytes = bytes(enc)
    encoded_string = base64.urlsafe_b64encode(encoded_bytes).decode()
    return encoded_string

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + enc[i] - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt_notes():
    title = title_label_input.get()
    secret = text_widget.get("1.0", "end")
    key = key_label_input.get()

    if len(title) == 0 or len(secret) == 0 or len(key) == 0:
        tkinter.messagebox.showwarning(title="error", message="please enter all informations")

    else:
        secret_encrypted = encode(key,secret)
        try:
            with open("secret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{secret_encrypted}")
        except FileNotFoundError:
            with open("secret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{secret_encrypted}")

        finally:
            title_label_input.delete(0, tk.END)
            text_widget.delete("1.0", "end")
            key_label_input.delete(0, tk.END)




