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

def decode_secret():
    secret = text_widget.get("1.0", "end")
    key = key_label_input.get()

    if len(secret) == 0 or len(key) == 0:
        tkinter.messagebox.showwarning(title="error", message="please enter all informations")

    else:
        try:
            dec_secret = decode(key,secret)
            text_widget.delete("1.0", "end")
            text_widget.insert("1.0",dec_secret)
        except:
            tk.messagebox.showwarning(title="error",message="please enter your encrypted message")

window = tk.Tk()
window.title("My Secret Notes")
window.config(padx=20, pady=20)
window.geometry("400x600")
window.configure(bg='black')

key_image = Image.open("img.png")
resized_image = key_image.resize((160, 80))
photo = ImageTk.PhotoImage(resized_image)

image_label = tk.Label(window, image=photo, bg="yellow")
image_label.pack()

title_label = tk.Label(text="Enter Your Title", bg="yellow", foreground="black")
title_label.pack(pady=5)

title_label_input = tk.Entry(width=50)
title_label_input.pack()

text_label = tk.Label(text="Enter Your Secret", bg="yellow", foreground="black")
text_label.pack(pady=5)

text_widget = tk.Text(window, height=15)
text_widget.pack(pady=5)

key_label = tk.Label(text="Enter master key", bg="yellow", foreground="black")
key_label.pack()

key_label_input = tk.Entry(width=50)
key_label_input.pack(pady=5)

save_enc_button = tk.Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_enc_button.pack(pady=5)

dec_button = tk.Button(text="Decrypt",command=decode_secret)
dec_button.pack(pady=5)

result_label = tk.Label(text="", bg="gray10", foreground="white")
result_label.pack()

window.mainloop()


