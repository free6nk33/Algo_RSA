import tkinter as tk
from tkinter import filedialog, messagebox, Text
import random
from sympy import isprime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64

def generate_prime_above(minimum):
    while True:
        num = random.randint(minimum + 1, 1000)
        if isprime(num):
            return num

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Inverse modulaire impossible")
    return x % m

def gen_key():
    p = generate_prime_above(100)
    q = generate_prime_above(100)
    n = p * q
    phi = (p - 1) * (q - 1)
    c = random.choice([3, 65537])  
    d = mod_inverse(c, phi)  
    return n, c, d


def create_characters():
    return {char: idx + 1 for idx, char in enumerate("abcdefghijklmnopqrstuvwxyz!?.' ")}


def encode_message(message, c, n):
    mapping = create_characters()
    encoded_numbers = [
        pow(mapping[char], c, n) 
        for char in message if char in mapping
    ]
    return encoded_numbers


def decode_message(encoded_numbers, d, n):
    reversed_mapping = {v: k for k, v in create_characters().items()}
    decoded_message = "".join(
        reversed_mapping.get(pow(int(num), d, n), '') 
        for num in encoded_numbers
    )
    return decoded_message


def encrypt_aes(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  


def decrypt_aes(encrypted_data, key):
    iv = encrypted_data[:16]  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

def encode_base64(data):
    return base64.b64encode(data).decode()

def decode_base64(encoded_data):
    return base64.b64decode(encoded_data)


class CHIFFREMENTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Application CHIFFREMENT/ENCODAGE")
        
        self.n, self.c, self.d = gen_key()  
        self.aes_key = os.urandom(32)  

        self.keys_display = Text(root, height=10, width=50)
        self.keys_display.pack(pady=10)
        self.keys_display.insert(tk.END, f"Key pub (n, c): ({self.n}, {self.c})\Key private (d): {self.d}\n\n")
        self.keys_display.insert(tk.END, f"Key AES (256 bits): {self.aes_key.hex()}\n\n")

        self.message_input = Text(root, height=5, width=50)
        self.message_input.pack(pady=10)
        self.message_input.insert(tk.END, "Entrez votre message ici...")

        self.encode_button_rsa = tk.Button(root, text="Chiffrer avec RSA", command=self.chiffrer_rsa)
        self.encode_button_rsa.pack(pady=5)

        self.decode_button_rsa = tk.Button(root, text="Dechiffrer avec RSA", command=self.dechiffrer_rsa)
        self.decode_button_rsa.pack(pady=5)

        self.encode_button_aes = tk.Button(root, text="Chiffrer avec AES", command=self.chiffrer_aes)
        self.encode_button_aes.pack(pady=5)

        self.decode_button_aes = tk.Button(root, text="Dechiffrer avec AES", command=self.dechiffrer_aes)
        self.decode_button_aes.pack(pady=5)

        self.encode_button_base64 = tk.Button(root, text="Encoder en Base64", command=self.encoder_base64)
        self.encode_button_base64.pack(pady=5)

        self.decode_button_base64 = tk.Button(root, text="Decoder de Base64", command=self.decoder_base64)
        self.decode_button_base64.pack(pady=5)

        self.result_display = Text(root, height=10, width=50)
        self.result_display.pack(pady=10)

    def chiffrer_rsa(self):
        message = self.message_input.get("1.0", tk.END).strip()
        encoded_numbers = encode_message(message, self.c, self.n)
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, "Message chiffre avec RSA :\n" + "\n".join(map(str, encoded_numbers)))

    def dechiffrer_rsa(self):
        try:
            encoded_numbers = list(map(int, self.result_display.get("1.0", tk.END).strip().split()))
            decoded_message = decode_message(encoded_numbers, self.d, self.n)
            self.result_display.delete(1.0, tk.END)
            self.result_display.insert(tk.END, "Message dechiffre avec RSA :\n" + decoded_message)
        except ValueError:
            messagebox.showerror("Erreur", "Veuillez entrer des nombres valides pour le déchiffrement RSA.")

    def chiffrer_aes(self):
        message = self.message_input.get("1.0", tk.END).strip()
        encrypted_data = encrypt_aes(message, self.aes_key)
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, "Message chiffre avec AES (en hexadécimal) :\n" + encrypted_data.hex())

    def dechiffrer_aes(self):
        try:
            hex_input = self.result_display.get("1.0", tk.END).strip()
            encrypted_data = bytes.fromhex(hex_input)
            decrypted_message = decrypt_aes(encrypted_data, self.aes_key)
            self.result_display.delete(1.0, tk.END)
            self.result_display.insert(tk.END, "Message dechiffre avec AES :\n" + decrypted_message)
        except ValueError:
            messagebox.showerror("Erreur", "Veuillez entrer des données valides pour le déchiffrement AES.")

    def encoder_base64(self):
        message = self.message_input.get("1.0", tk.END).strip()
        encoded_message = encode_base64(message.encode())
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, "Message encode en Base64 :\n" + encoded_message)

    def decoder_base64(self):
        try:
            base64_input = self.result_display.get("1.0", tk.END).strip()
            decoded_message = decode_base64(base64_input).decode()
            self.result_display.delete(1.0, tk.END)
            self.result_display.insert(tk.END, "Message decode de Base64 :\n" + decoded_message)
        except Exception as e:
            messagebox.showerror("Erreur", "Veuillez entrer une chaine Base64 valide.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CHIFFREMENTApp(root)
    root.mainloop()
