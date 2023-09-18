#!/usr/bin/env python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import hashlib
import getpass

def decrypt_file(file_name, password):
    with open(file_name, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Generate the 256-bit encryption key using the salt and password
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

    # Create the AES Cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove the PKCS7 padding
    pad_length = plaintext[-1]
    plaintext = plaintext[:-pad_length]

    if not plaintext.startswith(b"MAGIC-STRING"):
        print("wrong password.. exiting..")
        sys.exit(1)

    plaintext = plaintext[len(b"MAGIC-STRING"):]

    # Write the decrypted content to a file
    with open(file_name.replace(".enc", "_decrypted"), 'wb') as f:
        f.write(plaintext)


if __name__ == '__main__':
    # Get the file name and password from the command line
    if len(sys.argv) != 2:
        print("Usage: python decrypt_file.py <file_name.enc> <password>")
        sys.exit(1)

    file_name = sys.argv[1]
    password = getpass.getpass("Enter password: ")

    decrypt_file(file_name, password)
