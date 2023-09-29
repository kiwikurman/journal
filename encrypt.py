#!/usr/bin/env python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import hashlib  # This was missing in the original example for PBKDF2
import getpass

from decrypt import decrypt_file

'''
i want to make sure i didn't make a mistake with the password before encrypting,
without writing the password in the code
so i want to compare the encrypted text with the given password 
to a previously encrypted magic_string with the same password
there will be an issue with the random salt i think.. and it's less safe..
'''


def encrypt_file(file_name, password):
    # Read the file
    with open(file_name, 'rb') as f:
        plaintext = f.read()

    plaintext = b"MAGIC-STRING" + plaintext
    # Generate a 256-bit encryption key from the password
    # We use PBKDF2 with HMAC-SHA-256, 100000 iterations, and a random salt.
    salt = os.urandom(16)
    backend = default_backend()
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

    # Generate a random 128-bit IV (Initialization Vector)
    iv = os.urandom(16)

    # Create an AES Cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=backend
    )
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size with PKCS7
    pad_length = 16 - len(plaintext) % 16
    plaintext += bytes([pad_length]) * pad_length

    # Perform the encryption
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the salt, IV and ciphertext to the output file
    with open(file_name + ".enc", 'wb') as f:
        for x in [salt, iv, ciphertext]:
            f.write(x)


def verify_password(p):
    decrypt_file("magic.enc", p)
    # i've written a whole function to check if the string in the file is as expected
    # turns out encrypt is adding the magic string - and decrypt is looking for it.. so any string would do
    # decrypt just terminates the whole script if the magic string doesn't match
    # it makes brute force attack easier with clear pass/fail result.. but i'm ok with that

if __name__ == '__main__':
    # Get the file name and password from the command line
    if len(sys.argv) != 2:
        print("Usage: python encrypt_file.py <file_name> <password>")
        sys.exit(1)

    file_name = sys.argv[1]
    password = getpass.getpass("Enter password: ")
    verify_password(password)
    encrypt_file(file_name, password)
    os.remove(file_name)
