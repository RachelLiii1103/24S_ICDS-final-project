from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import random 
from chat_utils import *
import json
import string
import secrets

def create_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(12))
    #password = random.randint(100000,999999)
    return password

def encrypt_AES(plaintext, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 16, count=1000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return salt + cipher.nonce + ciphertext + tag

def decrypt_AES(ciphertext, password):
    salt = ciphertext[:16]
    nonce = ciphertext[16:32]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[32:-16]
    key = PBKDF2(password, salt, 16, count=1000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# test
#password = input("Password:")

password = create_password()

print("Password is:",create_password())
plaintext = "my_msg"

encrypted_data = encrypt_AES(plaintext, password)
print("Encrypted data:", encrypted_data)

decrypted_data = decrypt_AES(encrypted_data, password)
print("Decrypted data:", decrypted_data)



'''
encrypted_data = encrypt_AES(plaintext, password)
print("Encrypted data:", encrypted_data)

decrypted_data = decrypt_AES(encrypted_data, password)
print("Decrypted data:", decrypted_data)

'''