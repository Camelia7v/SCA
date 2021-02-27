from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from hashlib import sha512, sha256


def generate_nonce():
    return get_random_bytes(3)


def generate_secret_key():
    return get_random_bytes(16)


def encrypt_message(message, secret_key):
    cipher = AES.new(secret_key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))
    return encrypted_message, cipher.iv


def decrypt_message(ciphertext, secret_key, iv):
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message


def sign_message(message, key_pair):
    # keyPair = RSA.generate(bits=128)
    hashh = int.from_bytes(sha256(message).digest(), byteorder='big')
    signature = pow(hashh, key_pair[1], key_pair[2])
    return signature


def check_signature(message, signed_message, key_pair):
    hashh = int.from_bytes(sha256(message).digest(), byteorder='big')
    hashFromSignature = pow(signed_message, key_pair[0], key_pair[2])
    print("hashh ", hashh)
    print("hashFromS ", hashFromSignature)
    print("Signature valid:", hashh == hashFromSignature)
    return hashh == hashFromSignature
