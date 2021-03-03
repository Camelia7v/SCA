from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from hashlib import sha256


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
    return hashh == hashFromSignature


if __name__ == '__main__':
    # import re
    # if not re.match(r"([A-Z]*[a-z]+ \d+RON x\d+)+", "Matura 10RON x10 Ceva 12RON x101"):
    #     print("Naspa")
    # else: print("Merge")
    # import csv
    # amount = 10
    # with open('database.csv', mode='r+') as csv_file:
    #     csv_reader = csv.reader(csv_file, delimiter=',')
    #     l_csv_reader = list(csv_reader)
    #     line_count = 1
    #     writer = csv.writer(csv_file)
    #     # for row in l_csv_reader:
    #     #     print(row[1], " ,",  row[5])
    #     #     if row[1] == "Client" and int(row[5]) >= amount:
    #     #         for m_row in l_csv_reader:
    #     #             print(m_row)
    #     #             if m_row[1] == 'Merchant':
    #     #                 m_row[5] = str(int(m_row[5]) + amount)
    #     #                 row[5] = str(int(row[5]) - amount)
    #     l_csv_reader[0][1] = '30'
    #     writer.writerows(l_csv_reader)

    import pandas as pd

    print("Updating Database...")

    df = pd.read_csv("database.csv")
    print(df["TYPE"] == "Client")
    for index in df.index:
            print(index)
            if df.loc[index, "CCODE"] == 123 and df.loc[index, "CARD_DATE"] == "12/22" and df.loc[index, "CARD_NR"] == 1111222233334444:
                df.loc[index, "AMOUNT"] = df.loc[index, "AMOUNT"] - 10
                df.loc[df["CARD_NR"] == 1111111111111111, "AMOUNT"] = df["AMOUNT"] + 10
            else:
                print(df.loc[index, "CARD_DATE"], "=?", "12/22")
    df.to_csv("database.csv", index=False)
