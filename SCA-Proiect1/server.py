import socket
import time
from _dummy_thread import start_new_thread
from Cryptodome.PublicKey import RSA
import generator
import threading

public_key = b"aceasta-e-cheia1"
received_bytes = 1024
lock = threading.Lock()


# thread function
def client(connection):
    while True:
        data = connection.recv(received_bytes)
        if not data:
            break
        print("Received: ", data)

        iv_len = data[-2:].decode("UTF-8")
        print(iv_len)
        iv = data[-int(iv_len) - 2:-2]
        print(iv)
        encrypted_symmetric_key = data[0:-int(iv_len) - 2]
        client_key = generator.decrypt_message(encrypted_symmetric_key, public_key, iv)
        print("client_key: ", client_key)

        # keyPair = RSA.generate(bits=1024)
        # print("ATENTIE:", keyPair.e, keyPair.d, keyPair.n)
        #           e   d   n
        keyPair = (65537,
                   3249363879590348244407420679718315593018795480751143263920466234607101529772019536374827861603478921319831506727514840034690858795199938514646504336630322245054925344737718582037126944624844593456147038849661482375008046794626654844563691818605739128462552726119725459601547499991706849292343879494426890457,
                   132351498183165104346630906828277967072512616172770463696429829470134004323597790152515285000563827263230452117092069652798965079466139447131378467812145100226243596817368541547326840920361199821160680478907933036643778629558968092867215707424031512767460064142069503331941992256746277252117637929853042299651
                   )
        transaction_id = generator.generate_secret_key()
        transaction_id_signature = generator.sign_message(transaction_id, keyPair)
        print(f"Sid:{transaction_id}, Sid_sign: {transaction_id_signature}")
        print("Sid len: ", len(transaction_id))

        transaction_start, transaction_iv = generator.encrypt_message(
            str(transaction_id_signature).encode("UTF-8") + transaction_id \
            + str(len(transaction_id)).encode("UTF-8"), client_key)
        transaction_start_package = transaction_start + transaction_iv + str(len(transaction_id)).encode("UTF-8")
        connection.send(transaction_start_package)
        time.sleep(1)

        if b"exit" in data:
            break
            
    connection.close()


def payment_gateway(connection):
    while True:
        data = connection.recv(received_bytes)
        if not data:
            break
        print("Received: ", data)


def Main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 8081))
    s.listen(2)

    connections = list()
    for i in range(0, 2):
        connections.append(s.accept())

    t = threading.Thread(target=client, args=(connections[0][0],))
    t.start()
    t.join()

    t = threading.Thread(target=payment_gateway, args=(connections[1][0],))
    t.start()
    t.join()

    # while True:
    #     (connection, address) = s.accept()
    #     print("Connected address:", address)
    #
    #     # lock acquired by client
    #     lock.acquire()
    #
    #     # Start a new thread and return its identifier
    #     t = threading.Thread(target=client, args=(connection,))
    #     t.start()
    #     t.join()
    #     # start_new_thread(client, (connection,))
    #     # start_new_thread(payment_gateway, (connection,))
    #
    #     t = threading.Thread(target=payment_gateway, args=(connection,))
    #     t.start()
    #     t.join()

    # connection.close()
    # print("Server closed")


if __name__ == '__main__':
    Main()
