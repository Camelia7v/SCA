import socket
import time
import generator
import pickle

if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 8081))

    # nu uita padarea pana la 16 octeti
    payment_gateway_client_key = b"payment_gateway1"
    merchant_public_key = b"aceasta-e-cheia1"
    client_public_key = generator.generate_secret_key()
    print("Cheia client (simetrica):          ", client_public_key)
    encrypted_client_key, init_vector_merchant = generator.encrypt_message(client_public_key, merchant_public_key)
    print("Cheia client (simetrica) criptata: ", encrypted_client_key)
    setup_package = encrypted_client_key + init_vector_merchant + str(len(init_vector_merchant)).encode("UTF-8")
    print("Init vector client:                ", init_vector_merchant)

    client_socket.send(setup_package)
    time.sleep(1)

    keyPair = (65537,
               3249363879590348244407420679718315593018795480751143263920466234607101529772019536374827861603478921319831506727514840034690858795199938514646504336630322245054925344737718582037126944624844593456147038849661482375008046794626654844563691818605739128462552726119725459601547499991706849292343879494426890457,
               132351498183165104346630906828277967072512616172770463696429829470134004323597790152515285000563827263230452117092069652798965079466139447131378467812145100226243596817368541547326840920361199821160680478907933036643778629558968092867215707424031512767460064142069503331941992256746277252117637929853042299651
               )

    # recv info from server
    setup_package = client_socket.recv(1024)

    init_vector_merchant_length = setup_package[-2:].decode("UTF-8")
    print("Init Vector Mechant Size:          ", init_vector_merchant_length)
    init_vector_client = setup_package[-int(init_vector_merchant_length) - 2:-2]
    print("Init Vector Mechant :              ", init_vector_client)
    encrypted_transaction_id = setup_package[0:-int(init_vector_merchant_length) - 2]
    transaction_package = generator.decrypt_message(encrypted_transaction_id, client_public_key, init_vector_client)
    print("Transaction Package :              ", transaction_package)

    transaction_id_len = transaction_package[-2:].decode("UTF-8")
    print("...transaction id len:             ", transaction_id_len)
    transaction_id = transaction_package[-int(transaction_id_len)-2:-2]
    print("...transaction id:                 ", transaction_id)
    signature = int(transaction_package[0:-int(transaction_id_len)-2].decode("UTF-8"))
    print("...signature:                      ", signature)

    print(f"Is signature correct? {generator.check_signature(transaction_id, signature, keyPair)}")

    # new content- exchange subprotocol
    if generator.check_signature(transaction_id, signature, keyPair):
        print("Card Number:     ")
        card_number = input().encode("UTF-8")
        print("Card Expire Date:")
        card_expire_date = input().encode("UTF-8")
        print("Amount:          ")
        amount = input().encode("UTF-8")
        challenge_code = "test_ccode".encode("UTF-8")
        #  sid = transaction_id
        #  publicKC e public key client
        nonce = generator.generate_nonce()
        merchant = "merchant_id".encode("UTF-8")

        PI = [card_number,
              card_expire_date,
              challenge_code,
              transaction_id,
              amount,
              client_public_key,
              nonce,
              merchant
              ]
        print("Order Description:   ")
        order_description = input().encode("UTF-8")
        PO = [
            order_description,
            transaction_id,
            amount,
            nonce
        ]

        pickled_PI = pickle.dumps(PI)
        pickled_PO = pickle.dumps(PO)
        print(pickled_PO)
        PO = [pickled_PO, generator.sign_message(pickled_PO, keyPair)]
        PM = [pickled_PI, generator.sign_message(pickled_PI, keyPair)]
        encrypted_PM = generator.encrypt_message(pickle.dumps(PM), payment_gateway_client_key)
        placement_message = [encrypted_PM, PO]
        pickled_placement_message = pickle.dumps(placement_message)
        encrypted_placement_message, init_vector_merchant = generator.encrypt_message(pickled_placement_message, merchant_public_key)
        full_msg = [encrypted_placement_message, init_vector_merchant]
        client_socket.send(pickle.dumps(full_msg))

        time.sleep(1)

        response_from_gateway = client_socket.recv(2048)
        print("Response from gateway:", response_from_gateway)
        response_from_gateway = pickle.loads(response_from_gateway)
        decrypted_response_from_gateway = generator.decrypt_message(response_from_gateway[0], client_public_key, response_from_gateway[1])
        print("Decrypted Response:   ", decrypted_response_from_gateway)
        response, transaction_id_checker, signature_resp_sid_amount_nc = pickle.loads(decrypted_response_from_gateway)
        print("Response:             ", response)
        print("Transaction ID:       ", transaction_id_checker)
        print("Signature             ", signature_resp_sid_amount_nc)
        if transaction_id == transaction_id_checker \
                and generator.check_signature(pickle.dumps([response, transaction_id, amount, nonce]), signature_resp_sid_amount_nc, keyPair):
            print("Client Has received the responce and is CORRECT YESSSS!")
            time.sleep(1)
            client_socket.send(b"exit")

        # placement_info = b''
        # for info in PI:
        #     placement_info += info+b'*'
        #
        # # o * pentru elemente distincte dintrun sir si ** pentru obiect si signed_object//e un pic mai complicat :(
        # print(PI)
        # print("Placement Info:    ", placement_info)
        # # va trebui sa facem keypairs diferite pt client, payment gateway si merchant
        # placement_info_signature = str(generator.sign_message(placement_info, keyPair)).encode("UTF-8")
        # placement_message = placement_info + b"*" + placement_info_signature
        # placement_message, init_vector_pg = generator.encrypt_message(placement_message, payment_gateway_client_key)
        # placement_message = placement_message + b'**' + init_vector_pg
        # print("Placement Message: ", placement_message)
        # print("Order Description:   ")
        # order_description = input().encode("UTF-8")
        #
        # PO = [
        #     order_description,
        #     transaction_id,
        #     amount,
        #     nonce
        # ]
        # placement_object = b''
        # for desc in PO:
        #     placement_object += desc + b'*'
        # placement_object_signature = str(generator.sign_message(placement_object, keyPair)).encode("UTF-8")
        #
        # placement_message = placement_message + b'***' + placement_object + b'**' + placement_object_signature
        # placement_message, init_vector_merchant = generator.encrypt_message(placement_message, merchant_public_key)
        # placement_message = placement_message + b'****' + init_vector_merchant
        # print("Placement Message Full:", placement_message)
        # for i in placement_info.split(b'*'):
        #     print(i)
    else:
        client_socket.send(b"exit")

    # s.send(b"exit")
    # s.close()
