import socket
import time
import generator
import pickle
import re


if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 8081))

    payment_gateway_client_key = b"payment_gateway1"
    merchant_public_key = b"aceasta-e-cheia1"
    client_public_key = generator.generate_secret_key()
    print("Symmetric client key:           ", client_public_key)
    encrypted_client_key, init_vector_merchant = generator.encrypt_message(client_public_key, merchant_public_key)
    print("Encrypted symmetric client key: ", encrypted_client_key)
    setup_package = encrypted_client_key + init_vector_merchant + str(len(init_vector_merchant)).encode("UTF-8")
    print("IV from encrypted client key:   ", init_vector_merchant)

    client_socket.send(setup_package)
    time.sleep(1)

    keyPair_client = (65537,
                      3249363879590348244407420679718315593018795480751143263920466234607101529772019536374827861603478921319831506727514840034690858795199938514646504336630322245054925344737718582037126944624844593456147038849661482375008046794626654844563691818605739128462552726119725459601547499991706849292343879494426890457,
                      132351498183165104346630906828277967072512616172770463696429829470134004323597790152515285000563827263230452117092069652798965079466139447131378467812145100226243596817368541547326840920361199821160680478907933036643778629558968092867215707424031512767460064142069503331941992256746277252117637929853042299651
                      )
    keyPair_merchant = (65537,
                        18482560035306177533249753621229058828370491771606281576685890966513146880826388261426576289757885280292912625346234121720569404675747412869167836088862645634526774046555013386186848352793117095828969952215289610693967252244329867470931513167109728860540435457915945539215169672510168683641025182596988573473,
                        145354984444063314839590692368938659412190030308291305082951588352684652855446280898693623636223503313746793767277937476224114848908134983664798296850694969043258888836483417292630380941195584513367919380439878717643040448892460770813874462221074450835434917805014183713054288962538915179728109282561423011149
                        )
    keyPair_payment_gateway = (65537,
                               20052666353930300850320955327251971459545394019641537250464110239042540458311404534186341827802682672283882908798482531932318652802037340236219211781850733703520564696600447916660974117762254504665290805098116291001866925892560192587296790069461983319820012914108126269158622829539076603255843079235726324623,
                               107478355742181977250254299675494782542974973450439372462373043773145039788702066567734228940397007916047338719601402551236832349105468915727752891641558109869246740387884437096064926809940546667891969475429661322144419914362418875001266049551282603570322322401772315373342866042474278545583413923948461145569
                               )

    # receiving info from server
    setup_package = client_socket.recv(1024)

    init_vector_merchant_length = setup_package[-2:].decode("UTF-8")
    print("IV size from merchant:          ", init_vector_merchant_length)
    init_vector_client = setup_package[-int(init_vector_merchant_length) - 2:-2]
    print("IV from merchant:               ", init_vector_client)
    encrypted_transaction_id = setup_package[0:-int(init_vector_merchant_length) - 2]
    transaction_package = generator.decrypt_message(encrypted_transaction_id, client_public_key, init_vector_client)
    print("Transaction Package:            ", transaction_package)

    transaction_id_len = transaction_package[-2:].decode("UTF-8")
    print("Transaction ID length:          ", transaction_id_len)
    transaction_id = transaction_package[-int(transaction_id_len) - 2:-2]
    print("Transaction ID:                 ", transaction_id)
    signature = int(transaction_package[0:-int(transaction_id_len) - 2].decode("UTF-8"))
    print("Signature:                      ", signature)

    print(f"Is signature correct? {generator.check_signature(transaction_id, signature, keyPair_client)}")

    # Exchange Sub-protocol

    if generator.check_signature(transaction_id, signature, keyPair_client):
        card_number = input("Card Number:       ")
        while not re.match(r"\d{16}", card_number):
            card_number = input("Incorrect! Try again:       ")
        card_expire_date = input("Card Expire Date:  ")
        while not re.match(r"\d{2}/\d{2}", card_expire_date):
            card_expire_date = input("Incorrect! Try again:       ")
        amount = input("Amount:            ")
        while not re.match(r"\d+", amount):
            amount = input("Incorrect! Try again:       ")
        challenge_code = input("Challenge code:            ")
        while not re.match(r"\d{3}", challenge_code):
            challenge_code = input("Incorrect! Try again:       ")
        # publicKC e client public key
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
        order_description = input("Order Description: ")
        while not re.match(r"[A-Z]*[a-z]+ \d+RON x\d+", order_description):
            order_description = input("Incorrect! Try again:       ")
        PO = [order_description,
              transaction_id,
              amount,
              nonce
              ]

        pickled_PI = pickle.dumps(PI)
        pickled_PO = pickle.dumps(PO)
        PO = [pickled_PO, generator.sign_message(pickled_PO, keyPair_client)]
        PM = [pickled_PI, generator.sign_message(pickled_PI, keyPair_client)]
        encrypted_PM = generator.encrypt_message(pickle.dumps(PM), payment_gateway_client_key)
        placement_message = [encrypted_PM, PO]
        pickled_placement_message = pickle.dumps(placement_message)
        encrypted_placement_message, init_vector_merchant = generator.encrypt_message(pickled_placement_message,
                                                                                      merchant_public_key)
        full_msg = [encrypted_placement_message, init_vector_merchant]
        client_socket.send(pickle.dumps(full_msg))
        time.sleep(1)

        start_time = time.time()
        response_from_gateway = client_socket.recv(2048)
        timer = time.time() - start_time
        print("Nr. de sec. in care clientul primeste raspuns de la Payment gateway: ", timer)
        # daca in 10 secunde nu primeste raspuns, isi inchide conexiunea
        if timer > 10:
            print("Time exceeded !!!")
            client_socket.send(b"exit")
            client_socket.close()
        else:
            print("Response from Payment gateway: ", response_from_gateway)
            response_from_gateway = pickle.loads(response_from_gateway)
            decrypted_response_from_gateway = generator.decrypt_message(response_from_gateway[0], client_public_key,
                                                                        response_from_gateway[1])
            print("Decrypted response:            ", decrypted_response_from_gateway)
            response, transaction_id_checker, signature_resp_sid_amount_nc = pickle.loads(decrypted_response_from_gateway)
            print("Response from PG:              ", response)
            print("Transaction ID:                ", transaction_id_checker)
            print("Signature:                     ", signature_resp_sid_amount_nc)
            if transaction_id == transaction_id_checker \
                    and generator.check_signature(pickle.dumps([response, transaction_id, amount, nonce]),
                                                  signature_resp_sid_amount_nc, keyPair_client):
                print("Client has received the response and it is CORRECT!")
                client_socket.send(b"exit")
    else:
        client_socket.send(b"exit")
