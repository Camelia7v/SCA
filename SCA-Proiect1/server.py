import socket
import time
import generator
import pickle
import threading

merchant_public_key = b"aceasta-e-cheia1"
payment_gateway_merchant_key = b"payment_gateway2"
merchant = "merchant_id".encode("UTF-8")
received_bytes = 1024
lock = threading.Lock()


# thread function
def client(connection, pg_connection):
    while True:
        client_data = connection.recv(received_bytes)
        if not client_data:
            break
        print("Data received from client:  ", client_data)
        if b"exit" in client_data:
            break

        init_vector_client_length = client_data[-2:].decode("UTF-8")
        print("IV length from client:      ", init_vector_client_length)
        init_vector_client = client_data[-int(init_vector_client_length) - 2:-2]
        print("IV from client:             ", init_vector_client)
        encrypted_client_key = client_data[0:-int(init_vector_client_length) - 2]
        client_key = generator.decrypt_message(encrypted_client_key, merchant_public_key, init_vector_client)
        print("Client Key:                 ", client_key)

        # e   d   n
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


        transaction_id = generator.generate_secret_key()
        transaction_id_signature = generator.sign_message(transaction_id, keyPair_client)
        print(f"Sid: {transaction_id}, Sid_signed: {transaction_id_signature}")
        print("Sid length: ", len(transaction_id))

        transaction_start, transaction_iv = generator.encrypt_message(
            str(transaction_id_signature).encode("UTF-8") + transaction_id
            + str(len(transaction_id)).encode("UTF-8"), client_key)
        transaction_start_package = transaction_start + transaction_iv + str(len(transaction_id)).encode("UTF-8")
        connection.send(transaction_start_package)
        time.sleep(1)

        # Exchange Sub-protocol

        encrypted_placement_message = connection.recv(received_bytes)
        print("Encrypted(PM,PO):           ", encrypted_placement_message)
        full_msg = pickle.loads(encrypted_placement_message)
        encrypted_placement_message, init_vector_merchant = full_msg
        pickled_placement_message = generator.decrypt_message(encrypted_placement_message, merchant_public_key,
                                                              init_vector_merchant)
        print("Pickled Placement Message:  ", pickled_placement_message)
        Encrypted_PM, PO = pickle.loads(pickled_placement_message)
        print("Encrypted PM:               ", Encrypted_PM)
        print("PO:                         ", PO)
        pickled_PO, sign_pickled_PO = PO
        if generator.check_signature(pickled_PO, sign_pickled_PO, keyPair_client):
            print("Signature of PO is correct!")
            _, transaction_id, amount, nonce = pickle.loads(pickled_PO)
            print(f"INFO: {transaction_id},\n {client_key}, \n {amount} ")
            merchant_to_pg = \
                [Encrypted_PM, generator.sign_message(pickle.dumps([transaction_id, client_key, amount]), keyPair_client)]
            pickled_merchant_to_pg = pickle.dumps(merchant_to_pg)
            encrypted_pickled_merchant_to_pg = generator.encrypt_message(pickled_merchant_to_pg,
                                                                         payment_gateway_merchant_key)
            pg_connection.send(pickle.dumps(encrypted_pickled_merchant_to_pg))
            time.sleep(1)
            print("Encrypted Pickled Merchant To PG: ", pickle.dumps(encrypted_pickled_merchant_to_pg))

            # response from Payment gateway
            encrypted_pickled_pg_response = pickle.loads(pg_connection.recv(2048))
            pickled_payment_gateway_response = generator.decrypt_message(encrypted_pickled_pg_response[0],
                                                                         merchant_public_key,
                                                                         encrypted_pickled_pg_response[1])
            payment_gateway_response = pickle.loads(pickled_payment_gateway_response)
            print("Payment GateWay Response:         ", payment_gateway_response)
            response, transaction_id_check, signature_resp_sid_amount_nc = payment_gateway_response
            if transaction_id == transaction_id_check \
                    and generator.check_signature(pickle.dumps([response, transaction_id, amount, nonce]),
                                                  signature_resp_sid_amount_nc, keyPair_client):
                print("Correct! Transaction ID and Signature are OK!")
                send_to_client = [response, transaction_id, signature_resp_sid_amount_nc]
                pickled_send_to_client = pickle.dumps(send_to_client)
                encrypted_pickled_send_to_client = pickle.dumps(
                    generator.encrypt_message(pickled_send_to_client, client_key))
                connection.send(encrypted_pickled_send_to_client)
                time.sleep(1)
    connection.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 8081))
    s.listen(2)

    connections = list()
    for i in range(0, 2):
        connections.append(s.accept())

    t = threading.Thread(target=client, args=(connections[0][0], connections[1][0]))
    t.start()
    t.join()


if __name__ == '__main__':
    main()
