import socket
import time
import generator
import pickle

keyPair = (65537,
           3249363879590348244407420679718315593018795480751143263920466234607101529772019536374827861603478921319831506727514840034690858795199938514646504336630322245054925344737718582037126944624844593456147038849661482375008046794626654844563691818605739128462552726119725459601547499991706849292343879494426890457,
           132351498183165104346630906828277967072512616172770463696429829470134004323597790152515285000563827263230452117092069652798965079466139447131378467812145100226243596817368541547326840920361199821160680478907933036643778629558968092867215707424031512767460064142069503331941992256746277252117637929853042299651
           )
merchant_id_check_client = b"merchant"
merchant_public_key = b"aceasta-e-cheia1"
payment_gateway_merchant_key = b"payment_gateway2"
payment_gateway_client_key = b"payment_gateway1"
socket_to_merchant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_to_merchant.connect(("127.0.0.1", 8081))
msg_size = 2048
payment_gateway_public_key = b"aceasta-e-cheia2"

if __name__ == '__main__':
    encrypted_message_from_merchant = socket_to_merchant.recv(msg_size)
    print("Encrypted Message:      ", encrypted_message_from_merchant)
    encrypted_message_from_merchant = pickle.loads(encrypted_message_from_merchant)
    message_from_merchant = pickle.loads(
        generator.decrypt_message(encrypted_message_from_merchant[0], payment_gateway_merchant_key,
                                  encrypted_message_from_merchant[1]))
    print("Decrypted Message:      ", message_from_merchant)
    _, exchange_signature = message_from_merchant
    decrypted_PM = generator.decrypt_message(message_from_merchant[0][0], payment_gateway_client_key,
                                             message_from_merchant[0][1])
    print("PM:                     ", decrypted_PM)
    print("Exchange Signature:     ", exchange_signature)
    unpacked_PM = pickle.loads(decrypted_PM)
    print("UnPacked PM:            ", unpacked_PM)
    unpacked_PI = pickle.loads(unpacked_PM[0])
    print("Unpacked PI:            ", unpacked_PI)
    if generator.check_signature(unpacked_PM[0], unpacked_PM[1], keyPair):
        print("UnPacked Placement Info:", pickle.loads(unpacked_PM[0]))
        print("Signature of PI is correct!")
        card_number, card_exp, ccode, transaction_id, amount, public_client_key, nonce, merchant_id = pickle.loads(
            unpacked_PM[0])
        print("PI: ")
        for i in pickle.loads(unpacked_PM[0]):
            print(i)
        # aici se testeaza ce era in PM la 4. +
        if generator.check_signature(pickle.dumps([transaction_id, public_client_key, amount]),
                                     message_from_merchant[1], keyPair):
            print("Signature of message from merchant is complete!")
            response = "transaction_is_ok_bro_or_sis"
            payment_gateway_response = [response, transaction_id, generator.sign_message(pickle.dumps([response,
                                                                                                       transaction_id,
                                                                                                       amount, nonce]),
                                                                                         keyPair)]
            pickled_payment_gateway_response = pickle.dumps(payment_gateway_response)
            encrypted_pickled_pg_response = generator.encrypt_message(pickled_payment_gateway_response,
                                                                      merchant_public_key)
            encrypted_pickled_pg_response = pickle.dumps(encrypted_pickled_pg_response)
            socket_to_merchant.send(encrypted_pickled_pg_response)
            time.sleep(1)
