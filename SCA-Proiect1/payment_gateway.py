import socket
import time
import generator
import pickle
import pandas as pd

merchant_number = 1111111111111111
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
    if generator.check_signature(unpacked_PM[0], unpacked_PM[1], keyPair_client):
        print("UnPacked Placement Info:", pickle.loads(unpacked_PM[0]))
        print("Signature of PI is correct!")
        card_number, card_exp, ccode, transaction_id, amount, public_client_key, nonce, merchant_id = pickle.loads(
            unpacked_PM[0])

        print("Updating Database...")

        df = pd.read_csv("database.csv")
        for index in df.index:
            if df.loc[index, "CCODE"] == int(ccode) and df.loc[index, "CARD_DATE"] == card_exp \
                    and df.loc[index, "CARD_NR"] == int(card_number):
                df.loc[index, "AMOUNT"] = df.loc[index, "AMOUNT"] - int(amount)
                df.loc[df["CARD_NR"] == merchant_number, "AMOUNT"] = df["AMOUNT"] + int(amount)
                print("Database updated successfully!")
            else:
                print(df.loc[index, "CARD_DATE"], "=?", card_exp)
        df.to_csv("database.csv", index=False)

        print("PI: ")
        for i in pickle.loads(unpacked_PM[0]):
            print(i)
        # aici se testeaza ce era in PM la 4.
        # print(f"INFO: {transaction_id},\n {public_client_key}, \n {amount} ")
        if generator.check_signature(pickle.dumps([transaction_id, public_client_key, amount]),
                                     exchange_signature, keyPair_merchant):
            print("Signature of message from merchant is complete!")
            response = "transaction_is_ok_bro_or_sis"
            payment_gateway_response = [response, transaction_id, generator.sign_message(pickle.dumps([response,
                                                                                                       transaction_id,
                                                                                                       amount, nonce]),
                                                                                         keyPair_payment_gateway)]
            pickled_payment_gateway_response = pickle.dumps(payment_gateway_response)
            encrypted_pickled_pg_response = generator.encrypt_message(pickled_payment_gateway_response,
                                                                      merchant_public_key)
            encrypted_pickled_pg_response = pickle.dumps(encrypted_pickled_pg_response)
            print("Encryption: send to M then C", encrypted_pickled_pg_response)
            socket_to_merchant.send(encrypted_pickled_pg_response)
            time.sleep(1)
        else:
            print("Signature Incomplete")
