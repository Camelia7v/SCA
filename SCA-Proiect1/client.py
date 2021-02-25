import socket
import time
import generator

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8081))

# nu uita padarea pana la 16 octeti
merchant_public_key = b"aceasta-e-cheia1"

client_key = generator.generate_secret_key()
print("Cheia simetrica: ", client_key)
encrypted_symmetric_key, iv1 = generator.encrypt_message(client_key, merchant_public_key)
print("Cheia simetrica criptata: ", encrypted_symmetric_key)
package = encrypted_symmetric_key + iv1 + str(len(iv1)).encode("UTF-8")
print(iv1)
s.send(package)
time.sleep(1)

keyPair = (65537,
           3249363879590348244407420679718315593018795480751143263920466234607101529772019536374827861603478921319831506727514840034690858795199938514646504336630322245054925344737718582037126944624844593456147038849661482375008046794626654844563691818605739128462552726119725459601547499991706849292343879494426890457,
           132351498183165104346630906828277967072512616172770463696429829470134004323597790152515285000563827263230452117092069652798965079466139447131378467812145100226243596817368541547326840920361199821160680478907933036643778629558968092867215707424031512767460064142069503331941992256746277252117637929853042299651
           )

package = s.recv(1024)

iv_len = package[-2:].decode("UTF-8")
print(iv_len)
iv = package[-int(iv_len) - 2:-2]
print(iv)
encrypted_message = package[0:-int(iv_len) - 2]
transaction_package = generator.decrypt_message(encrypted_message, client_key, iv)
print("tran ", transaction_package)

transaction_id_len = transaction_package[-2:].decode("UTF-8")
print("...transaction id len: ", transaction_id_len)
transaction_id = transaction_package[-int(transaction_id_len)-2:-2]
print("...transaction id: ", transaction_id)
signature = int(transaction_package[0:-int(transaction_id_len)-2].decode("UTF-8"))
print("...signature: ", signature)

print(f"Is signature correct? {generator.check_signature(transaction_id, signature, keyPair)}")


# s.send(b"exit")
# s.close()
