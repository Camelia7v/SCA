import socket
import time
import generator

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8081))

# nu uita padarea pana la 16 octeti
payment_gateway_public_key = b"aceasta-e-cheia2"

s.send(b"hello")
