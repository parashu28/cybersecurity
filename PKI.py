from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import socket

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5555))
try: public_pem = client_socket.recv(4096)
except:print("failed")
challenge = client_socket.recv(4096)
print(challenge)
public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())

signature = private_key.sign(
    challenge,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()

)

print("\n")
print(signature)
client_socket.sendall(signature)


public_pem2 = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
client_socket.sendall(public_pem2)

client_socket.close

