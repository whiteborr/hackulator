from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

def load_cert_key(cert_path, key_path, ca_path, password=None):
    with open(cert_path, "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read(), backend=default_backend())
    with open(key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password, backend=default_backend())
    with open(ca_path, "rb") as ca_file:
        ca_cert = load_pem_x509_certificate(ca_file.read(), backend=default_backend())
    return cert, private_key, ca_cert

def sign_payload(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())