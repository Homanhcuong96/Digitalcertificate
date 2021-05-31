from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_private_key():
  with open("../secret_key/key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
      key_file.read(),
      password='passphrase',
      backend=default_backend()
      )
    return private_key

with open('certificate_hung.pem', 'rb') as cert_file:
  data = cert_file.read()

cert = x509.load_pem_x509_certificate(data, default_backend())
private_key = load_private_key()

public_key = private_key.public_key()
verifier = public_key.verifier(cert.signature, padding.PKCS1v15(),cert.signature_hash_algorithm)
data = cert.tbs_certificate_bytes
verifier.update(data)
try:
  verifier.verify()
  print 'True'
except Exception:
  print 'False'