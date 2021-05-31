from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import datetime

def load_csr(filepath):
  with open(filepath, 'rb') as f:
    csr = x509.load_pem_x509_csr(data=f.read(), backend=default_backend())

  if csr is None:
    return None
  return csr

def load_private_key():
  with open("./secret_key/key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
      key_file.read(),
      password='passphrase',
      backend=default_backend()
      )
    return private_key

def certificate_builder(csr):
  one_day = datetime.timedelta(1, 0, 0)
  private_key = load_private_key()

  public_key = private_key.public_key()
  builder = x509.CertificateBuilder()
  builder = builder.subject_name(csr.subject)
  builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA'),
  ]))
  for ext in csr.extensions:
    if isinstance(ext.value, x509.UnrecognizedExtension):
      oid = x509.ObjectIdentifier(ext.value.oid.dotted_string)
      value =  ext.value.value
      extension = x509.extensions.UnrecognizedExtension(oid, value)
      builder = builder.add_extension(extension, critical=False)

  builder = builder.not_valid_before(datetime.datetime.today() - one_day)
  builder = builder.not_valid_after(datetime.datetime(2019, 8, 2))
  builder = builder.serial_number(x509.random_serial_number())
  builder = builder.public_key(public_key)

  builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

  builder = builder.add_extension(extension=x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=True
  ) 
  certificate = builder.sign(
    private_key=private_key,
    algorithm=hashes.SHA256(),
    backend=default_backend()
  )
  return certificate


def main():
  private_key = load_private_key()
  print isinstance(private_key, rsa.RSAPrivateKey)

if __name__ == '__main__':
  main()