from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from app import app
from app.certificate_builder import load_private_key
import datetime

one_day = datetime.timedelta(1, 0, 0)
private_key = load_private_key()
builder = x509.CertificateRevocationListBuilder()
builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io CA'),]))
builder = builder.last_update(datetime.datetime.today())
builder = builder.next_update(datetime.datetime.today() + one_day)
revoked_cert = x509.RevokedCertificateBuilder().serial_number(
  333
).revocation_date(
  datetime.datetime.today()
).build(default_backend())
builder = builder.add_revoked_certificate(revoked_cert)

crl = builder.sign(
  private_key=private_key, algorithm=hashes.SHA256(),
  backend=default_backend()
)
with open('crl_lits.pem', "wb") as f:
  f.write(crl.public_bytes(serialization.Encoding.PEM))