from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os, requests
from app import app

class Attribute:
  def __init__(self, oid, value_range, datatype='integer'):
    self.oid = oid
    self.datatype = datatype
    self.value_range = value_range

  def get_value_extension(self, oid, value):
    if self.oid == oid:
      if value in self.value_range:
        return value
    return None

def load_certificate(username):
  certificate_list = os.listdir('./certificates')
  owner_cerfiticate = 'certificate_' + username + '.pem'
  if owner_cerfiticate in certificate_list:
    certificate_file_path = os.path.join(app.config['UPLOAD_FOLDER'], owner_cerfiticate)
    with open(certificate_file_path, 'rb') as f:
      certificate = x509.load_pem_x509_certificate(data=f.read(), backend=default_backend())
      if certificate is None:
        return None, 'Certificate error'
      status_code, message = get_valid_certificate(certificate_file_path)
      if status_code != 200:
        return None, message
      return certificate, message
  return None, 'Certificate not found'

def valid_certificate(certificate):
  public_key = certificate.public_key()
  verifier = public_key.verifier(certificate.signature, padding.PKCS1v15(),certificate.signature_hash_algorithm)
  data = certificate.tbs_certificate_bytes
  verifier.update(data)
  try:
    verifier.verify()
    return True
  except Exception:
    return False

def get_permission(certificate, action, source, role):
  attributes = []
  permission_required = None
  for element in role["sources"]:
    if element["filename"] == source:
      actions = element["actions"]
      for element in actions:
        if element["type"] == action:
          permission_required = element["level"]

  if permission_required == None:
    return False, "Source are not defined"
  for element in role["attributes"]:
    attribute = Attribute(element["oid"], element['value_range'])
    attributes.append(attribute)

  extensions = certificate.extensions
  values = []
  for extension in extensions:
    if isinstance(extension.value, x509.UnrecognizedExtension):
      for attribute in attributes:
        value = attribute.get_value_extension(extension.value.oid.dotted_string, int(extension.value.value))
        if value != None:
          values.append(value)
          break


  if sum(values) >= permission_required:
    return True, ""
  return False, "Permission not accepted"

def get_valid_certificate(certificate_file_path):
  url = 'http://127.0.0.1:5003/verify'
  file = {'filename':open(certificate_file_path, 'rb')}
  r = requests.post(url, files=file)
  message = eval(r.text)['message']
  status_code = r.status_code
  return status_code, message