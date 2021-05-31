from app import app, db
import os
from flask import Flask, request, redirect, url_for, flash, render_template, send_from_directory, Response
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from app.forms import LoginForm, RegistrationForm
from flask_login import current_user, login_user, logout_user, login_required
from app.certificate_builder import load_csr, certificate_builder, load_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
from app.models import User

def allowed_file(filename):
  return '.' in filename and \
    filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
@app.route('/index')
@login_required
def index():
    #load list certificate
    certificate_list = os.listdir('./certificates')
    owner_cerfiticate = 'certificate_' + current_user.username + '.pem'
    return render_template('index.html', title='Home', certificate_list=certificate_list, owner_cerfiticate=owner_cerfiticate)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/download/<path:filename>', methods=['GET'])
@login_required
def download(filename):
    root_dir = os.path.dirname(os.getcwd())
    forder_name = os.path.join(root_dir, 'CA', 'certificates')
    return send_from_directory(forder_name, filename)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
  if request.method == 'POST':
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
      flash('No selected file')
      return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = 'csr_' + current_user.username + '.pem'
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('index'))
  return render_template('upload_file.html')

@app.route('/handle', methods=['GET'])
@login_required
def handle():
    csr_list = os.listdir('./CSR')
    csr_file_name = 'csr_' + current_user.username + '.pem'
    if csr_file_name in csr_list:
        csr_file_path = os.path.join(app.config['UPLOAD_FOLDER'], csr_file_name)
        csr_file = load_csr(csr_file_path)
        if csr_file != None:
            certificate_list = os.listdir('./certificates')
            owner_cerfiticate = 'certificate_' + current_user.username + '.pem'
            if owner_cerfiticate in certificate_list:
                flash('User already have certificate')
                return redirect(url_for('index'))
            else:   
                certificate = certificate_builder(csr_file)
                if certificate != None:
                    certificate_file_name = 'certificate_' + current_user.username + '.pem'
                    certificate_file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], certificate_file_name)
                    with open(certificate_file_path, "wb") as f:
                        f.write(certificate.public_bytes(serialization.Encoding.PEM))
                    flash('Success create certificate')
                else:
                    flash('Faile')
        else:
            flash('CSR file error')
        return redirect(url_for('index'))
    else:
        flash('CSR not found')
        return redirect(url_for('index'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    file = request.files['filename']

    certificate = x509.load_pem_x509_certificate(data=file.read(), backend=default_backend())
    if certificate is None:
        return Response("{'message':'Cannot read certificate'}", status=202, mimetype='application/json')
    #load crl_list
    with open('./CRL/crl_list.pem', 'rb') as f:
        crl_list = x509.load_pem_x509_crl(data=f.read(), backend=default_backend())

    list_revocation_serial_number = []
    for r in crl_list:
        list_revocation_serial_number.append(r.serial_number)
    if certificate.serial_number in list_revocation_serial_number:
        return Response("{'message':'Certificate has been revoked'}", status=202, mimetype='application/json')
    else:
        return Response("{'message':'success'}", status=200, mimetype='application/json')

@app.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete(filename):
    certificate_list = os.listdir('./certificates')
    certificate_file_name = filename
    if certificate_file_name not in certificate_list:
        flash("Certificate not found")
    else:
        certificates_path =  os.path.join(app.config['DOWNLOAD_FOLDER'], certificate_file_name)
        with open(certificates_path, 'rb') as f:
            certificate = x509.load_pem_x509_certificate(data=f.read(), backend=default_backend())
        if certificate == None:
            flash("Cannot read Certificate")
            return redirect(url_for('index'))

        with open('./CRL/crl_list.pem', 'rb') as f:
            old_crl_list = x509.load_pem_x509_crl(data=f.read(), backend=default_backend())

        crl = x509.CertificateRevocationListBuilder().issuer_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA'),
                ])
            ).last_update(
                datetime.datetime.utcnow()
            ).next_update(
                datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
            )

        for cert in old_crl_list:
            crl = crl.add_revoked_certificate(cert)
        #Add new revoked certificate
        new_revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            certificate.serial_number
            ).revocation_date(
            datetime.datetime.today()
            ).build(default_backend())

        print certificate.serial_number
        crl = crl.add_revoked_certificate(new_revoked_cert)

        private_key = load_private_key()
        crl_list = crl.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        with open('./CRL/crl_list.pem', "wb") as f:
            f.write(crl_list.public_bytes(serialization.Encoding.PEM))

        os.remove(certificates_path)
        flash("Revocate certifucate success!")
    return redirect(url_for('index'))