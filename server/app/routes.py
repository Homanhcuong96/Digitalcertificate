from app import app, db
from cryptography import x509
import os
from flask import Flask, request, redirect, url_for, flash, render_template, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from app.forms import LoginForm, RegistrationForm
from flask_login import current_user, login_user, logout_user, login_required
from cryptography.hazmat.primitives import serialization
from app.models import User
from app.handle_certificates import load_certificate, get_permission, valid_certificate
import json
from pprint import pprint

def allowed_file(filename):
  return '.' in filename and \
    filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
@app.route('/index')
@login_required
def index():
    #load list certificate
    file_list = os.listdir('./sources')
    return render_template('index.html', title='Home', file_list=file_list)

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
        filename = 'certificate_' + current_user.username + '.pem'
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('index'))
  return render_template('upload_file.html')

@app.route('/sources/<path:filename>', methods=['GET'])
@login_required
def sources(filename):
    file_list = os.listdir('./sources')
    if filename in file_list:
        file_path = os.getcwd()+'/sources/' + filename

        certificate, message = load_certificate(current_user.username)

        if certificate is None or valid_certificate(certificate) is not True:
            flash(message)
        else:
            with open('./app/role.json') as f:
                role = json.load(f)

            permission, message = get_permission(certificate, action='read', source=filename, role=role)
            if permission == True:
                with open(file_path) as f:
                    file_content = f.read()
                return file_content

            
            else:
                flash(message)
    else:
        flash('File not found') 
    return redirect(url_for('index'))