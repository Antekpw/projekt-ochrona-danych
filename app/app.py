from flask import Flask,render_template,request,redirect,session
from flask_session import Session
from database import db
from models.models import *
import psycopg2
from utils import validate_password
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.PublicKey import RSA
from utils import validate_password
from flask_session import Session
import os
import pyotp
import qrcode
import io
import base64
app = Flask(__name__)
app.secret_key = os.urandom(32)  # KLUCZ DO PODPISYWANIA COOKIE

#session = Session(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://antek:haslo123@localhost:5432/mail_db'
# app.config['SESSION_TYPE'] = 'filesystem'
# app.config['SESSION_PERMANENT'] = False
# app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True 
db.init_app(app)
Session(app)
@app.route("/")
def hello_world():
    return "hello nigga"

@app.route("/register",methods = ['GET','POST'])
def register():
    msg = ''
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        
        if not validate_password(password):
            time.sleep(0.5)
            msg = 'Hasło nie spełnia wymagań bezpieczeństwa'
            return render_template('register.html',msg=msg)

        ph = PasswordHasher()
        encrypted_password = ph.hash(password) 

        key = RSA.generate(2048)

        private_key = key.export_key(passphrase=password,format='DER',pkcs=8) #format binarny bez ----, pcks=8 bo z 1 nie dziala
        public_key = key.public_key().export_key(format='DER')
        totp_secret = pyotp.random_base32()
        
        user = User(email=email,encrypted_password=encrypted_password,totp_secret=totp_secret)
        try:
            db.session.add(user)
            db.session.flush()
            new_keys = UserKey(user_id=user.id,private_key=private_key,public_key=public_key)
            db.session.add(new_keys)

            db.session.commit()

            totp_auth = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=email,
            issuer_name="system"
            )
            qr_code = qrcode.make(totp_auth)
            buffer = io.BytesIO()
            qr_code.save(buffer,format="PNG") # zapisanie do ramu 
            bytes_from_buffer = buffer.getvalue() # pobranie bajtow z ramu

            decoded_bytes = base64.b64encode(bytes_from_buffer).decode("utf-8")
            #print(decoded_bytes)
            session['user_id'] = user.id 
            return render_template("2FA.html",decoded_bytes=decoded_bytes)

        except Exception as e:
            print(e)
            db.session.rollback()
            msg = 'blad rejestracji'
            return render_template('register.html',msg=msg)
    elif request.method == 'GET':  
        
        return render_template('register.html',msg='zarejestruj sie chuju')

@app.route("/loginafterreg",methods = ['POST'])
def login_after_reg():
    print("halo?")
    user_id = session.get('user_id')
    print(user_id)
    user = db.session.query(User).filter_by(id=user_id).first()
    if user is None:
        print("co kurwa!")
    user_secret = user.totp_secret
    if request.method == 'POST':
        code = request.form['totp']
        if pyotp.TOTP(user_secret).verify(code):
            return "<h1>hurra</h1>"
    return "ups"




@app.route("/login",methods=['GET','POST'])
def login():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        queried_user = db.session.query(User).filter_by(email=email).first()
        
        if queried_user is None:
            time.sleep(0.5)
            return render_template("login.html",msg='Ponów próbę logowania')
        
        hash_in_db = queried_user.password_hash
        ph = PasswordHasher()
        try:
            ph.verify(hash_in_db,password)
            msg = 'Poprawnie'
        except VerifyMismatchError as e:
            msg = 'Ponów próbe logowania'
            time.sleep(0.5)
            return render_template('login.html',msg=msg)

    time.sleep(0.5)
    #session['user_id'] = queried_user.id
    #session['temp_password'] = password
    return redirect("/login/2FA")




@app.route("/login/2FA",methods=['GET','POST'])
def second_login():
   # user_id = session['user_id']
  #  user = db.session.query(User).filter_by(user_id).first()
    
    msg = ''
    key = "uffklucz"
    
    totp_auth = pyotp.totp.TOTP(key).provisioning_uri(
        name="kurwa",
        issuer_name="system"
    )
    qr_code = qrcode.make(totp_auth)
    buffer = io.BytesIO()
    qr_code.save(buffer,format="PNG") # zapisanie do ramu 
    bytes_from_buffer = buffer.getvalue() # pobranie bajtow z ramu

    decoded_bytes = base64.b64encode(bytes_from_buffer).decode("utf-8")
    print(decoded_bytes)
    #parsed_totp = pyotp.parse_uri(totp_auth)
    return render_template("2FA.html",decoded_bytes=decoded_bytes)





    
        
    