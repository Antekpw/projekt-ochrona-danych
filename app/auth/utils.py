import base64
import io
from argon2 import PasswordHasher
import pyotp
import qrcode
from Crypto.PublicKey import RSA
import string
from database import db
from models.models import User, UserKey
def validate_password(password):
    num_of_char = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return num_of_char >=12 and has_upper and has_lower and has_digit and has_special

def generate_keys(password):
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=password, format='PEM', pkcs=8)
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

def generate_totp_qr_code(email, totp_secret):
    totp_auth = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="system")
    qr_code = qrcode.make(totp_auth)
    buffer = io.BytesIO()
    qr_code.save(buffer, format="PNG")
    bytes_from_buffer = buffer.getvalue()
    decoded_bytes = base64.b64encode(bytes_from_buffer).decode("utf-8")
    return decoded_bytes

def handle_db(private_key, public_key, user):
    db.session.add(user)
    db.session.flush()
    new_keys = UserKey(user_id=user.id, private_key=private_key, public_key=public_key)
    db.session.add(new_keys)
    db.session.commit()

def encrypt_password(password):
    ph = PasswordHasher()
    encrypted_password = ph.hash(password)
    return encrypted_password
