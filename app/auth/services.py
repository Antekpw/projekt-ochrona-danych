import time
from models.models import User, UserKey  
from database import db  
from .utils import *
import pyotp
import time
from argon2.exceptions import VerifyMismatchError

def register_user(email, password):
    if not validate_password(password):
        time.sleep(0.5)
        return None, 'Hasło nie spełnia wymagań bezpieczeństwa'

    encrypted_password = encrypt_password(password)

    private_key, public_key = generate_keys(password)
    totp_secret = pyotp.random_base32()

    user = User(email=email, encrypted_password=encrypted_password, totp_secret=totp_secret)
    try:
        handle_db(private_key, public_key, user)

        decoded_bytes = generate_totp_qr_code(email, totp_secret)
        
        return user.id, decoded_bytes

    except Exception as e:
        print(e)
        db.session.rollback()
        return None, 'Błąd rejestracji'
    


def login_user(email, password):
    user_id = None
    msg =''
    
    queried_user = db.session.query(User).filter_by(email=email).first()
    
    if queried_user is None:
        time.sleep(0.5)
        user_id = None
        msg = 'Ponów próbę logowania'
        return user_id, msg
    
    hash_in_db = queried_user.password_hash
    ph = PasswordHasher()
    try:
        ph.verify(hash_in_db, password)
        user_id = queried_user.id
        msg='Poprawnie'
    except VerifyMismatchError as e:
        queried_user.failed_attempts += 1
        db.session.commit()
        time.sleep(0.5)
        user_id = None
        msg = 'Ponów próbę logowania'
    return user_id, msg

def verify_2fa(user_id, code):
    
    try:
        user = db.session.query(User).filter_by(id=user_id).first()
        if not user:
            return False, 'Użytkownik nie znaleziony.'
        
        user_secret = user.totp_secret
        if not code or not code.isdigit() or len(code) != 6:
            return False, 'Nieprawidłowy kod 2FA.'
        
        totp = pyotp.TOTP(user_secret)
        if totp.verify(code):
            return True, 'Zalogowano pomyślnie!'
        else:
            return False, 'Nieprawidłowy kod 2FA.'
    except Exception as e:
        print(f"Błąd weryfikacji TOTP: {e}")
        return False, 'Wystąpił błąd podczas weryfikacji.'



