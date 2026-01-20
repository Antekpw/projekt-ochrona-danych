import time
from models.models import User, UserKey  
from database import db  
from .utils import *
import pyotp
import time
from argon2.exceptions import VerifyMismatchError
from datetime import datetime,timedelta,timezone
def register_user(email, password):
    
    if not valid_credentials(email, password):
        time.sleep(0.5)
        return None, 'Nieprawidłowy format email lub hasło nie spełnia wymagań bezpieczeństwa'
    encrypted_password = encrypt_password(password)

    private_key, public_key = generate_keys(password)
    totp_secret = pyotp.random_base32()
    encrypted_totp,salt = encrypt_secret_with_password(totp_secret, password)
    user = User(email=email, encrypted_password=encrypted_password, totp_secret=encrypted_totp, totp_salt=salt)
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
    
    if queried_user.lockout_until and queried_user.lockout_until > datetime.now(timezone.utc):
        remaining_time = (queried_user.lockout_until - datetime.now(timezone.utc)).seconds // 60
        return None, f'Konto zablokowane. Spróbuj za {remaining_time + 1} min.'
    
    hash_in_db = queried_user.password_hash
    ph = PasswordHasher()
    try:
        ph.verify(hash_in_db, password)
        queried_user.failed_attempts = 0
        queried_user.lockout_until = None
        db.session.commit()
        user_id = queried_user.id
        msg='Poprawnie'
    except VerifyMismatchError as e:
        queried_user.failed_attempts += 1
        if queried_user.failed_attempts >= 5:
            queried_user.lockout_until = datetime.now() + timedelta(minutes=30)
            msg = 'Zbyt wiele nieudanych prób. Konto zablokowane na 30 minut.'
        else:
            msg = f'Ponów próbę logowania. Pozostało prób: {5 - queried_user.failed_attempts}'
        db.session.commit()
        time.sleep(0.5)
        user_id = None
    return user_id, msg

def verify_2fa(user_id, code,password):
    
    try:
        user = db.session.query(User).filter_by(id=user_id).first()
        if not user:
            return False, 'Użytkownik nie znaleziony.'

        user_secret = decrypt_secret_with_password(user.totp_secret,user.totp_salt,password)
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



