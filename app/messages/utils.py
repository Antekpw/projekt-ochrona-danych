from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from database import db
def serialize_message(text, attachment_bytes):
    """Pakuje tekst i załącznik w jeden ciąg bajtów."""
    text_bytes = text.encode('utf-8')
    text_len = len(text_bytes)
    # [4 bajty długości][tekst][reszta to plik]
    return text_len.to_bytes(4, 'big') + text_bytes + attachment_bytes

def deserialize_message(raw_data):
    """Odwrotność - wyciąga tekst i załącznik."""
    text_len = int.from_bytes(raw_data[:4], 'big')
    text = raw_data[4:4+text_len].decode('utf-8')
    attachment = raw_data[4+text_len:]
    return text, attachment




def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, 16))

def encrypt_aes_key(aes_key, public_key_rsa):
    cipher_rsa = PKCS1_OAEP.new(public_key_rsa)
    return cipher_rsa.encrypt(aes_key)

def decrypt_aes_key(encrypted_aes_key, private_key_rsa):
    cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
    return cipher_rsa.decrypt(encrypted_aes_key)

def decrypt_data(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data), 16)

def verify_signature(data, signature, public_key):
    h = SHA256.new(data)
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
def mark_read(recipient_msg):
    if not recipient_msg.is_read:
        recipient_msg.is_read = True
        db.session.commit()