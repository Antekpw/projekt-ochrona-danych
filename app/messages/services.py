import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from database import db
from models.models import Message, RecipientMessage, UserKey
from .utils import *

def _get_private_key(user_id, passphrase):
    key_record = UserKey.query.filter_by(user_id=user_id).first()
    return RSA.import_key(key_record.private_key_encrypted, passphrase=passphrase)
def _get_public_key(user_id):
    key_record = UserKey.query.filter_by(user_id=user_id).first()
    return RSA.import_key(key_record.public_key_rsa)

def _sign(data, private_key):
    h = SHA256.new(data)
    return pss.new(private_key).sign(h)

def _save_to_db(sender_id, receiver_id, encrypted_body, signature, encrypted_aes_key):
    msg = Message(
        sender_id=sender_id, 
        encrypted_body=encrypted_body, 
        signature=signature
    )
    db.session.add(msg)
    db.session.flush()

    recipient_msg_obj = RecipientMessage(
        message_id=msg.id,
        recipient_id=receiver_id,
        encrypted_aes_key=encrypted_aes_key
    )
    db.session.add(recipient_msg_obj)
    db.session.commit()

def encrypt_message(sender_id, receiver, text, attachment_bytes, passphrase):
    try:
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        raw_data = serialize_message(text, attachment_bytes)
        
        encrypted_body = iv + encrypt_data(raw_data, aes_key, iv)
        private_key = _get_private_key(sender_id, passphrase)
        signature = _sign(raw_data, private_key)
        
        receiver_pub_key = RSA.import_key(receiver.keys.public_key_rsa)
        encrypted_aes_key = encrypt_aes_key(aes_key, receiver_pub_key)
        
        _save_to_db(sender_id, receiver.id, encrypted_body, signature, encrypted_aes_key)

        return True, "Wiadomość została wysłana."

    except Exception:
        db.session.rollback()
        return False, "Wystąpił błąd podczas wysyłania wiadomości."
    
def decrypt_message(recipient_msg, passphrase):
    try:
        user_id = recipient_msg.recipient_id
        sender_id = recipient_msg.message.sender_id
        sender_public_key = _get_public_key(sender_id)
        print("user id:", user_id)
        recipient_private_key = _get_private_key(user_id, passphrase)
        
        aes_key = decrypt_aes_key(recipient_msg.encrypted_aes_key, recipient_private_key)
        
        encrypted_body = recipient_msg.message.encrypted_body
        iv = encrypted_body[:16]
        ciphertext = encrypted_body[16:]
        
        decrypted_data = decrypt_data(ciphertext, aes_key, iv)
        
        if not verify_signature(decrypted_data, recipient_msg.message.signature, sender_public_key):
            print("zły podpis")
            return False, "Nieprawidłowy podpis wiadomości."
        
        text, attachment_bytes = deserialize_message(decrypted_data)
        print(type(attachment_bytes))
        return True, {
    'text': text,
    'attachment': attachment_bytes if len(attachment_bytes) > 0 else None
}

    except Exception:
        return False, "Wystąpił błąd podczas odszyfrowywania wiadomości."