from flask import Blueprint, request, render_template, session,redirect,flash
from database import db
from models.models import Message, User, UserKey ,RecipientMessage 
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
messages_bp = Blueprint('messages', __name__)

@messages_bp.route("/send", methods=['GET', 'POST'])
def send_message():
    current_user_id = session.get('user_id')
    if request.method == 'POST':
        text = request.form.get('message', '')
        attachment = request.files.get('attachment', None)
        receiver_mail = request.form.get('receiver_mail', '')
        password = request.form.get('password', '')
        receiver = db.session.query(User).filter_by(email=receiver_mail).first()

        receiver_key = db.session.query(UserKey).filter_by(user_id=receiver.id).first()
        #print("receiver_id:", receiver.id)
        RSA_public_key = RSA.import_key(receiver_key.public_key_rsa)
        #print("Receiver Key:", RSA_public_key.export_key(format='DER').hex())
        key = os.urandom(32)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC,iv)

        data_to_send = create_data_to_send(text, attachment)

        ##data_padded = uzupełnienie do bloku 16 bajtów
        data_padded = pad(data_to_send,16)

        encrypted_data = aes.encrypt(data_padded)
        content = iv + encrypted_data
        ## signature = RSA.sign(data_to_send, private_key, 'SHA-256') skrot danych zaszyfrowanych prywatnym kluczem nadawcy
        ## encrypted_aes_key zaszyfrowany klucz AES kluczem publicznym odbiorcy
        encrypted_aes_key = encrypt_aes_key(RSA_public_key, key)

        ###signature
        sender_private_key_obj = db.session.query(UserKey).filter_by(user_id=current_user_id).first()
        sender_private_key = RSA.import_key(sender_private_key_obj.private_key_encrypted, passphrase=password)

        signature = sign(data_to_send, sender_private_key)

        message_obj = Message(sender_id=current_user_id, encrypted_body=content, signature=signature)
        db.session.add(message_obj)
        db.session.flush()
        recipient_msg_obj = RecipientMessage(message_id=message_obj.id, recipient_id=receiver.id, encrypted_aes_key=encrypted_aes_key)

        db.session.add(recipient_msg_obj)
        db.session.commit()

        return render_template('send_message.html', msg='Wiadomość wysłana')
    elif request.method == 'GET':
        return render_template('send_message.html', msg='Wyślij wiadomość')

def encrypt_aes_key(RSA_public_key, key):
    cipher = PKCS1_OAEP.new(RSA_public_key)
    encrypted_aes_key = cipher.encrypt(key)
    return encrypted_aes_key

def sign(data_to_send, sender_private_key):
    h = SHA256.new(data_to_send)
    signature = pss.new(sender_private_key).sign(h)
    return signature

def create_data_to_send(text, attachment):
    text_len  = len(text)
    text_to_bytes = text.encode('utf-8')
    attachment_to_bytes = attachment.read()
        #print(type(attachment_to_bytes)) bytes
    data_to_send = text_len.to_bytes(4, 'big') + text_to_bytes + attachment_to_bytes
    return data_to_send