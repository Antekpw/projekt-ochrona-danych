from flask import Blueprint, request, render_template, session,redirect,flash,send_file, url_for
from database import db
from models.models import Message, User, UserKey ,RecipientMessage 
import io
from .services import *
import magic
messages_bp = Blueprint('messages', __name__)

@messages_bp.route("/send", methods=['GET', 'POST'])
def send_message():
    if request.method == 'POST':
        receiver_mail = request.form.get('receiver_mail')
        message_text = request.form.get('message', '')
        passphrase = request.form.get('password')
        file = request.files.get('attachment')
        file_bytes = file.read() if file else b''

        receiver = User.query.filter_by(email=receiver_mail).first()
        if not receiver:
            flash("Wpisz odbiorcę jeszcze raz", "danger")
            return redirect(request.url)

        success, info = encrypt_message(
            sender_id=session.get('user_id'),
            receiver=receiver,
            text=message_text,
            attachment_bytes=file_bytes,
            passphrase=passphrase
        )

        if success:
            flash(info, "success")
        else:
            flash(info, "danger")
            
        return render_template('send_message.html')
    print("wyslane")
    return render_template('send_message.html')
@messages_bp.route("/inbox")
def inbox():
    user_id = session.get('user_id')
    messages = RecipientMessage.query.join(Message).filter(RecipientMessage.recipient_id == user_id, 
                                                           RecipientMessage.is_deleted == False).order_by(Message.created_at.desc()).all()
    return render_template('inbox.html', messages=messages)

@messages_bp.route("/message/<int:msg_id>",methods=['GET','POST'])
def view_message(msg_id):
    user_id = session.get('user_id')
    passphrase = request.form.get('password', '')
    if not user_id:
        flash("Nie jesteś zalogowany.", "danger")
        return redirect('/login')

    recipient_msg = RecipientMessage.query.filter_by(message_id=msg_id, recipient_id=user_id).first()

    if not recipient_msg or recipient_msg.is_deleted:
        print("wtf tutaj?")
        flash("Brak wiadomości.", "danger")
        return redirect('/inbox')
    if request.method == 'GET':
        return render_template('unlock_message.html', msg_id=msg_id)
    success, content = decrypt_message(
        recipient_msg=recipient_msg,
        passphrase=request.form.get('password', '')
    )

    if not success:
        flash('Wprowadz haslo ponownie', "danger")
        print("chyba tutaj")
        return render_template('unlock_message.html', msg_id=msg_id)
    
    mark_read(recipient_msg)
    #print(content)
    return render_template('view_message.html', message=recipient_msg.message, content=content)
@messages_bp.route("/download/<int:msg_id>", methods=['POST'])
def download_attachment(msg_id):
    user_id = session.get('user_id')
    passphrase = request.form.get('password') 

    recipient_msg = RecipientMessage.query.filter_by(message_id=msg_id, recipient_id=user_id).first_or_404()

    success, content = decrypt_message(recipient_msg, passphrase)

    if success:
        print("moze chociaz tutaj")
         
        print(magic.from_buffer(content['attachment'], mime=True))
        return send_file(
            io.BytesIO(content['attachment']),
            mimetype=magic.from_buffer(content['attachment'], mime=True),
            as_attachment=True,
            download_name=f"zalacznik_{msg_id}" # Można tu dodać logikę rozszerzeń
        )
    
    flash("Błąd autoryzacji przy pobieraniu pliku.")
    print("blad przy pobieraniu")
    return redirect("/inbox")

