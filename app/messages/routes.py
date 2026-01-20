from flask import Blueprint, request, render_template, session,redirect,flash,send_file, url_for
from auth.utils import is_valid_email
from database import db
from models.models import Message, User, UserKey ,RecipientMessage 
import io
from .services import *
import magic
import time
from auth.routes import login_required
import bleach
messages_bp = Blueprint('messages', __name__)

@messages_bp.route("/send", methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        receiver_mail = request.form.get('receiver_mail')
        message_text = request.form.get('message', '')
        passphrase = request.form.get('password')
        file = request.files.get('attachment')
        #file_bytes = file.read() if file else b''

        clean_message = bleach.clean(
            message_text,
            tags=[], 
            strip=True 
        )
        
        if len(clean_message) > 5000:
            flash("Wiadomość jest zbyt długa (max 5000 znaków).", "danger")
            return redirect(request.url)
        
        if not is_valid_email(receiver_mail):
            flash("Niepoprawny format adresu email.", "danger")
            return redirect(request.url)
        
        file_bytes = file.read()
        print(len(file_bytes))
        if len(file_bytes) > 5 * 1024 * 1024: ## 5mb tylko
            flash("Załącznik jest zbyt duży (max 5MB).", "danger")
            return redirect(request.url)


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
        time.sleep(1)
        return redirect('/inbox')
    return render_template('send_message.html')
@messages_bp.route("/inbox")
@login_required
def inbox():
    user_id = session.get('user_id')
    messages = RecipientMessage.query.join(Message).filter(RecipientMessage.recipient_id == user_id, 
                                                           RecipientMessage.is_deleted == False).order_by(Message.created_at.desc()).all()
    return render_template('inbox.html', messages=messages)

@messages_bp.route("/message/<int:msg_id>",methods=['GET','POST'])
@login_required
def view_message(msg_id):
    user_id = session.get('user_id')
    passphrase = request.form.get('password', '')
    if not user_id:
        flash("Nie jesteś zalogowany.", "danger")
        return redirect('/login')

    recipient_msg = RecipientMessage.query.filter_by(message_id=msg_id, recipient_id=user_id).first()

    if not recipient_msg or recipient_msg.is_deleted:
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
        return render_template('unlock_message.html', msg_id=msg_id)
    
    mark_read(recipient_msg)
    return render_template('view_message.html', message=recipient_msg.message, content=content)

@messages_bp.route("/download/<int:msg_id>", methods=['POST'])
@login_required
def download_attachment(msg_id):
    user_id = session.get('user_id')
    passphrase = request.form.get('password') 

    recipient_msg = RecipientMessage.query.filter_by(message_id=msg_id, recipient_id=user_id).first_or_404()

    success, content = decrypt_message(recipient_msg, passphrase)

    if success:
         
        return send_file(
            io.BytesIO(content['attachment']),
            mimetype=magic.from_buffer(content['attachment'], mime=True),
            as_attachment=True,
            download_name=f"zalacznik_{msg_id}" # Można tu dodać logikę rozszerzeń
        )
    
    flash("Błąd autoryzacji przy pobieraniu pliku.")
    return redirect("/inbox")

@messages_bp.route("/delete/<int:msg_id>", methods=['POST'])
@login_required
def delete_message(msg_id):
    user_id = session.get('user_id')
    
    success = remove_message_from_inbox(user_id, msg_id)
    
    if success:
        flash('Wiadomość została usunięta.', 'success')
    else:
        flash('Nie udało się usunąć wiadomości.', 'error')
        
    return redirect(url_for('messages.inbox'))