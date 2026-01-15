from database import db
from datetime import datetime,timezone

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  
    failed_attempts = db.Column(db.Integer, default=0)    
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")) 
    totp_secret = db.Column(db.String(32))

    keys = db.relationship('UserKey', backref='owner', cascade="all, delete-orphan", uselist=False)
    sent_messages = db.relationship('Message', backref='sender', lazy=True)

    def __init__(self,email,encrypted_password,totp_secret):
        self.email = email
        self.password_hash = encrypted_password
        self.totp_secret = totp_secret

class UserKey(db.Model):
    __tablename__ = 'user_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_key_rsa = db.Column(db.LargeBinary, nullable=False)      
    private_key_encrypted = db.Column(db.LargeBinary, nullable=False) 

    def __init__(self,user_id,public_key,private_key):
        self.user_id = user_id
        self.public_key_rsa = public_key
        self.private_key_encrypted = private_key
        

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)               
    signature = db.Column(db.Text, nullable=False)             
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    recipients = db.relationship('RecipientMessage', backref='message', cascade="all, delete-orphan")

class RecipientMessage(db.Model):
    __tablename__ = 'recipient_message'
    
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)