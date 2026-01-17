from flask import Flask,session
from flask_session import Session
from database import db
import os
from auth.routes import auth_bp
from messages.routes import messages_bp
def create_app():
    app = Flask(__name__)
    app.secret_key = 'bardzo tajne'##os.urandom(32)  # KLUCZ DO PODPISYWANIA COOKIE

    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://antek:haslo123@localhost:5432/mail_db'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True 
    db.init_app(app)
    Session(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(messages_bp)
    return app


app = create_app()









    
        
    