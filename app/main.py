from flask import Flask, redirect,session
from flask_session import Session
from database import db
import os
from auth.routes import auth_bp
from messages.routes import messages_bp
def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv('FLASK_SECRET_KEY','default-key-for-dev')  # KLUCZ DO PODPISYWANIA COOKIE

    db_user = os.getenv('DB_USER')
    db_pass = os.getenv('DB_PASSWORD')
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_pass}@{db_host}:5432/{db_name}'

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

@app.route("/")
def index():
    return redirect("/login") 









    
        
    