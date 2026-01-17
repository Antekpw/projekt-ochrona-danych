import time
from flask import Blueprint, request, render_template, session,redirect,flash
from .services import * # Upewnij się, że importujesz funkcję
auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/register", methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        
        user_id, result = register_user(email, password)
        if user_id is None:
            msg = result
            return render_template('register.html', msg=msg)

        session['user_id'] = user_id
        time.sleep(0.5)
        return render_template("2FA.html", decoded_bytes=result)

    elif request.method == 'GET':
        return render_template('register.html', msg='Zarejestruj się')


@auth_bp.route("/login",methods=['GET','POST'])
def login():
    msg = ''
    user_id = None
    if request.method == 'GET':
        return render_template("login.html",msg='Zaloguj się')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_id, msg = login_user(email, password)
        
        if user_id is None:
            msg = msg
            time.sleep(0.5)
            return render_template("login.html",msg=msg)
        
    session['user_id'] = user_id

    time.sleep(0.5)
    
    return redirect("/login/2FA")

@auth_bp.route("/login/2FA",methods = ['POST','GET'])
def login_after_reg():
    user_id = session.get('user_id')
    print("user_id:", user_id)
    if not user_id:
        flash('Sesja wygasła. Zaloguj się ponownie.', 'error')
        return redirect('/login')
    
    if request.method == 'POST':
        code = request.form.get('totp', '').strip()
        success, message = verify_2fa(user_id, code)
        
        if success:
            session['logged_in'] = True
            flash(message, 'success')
            time.sleep(0.5)
            return redirect('/dashboard')
        else:
            flash(message, 'error')
            time.sleep(0.5)
            return render_template('2FA.html', msg='Wprowadź kod 2FA')
    
    elif request.method == 'GET':
        return render_template('2FA.html', msg='Wprowadź kod 2FA')