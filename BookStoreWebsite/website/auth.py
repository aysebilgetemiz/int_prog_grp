from flask import Blueprint, render_template, request, session, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import pbkdf2_sha256
from passlib.hash import sha256_crypt as sha256



from flask import Flask,  jsonify, request
import uuid
from .__init__ import mydb

auth = Blueprint('auth', __name__)

def signup():
    user = {
        "_id": uuid.uuid4().hex,
        "email" : request.form.get('email'),
        "firstName" : request.form.get('firstName'),
        "password1" : request.form.get('password1'),
        "password2" : request.form.get('password2')
    }
    
   
    
    
    #if mydb.users.find_one({ "email": user['email'] }):
    #  return jsonify({ "error": "Email address already in use" }), 400
    
    mydb.users.insert_one(user)
    return jsonify(user), 200

def start_session(self, user):
    del user['password']
    session['logged_in'] = True
    session['user'] = user
    return jsonify(user), 200

def signout(self):
    session.clear()
    return redirect('/')


def log_in():
    user = mydb.users.find_one({
      "email": request.form.get('email')
    })    
    
    hash = pbkdf2_sha256.hash("password1")

    if user and pbkdf2_sha256.verify(request.form.get('password'), hash):
      flash('Giriş Başarılı.', category='success') 
      start_session(user)
   
    return jsonify({ "error": "Invalid login credentials" }), 401

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
     log_in
     return render_template("home.html", boolean=True)
    return render_template("login.html", boolean=True)


@auth.route('/logout')
def logout():
    return "<p>Logout</p>"


@auth.route('/sign_up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        if len(email) < 4:
           flash('E-posta en az 3 karakterden oluşmalıdır.', category='error')
        elif len(firstName) < 2:
            flash('Kullanıcı adı 1 karakterden uzun olmalıdır.', category='error')
        elif password1 != password2:
            flash('Şifreler eşleşmemektedir.', category='error')
        elif len(password1) < 7:
            flash('Şifre en az 7 karakterden oluşmalıdır.', category='error')
        else:   
            
            flash('Üyelik oluşturuldu.', category='success') 
            signup()
        
    return render_template("sign_up.html")


    
    
    