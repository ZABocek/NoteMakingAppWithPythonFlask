from flask import Blueprint, render_template, request, flash, redirect, url_for
import re
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
import string

auth = Blueprint('auth', __name__)

def generate_password(min_length, numbers=True, special_characters=True):
    letters = string.ascii_letters
    digits = string.digits
    special = string.punctuation
    
    characters = letters
    if numbers:
        characters += digits
    if special_characters:
        characters += special
        
    pwd = ""
    meets_criteria = False
    has_number = False
    has_special = False
    
    while not meets_criteria or len(pwd) < min_length:
        new_char = input(characters)
        pwd += new_char
        
        if new_char in digits:
            has_number = True
        elif new_char in special:
            has_special = True
            
        meets_criteria = True
        if numbers:
            meets_criteria = has_number
        if special_characters:
            meets_criteria = meets_criteria and has_special
            
    return pwd
    

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html")

@auth.route('/logout')
def logout():
    return "<p>Logout<p>"

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif not re.match(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$', email):
            raise ValueError('That\'s not a proper email address!')
        elif len(firstName) < 2:
            flash('First name must be greater than one character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif not generate_password(10):
            flash('Password must be at least 10 characters and contain a special character and number.', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commmit()
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))  
    return render_template("sign_up.html")