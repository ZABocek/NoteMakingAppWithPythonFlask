from flask import Blueprint, render_template, request, flash, redirect, url_for
import re
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

# New function to validate password criteria
def validate_password(password, min_length=10, numbers=True, special_characters=True):
    if len(password) < min_length:
        return False
    
    if numbers and not re.search(r"\d", password):
        return False
    
    if special_characters and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    
    return True

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

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
        elif not validate_password(password1):
            flash('Password must be at least 10 characters and contain a special character and number.', category='error')
        else:
            # Correct hash method
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))  
    return render_template("sign_up.html")
