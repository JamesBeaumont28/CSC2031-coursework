from flask import Blueprint, render_template, flash, redirect, url_for,jsonify,request,session
import requests
from flask_limiter.util import get_remote_address
from markupsafe import Markup
from sqlalchemy import nullsfirst

from accounts.forms import RegistrationForm, LoginForm, MFAForm
from config import User, db

from flask_limiter import Limiter

import pyotp

limiter = Limiter(get_remote_address)
accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

@accounts_bp.route('/registration',methods=['GET','POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        if not User.password_integrity_check(form.password.data):
            flash('Password is too weak. Password must Be between 8 and 15 characters in length, contain 1 lowercase letter, uppercase letter, digit and special character.', category="danger")
            return render_template('accounts/registration.html', form=form)

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        MFAkey = pyotp.random_base32(),
                        MFA_enabled = False,
                        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account Created. You must enable Multi-factor authentication first to login', category='success')
        form = MFAForm()
        return render_template('accounts/MFA_setup.html', form=form,secret=new_user.MFAkey)

    return render_template('accounts/registration.html', form=form)

@accounts_bp.route('/login',methods=['GET','POST'])
@limiter.limit("2 per minute,200 per day", error_message='Too many requests have been sent. Please come back later and try again.')
def login():
    form = LoginForm()
    data = {
        "secret": "6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd",
        "response": request.form.get("g-recaptcha-response")
    }
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=data)
    result = response.json()

    if 'authentication_attempts' not in session:
        session['authentication_attempts'] = 0
    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data).first()
        if user is None:
            flash('email is not registered, please register to login',category='danger')
        if not user.MFA_enabled:
            flash('You must set up Multi-Factor Authentication before you can log in', category="danger")
            form = MFAForm()
            return render_template('accounts/MFA_setup.html', form=form, secret=user.MFAkey)

        elif not user.password == form.password.data or not pyotp.HOTP(user.MFAkey) == form.pin.data:

            session['authentication_attempts'] = session.get('authentication_attempts') + 1

            if session.get('authentication_attempts') >= 3:
                flash('Maximum login attempts reached. Click ' + Markup("<a href = '/unlock'>here</a>") + ' to unlock account.', category="danger")
                return render_template('accounts/login.html')

            else:
                flash('Your login details incorrect please try again, ' + format(
                3 - session.get('authentication_attempts')) + ' attempts remaining', category="danger")
                return render_template('accounts/login.html', form=form)

        else:
            session['authentication_attempts'] = 0
            flash('Login Successful', category='success')
            return redirect(url_for('accounts.account'))

    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/unlock')
def unlock():
    session['authentication_attempts'] = 0
    return redirect(url_for('accounts.login'))

@accounts_bp.route('/MFA_setup', methods=['GET', 'POST'])
def MFA_setup():
    form = MFAForm()

    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data).first()

        if user is None:
            flash('Email is not registered, please register before activating Multi-Factor Authentication',category='danger')
            return redirect(url_for('accounts.registration'))

        elif user.email == form.email.data and pyotp.TOTP(user.MFAkey).verify(form.pin.data):
            user.MFA_enabled = True
            db.session.commit()
            flash('Multi-Factor authentication activated, redirecting to login page.', category='success')
            return redirect(url_for('accounts.login'))
        elif user.MFA_enabled:
            flash('Multi-Factor authentication has already been verified.', category='success')
            return redirect(url_for('accounts.login'))
        else:
            flash('Email or pin is incorrect, please try again', category='danger')
            return render_template('accounts/MFA_setup.html', form=form, secret=user.MFAkey)

    return render_template('accounts/MFA_setup.html', form=form)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')