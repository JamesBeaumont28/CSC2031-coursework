import flask_login
import pyotp
import requests
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_required, current_user, login_user
from markupsafe import Markup

from accounts.forms import RegistrationForm, LoginForm, MFAForm
from config import User, db

limiter = Limiter(get_remote_address)
accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

@accounts_bp.route('/registration',methods=['GET','POST'])
def registration():
    form = RegistrationForm()

    if current_user.is_authenticated:
        flash('You are already logged in.','success')
        return redirect(url_for('accounts.account'))

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
        session['user_uri'] = pyotp.totp.TOTP(new_user.MFAkey).provisioning_uri(new_user.email, 'CSC2031 Blog web page')
        session['MFAkey'] = new_user.MFAkey
        return redirect('MFA_setup')

    return render_template('accounts/registration.html', form=form)

@accounts_bp.route('/login',methods=['GET','POST'])
@limiter.limit("2 per minute,200 per day", error_message='Too many requests have been sent. Please come back later and try again.')

def login():

    if current_user.is_authenticated:
        flash('You are already logged in.', 'success')
        return redirect(url_for('accounts.account'))

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
            return redirect('/registration')

        elif not user.password == form.password.data:

            session['authentication_attempts'] = session.get('authentication_attempts') + 1

            #change at end to 3
            if session.get('authentication_attempts') >= 333:
                flash('Maximum login attempts reached. Click ' + Markup("<a href = '/unlock'>here</a>") + ' to unlock account.', category="danger")
                return render_template('accounts/login.html')

            else:
                flash('Your login details incorrect please try again, ' + format(
                3 - session.get('authentication_attempts')) + ' attempts remaining', category="danger")
                return render_template('accounts/login.html', form=form)

        elif not pyotp.totp.TOTP(user.MFAkey).now() == form.pin.data:
            if not user.MFA_enabled:
                flash('You must set up Multi-Factor Authentication before you can log in', category="danger")
                session['user_uri'] = pyotp.totp.TOTP(user.MFAkey).provisioning_uri(user.email, 'CSC2031 Blog web page')
                session['MFAkey'] = user.MFAkey
                return redirect('MFA_setup')
            else:
                session['authentication_attempts'] = session.get('authentication_attempts') + 1
                flash('Your pin is incorrect please try again, ' + format(
                    3 - session.get('authentication_attempts')) + ' attempts remaining', category="danger")
                return render_template('accounts/login.html', form=form)

        elif user.password == form.password.data:
            flask_login.login_user(user, remember=True)
            #print("Has a user been loaded :",flask_login.current_user.email,"-----------------------------------------------------------------------")
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

    #if not flask_login.current_user.is_authenticated:
        #flash('You are already logged in',category='danger')
        #return redirect(url_for('accounts.account'))

    form = MFAForm()
    if 'user_uri' not in session:
        session['user_uri'] = "No user loaded"
    if 'MFAkey' not in session:
        session['MFAkey'] = "please enter your email and a random pin to generate your key and QR code."
        return render_template('accounts/MFA_setup.html', form=form, secret=session['MFAkey'], qr_code = session['user_uri'])

    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data).first()

        if user is None:
            flash('Email is not registered, please register before activating Multi-Factor Authentication',category='danger')
            return redirect(url_for('accounts.registration'))

        elif user.email == form.email.data and pyotp.totp.TOTP(user.MFAkey).verify(form.pin.data):
            user.MFA_enabled = True
            db.session.commit()
            flash('Multi-Factor authentication activated, redirecting to login page.', category='success')
            return redirect(url_for('accounts.login'))
        elif user.MFA_enabled:
            flash('Multi-Factor authentication has already been verified.', category='success')
            return redirect(url_for('accounts.login'))
        else:
            flash('Email or pin is incorrect, please try again', category='danger')
            session['MFAkey'] = user.MFAkey
            return render_template('accounts/MFA_setup.html', form=form, secret= session['MFAkey'],qr_code=pyotp.totp.TOTP(user.MFAkey).provisioning_uri(user.email,'CSC2031 Blog web page'))

    return render_template('accounts/MFA_setup.html', form=form, secret= session['MFAkey'], qr_code=session['user_uri'])

@accounts_bp.route('/account')
@login_required
def account():
    return render_template('accounts/account.html')