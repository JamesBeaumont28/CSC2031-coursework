from datetime import datetime
from hashlib import scrypt


import flask_login
import pyotp
import requests
from fernet import Fernet
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_required, current_user, login_user
from markupsafe import Markup
from pyexpat.errors import messages

from accounts.forms import RegistrationForm, LoginForm, MFAForm
from config import User, db, Log, logger

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
        User.generate_log(new_user_id=new_user.id)
        db.session.commit()

        logger.warning(msg='[User:{}] Successfully registered'.format(new_user.email))

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
    print("\nresult is: ",result,"=================================================\n")
    if 'authentication_attempts' not in session:
        session['authentication_attempts'] = 0

    if form.validate_on_submit():

        user = User.query.filter(User.email == form.email.data).first()
        if user is None:
            flash('email is not registered, please register to login',category='danger')
            return redirect('/registration')

        if not User.verify_password(user,form.password.data or not result == 'success'):

            session['authentication_attempts'] = session.get('authentication_attempts') + 1

            if session.get('authentication_attempts') >= 3:
                logger.warning(msg='User:{} reached maximum login attempts.'.format(user.email))
                flash('Maximum login attempts reached. Click ' + Markup("<a href = '/unlock'>here</a>") + ' to unlock account.', category="danger")
                return render_template('accounts/login.html')

            else:
                flash('Your login details incorrect please try again, ' + format(
                3 - session.get('authentication_attempts')) + ' attempts remaining', category="danger")
                logger.warning(msg = 'User:{} Login details were incorrect.'.format(user.email))
                return render_template('accounts/login.html', form=form)

        elif not pyotp.totp.TOTP(user.MFAkey).now() == form.pin.data:
            if not user.MFA_enabled:
                flash('You must set up Multi-Factor Authentication before you can log in', category="danger")
                logger.warning(msg='User:{} tried to login without enabling MFA.'.format(user.email))
                session['user_uri'] = pyotp.totp.TOTP(user.MFAkey).provisioning_uri(user.email, 'CSC2031 Blog web page')
                session['MFAkey'] = user.MFAkey
                return redirect('MFA_setup')
            else:
                session['authentication_attempts'] = session.get('authentication_attempts') + 1
                flash('Your pin is incorrect please try again, ' + format(
                    3 - session.get('authentication_attempts')) + ' attempts remaining', category="danger")
                logger.warning(msg='User:{} Submitted incorrect MFA pin.'.format(user.email))
                return render_template('accounts/login.html', form=form)

        else:
            flask_login.login_user(user, remember=True)
            session['authentication_attempts'] = 0
            logintime = user.log.recentLoginTime
            user.log.prevLoginTime = logintime
            user.log.recentLoginTime = datetime.now()
            user.log.prevIP = user.log.latestIP
            user.log.latestIP = request.remote_addr
            db.session.commit()

            logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Successfully logged in'.format(user.email,user.role,user.log.latestIP))

            flash('Login Successful', category='success')

            if current_user.role == "end_user":
                return redirect(url_for('accounts.account'))
            elif current_user.role == "db_admin":
                return redirect("https://127.0.0.1:5000/admin")
            else:
                return redirect(url_for('security.security'))

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
            logger.warning(msg='[User:{}] Successfully activated MFA'.format(user.email))
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