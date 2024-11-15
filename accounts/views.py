from flask import Blueprint, render_template, flash, redirect, url_for,jsonify,request
import requests

from accounts.forms import RegistrationForm, LoginForm
from config import User, db

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
                        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account Created', category='success')
        return redirect(url_for('accounts.login'))

    return render_template('accounts/registration.html', form=form)

@accounts_bp.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    data = {
        "secret": "6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd",
        "response": request.form.get("g-recaptcha-response")
    }
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=data)
    result = response.json()
    if not User.check_login_count():
        print("maxiumum logins reached")

    elif form.validate_on_submit():
        if not User.verify_password(form.password.data):
            flash('Your email or password is incorrect', category="danger")
            User.add_login_attempt()
            return render_template('accounts/login.html', form=form)

        elif not result.get("success"):
            flash('your reCHAPCHA failed or was not submitted', category="danger")
            User.add_login_attempt()
            return render_template('accounts/login.html', form=form)
        else:
            flash('Login Successful', category='success')
            User.reset_login_limits()
            return redirect(url_for('accounts.account'))

    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')