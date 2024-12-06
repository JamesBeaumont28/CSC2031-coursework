import base64
import re
from hashlib import scrypt

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

from dotenv import load_dotenv
import os
load_dotenv()

import base64
from functools import wraps

from cryptography.hazmat.primitives import kdf
from fernet import Fernet
import flask_login
from flask import Flask, url_for, jsonify, render_template, flash, request

from flask_talisman import Talisman

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, logout_user, login_required, current_user

#database import
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData, false, nullsfirst, Enum

from datetime import datetime

from sqlalchemy.dialects.postgresql import INET
from werkzeug.utils import redirect
from wtforms.validators import length
from accounts.forms import LoginForm

import logging

#QRCODE READER
from flask_qrcode import QRcode
#Hasher
from argon2 import PasswordHasher

app = Flask(__name__)

#initilizing the qrcode reader
QRcode(app)
# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

#Talisman setup
csp = {'-style-src':['\'self\'',"'unsafe-inline'", "https://fonts.googleapis.com"],
       'script-src':['\'self\'','https://www.google.com/recaptcha/','https://www.gstatic.com/recaptcha/', "'unsafe-inline'"],
       'frame-src':['\'self\'','https://www.google.com/recaptcha/','https://recaptcha.google.com/recaptcha/'],
       'font-src': ["'self'","https://fonts.gstatic.com"]
       }
talisman = Talisman(app,content_security_policy = csp)

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO') == 'True'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = os.getenv('FLASK_ADMIN_FLUID_LAYOUT')== 'True'

#login manager
login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute,200 per day"])
metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

#security logger
logger = logging.getLogger('securityLog')

handler = logging.FileHandler('securityLog.log','a')
handler.setLevel(logging.WARNING)

formatter = logging.Formatter('%(asctime)s : %(message)s','%d/%m/%Y %I:%M:%S %p')

handler.setFormatter(formatter)
logger.addHandler(handler)

#password hasher
ph = PasswordHasher()

#symetric encryption


# DATABASE TABLES
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")

    def __init__(self, user_id, title, body):
        self.created = datetime.now()
        self.userid = user_id
        self.user = User.query.filter(User.id == user_id).first()
        key = scrypt(password=current_user.password.encode(),
                     salt=current_user.salt.encode(),
                     n=2048,
                     r=8,
                     p=1,
                     dklen=32)

        cipher = Fernet(base64.urlsafe_b64encode(key))
        self.title = cipher.encrypt(title)
        self.body = cipher.encrypt(body)

    def update(self, title, body):
        key = scrypt(password=self.user.password.encode(),
                     salt=self.user.salt.encode(),
                     n=2048,
                     r=8,
                     p=1,
                     dklen=32)
        cipher = Fernet(base64.urlsafe_b64encode(key))
        self.created = datetime.now()
        self.title = cipher.encrypt(title)
        self.body = cipher.encrypt(body)
        db.session.commit()

    def decrypt_title(post):

        key = scrypt(password=post.user.password.encode(),salt=post.user.salt.encode(),n=2048,r=8,p=1,dklen=32)

        cipher = Fernet(base64.urlsafe_b64encode(key))

        return cipher.decrypt(post.title).decode()

    def decrypt_body(post):
        key = scrypt(password=post.user.password.encode(),
                     salt=post.user.salt.encode(),
                     n=2048,
                     r=8,
                     p=1,
                     dklen=32)

        cipher = Fernet(base64.urlsafe_b64encode(key))

        return cipher.decrypt(post.body).decode()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    #Authentication info
    MFAkey = db.Column(db.String(32), nullable=False)
    MFA_enabled = db.Column(db.Boolean(), nullable=False)
    role = db.Column(Enum('end_user', 'db_admin', 'sec_admin', name='role'), nullable=False, default='end_user')

    # Db relationships
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")
    log = db.relationship("Log",uselist=False,back_populates="user")

    #network encryption
    salt =  db.Column(db.String(100),nullable = False)


    def __init__(self, email, firstname, lastname, phone, password, MFAkey, MFA_enabled):
        self.salt = base64.b64encode(secrets.token_bytes(32)).decode()
        self.password = ph.hash(password)
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.MFAkey = MFAkey
        self.MFA_enabled = MFA_enabled


    def generate_log(new_user_id):
        new_log = Log(user_id=new_user_id)
        db.session.add(new_log)
        #db.session.commit()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    def verify_password(user,submitted_password):
        if not ph.verify(user.password,submitted_password):
            return False
        else:
            return True

    def password_integrity_check(submitted_password):
        #REMOVE TRIS BEFORE SUBMITION------------------------------------------------------------------------------
        return True
        if len(submitted_password) < 8 or len(submitted_password) > 15:
            return False
        print("i am running")
        upper = False
        lower = False
        digit = False
        special = False

        for i in range(len(submitted_password)):
            if submitted_password[i].isupper():
                upper = True
            if submitted_password[i].islower():
                lower = True
            if submitted_password[i].isdigit():
                digit = True
            if submitted_password[i] in "!@#$%^&*()-+?_=,<>/\\|{}[]:;\"'`~":
                special = True

        if not upper or not lower or not digit or not special:
            return False
        else:
            return True

    #def verify_email(email):


class Log(db.Model):
    __tablename__ = 'logs'

    #IDs
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    #Times
    userRegTime = db.Column(db.DateTime,nullable = False, default=datetime.now())
    recentLoginTime = db.Column(db.DateTime,nullable = False, default=datetime.now())
    prevLoginTime = db.Column(db.DateTime,nullable = False, default=datetime.now())

    #IPs
    latestIP = db.Column(db.String(15))
    prevIP = db.Column(db.String(15))

    #the User it is logging
    user = db.relationship("User", back_populates="log")

    def __init__(self,user_id):
        self.userRegTime = datetime.now()
        self.latestIP = request.remote_addr
        self.userid = user_id
        self.user = User.query.filter(User.id == user_id).first()

    def decrypt_body(self):
        return

def role_required(role):
    def inner_decorator(f):
        @wraps(f)
        def wrapped(*args,**kwargs):
            if current_user.role != role:
                flash('You do not have permissions to access this page.',category='danger')
                logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Tried to access forbidden site'.format(current_user.email,current_user.role,current_user.log.latestIP))
                return redirect(url_for('accounts.account'))
            else:
                return f(*args,**kwargs)
        return wrapped
    return inner_decorator





# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')

    def is_accessible(self):
        if not current_user.is_authenticated:
            flash('You must login to an authorised account to access this page.', category='danger')
            logger.warning(msg='Anonymous user attempted to access forbidden site.')
            return False

        elif current_user.role != "db_admin":
            flash('You do not have permissions to access this page.', category='danger')
            logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Tried to access forbidden site'.format(current_user.email,current_user.role,current_user.log.latestIP))
            return False
        else:
            return True

    def is_visible(self):
        if current_user.role != "db_admin":
            return False
        else:
            return True

class LogView(ModelView):
    column_display_pk = True  # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = (
    'id','userid','userRegTime','recentLoginTime','prevLoginTime','latestIP','prevIP','user')

    def is_accessible(self):
        if not current_user.is_authenticated:
            flash('You must login to an authorised account to access this page.', category='danger')
            logger.warning(msg='Anonymous user attempted to access forbidden site.')
            return False

        elif current_user.role != "db_admin":
            flash('You do not have permissions to access this page.', category='danger')
            logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Tried to access forbidden site'.format(current_user.email,current_user.role,current_user.log.latestIP))
            return False
        else:
            return True

    def is_visible(self):
        if current_user.role != "db_admin":
            return False
        else:
            return True

class UserView(ModelView):
    column_display_pk = True  # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = (
    'id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'MFAkey', 'MFA_enabled','role','log')

    def is_accessible(self):
        if not current_user.is_authenticated:
            flash('You must login to an authorised account to access this page.',category='danger')
            logger.warning(msg='Anonymous user attempted to access forbidden site.')
            return False

        elif current_user.role != "db_admin":
            flash('You do not have permissions to access this page.',category='danger')
            logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Tried to access forbidden site'.format(current_user.email, current_user.role, current_user.log.latestIP))
            return False
        else:
            return True

    def is_visible(self):
        if current_user.role != "db_admin":
            return False
        else:
            return True



admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))
admin.add_view(LogView(Log, db.session))

# IMPORT BLUEPRINTS
from accounts.views import accounts_bp, login
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)

app.jinja_env.globals['decrypt_title'] = Post.decrypt_title
app.jinja_env.globals['decrypt_body'] = Post.decrypt_body


@app.route("/logout")
@login_required
def logout():
    logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Successfully logged out'.format(current_user.email, current_user.role,current_user.log.latestIP))
    logout_user()
    flash('successfully Logged out', category='success')
    return redirect("/login")

@app.before_request
def waf_attack_detector():
    conditions = {'SQL injection': re.compile(r'union|select|insert|drop|alter|;|`|\'', re.IGNORECASE),
                  'XSS': re.compile(r'<script>|<iframe>|%3cscript%3e|%3ciframe%3e', re.IGNORECASE),
                  'Path traversal': re.compile(r'\.\./|\.{2,}%2f|%2e%2e%2f', re.IGNORECASE)}

    for attack_type, attack_pattern in conditions.items():
        if attack_pattern.search(request.path) or attack_pattern.search(request.query_string.decode()):
            logger.warning(msg='A {} attack was detected by the firewall.'.format(attack_type))
            return render_template('errors/attack_warning.html',label = attack_type)

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('errors/429_error.html'), 429

@app.errorhandler(400)
def bad_request_error(e):
    return render_template('errors/400_error.html'),400

@app.errorhandler(404)
def not_found_error(e):
    return render_template('errors/404_error.html'),404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500_error.html'),500

@app.errorhandler(501)
def not_implemented_error(e):
    return render_template('errors/501_error.html'),501

@app.errorhandler(401)
def unauthorized_error(e):
    return render_template('errors/401_error.html'),401

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('errors/403_error.html'),403