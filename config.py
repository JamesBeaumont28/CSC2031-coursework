from functools import wraps

import flask_login
from flask import Flask, url_for, jsonify, render_template, flash, request

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

app = Flask(__name__)

#initilizing the qrcode reader
QRcode(app)
# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True

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

handler = logging.FileHandler('securityLog.log','w')
handler.setLevel(logging.WARNING)

formatter = logging.Formatter('%(asctime)s : %(message)s','%d/%m/%Y %I:%M:%S %p')

handler.setFormatter(formatter)
logger.addHandler(handler)

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
        self.title = title
        self.body = body
        self.userid = user_id
        self.user = User.query.filter(User.id == user_id).first()

    def update(self, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        db.session.commit()


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

    def __init__(self, email, firstname, lastname, phone, password, MFAkey, MFA_enabled):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.MFAkey = MFAkey
        self.MFA_enabled = MFA_enabled

    def generate_log(new_user_id):
        print("in gen log user id is ",new_user_id,"=====================================================")
        new_log = Log(user_id=new_user_id)
        db.session.add(new_log)
        #db.session.commit()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    def verify_password(submitted_password):
        if User.query.filter_by(password=submitted_password).first() is None:
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
        print("the id passed in is ",user_id, "---------------------------------------")

        self.userRegTime = datetime.now()
        self.latestIP = request.remote_addr
        self.userid = user_id
        self.user = User.query.filter(User.id == user_id).first()

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


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('successfully Logged out', category='success')
    logger.warning(msg='[User:{}, Role:{}, IP Address:{}] Successfully logged out'.format(user.email, user.role, user.log.latestIP))
    return redirect("/login")


@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('errors/429_error.html'), 429
