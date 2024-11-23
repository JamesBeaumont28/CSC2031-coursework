from flask import Flask, url_for, jsonify, render_template, flash

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#database import
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData, false, nullsfirst
from datetime import datetime

#date and time
import datetime

from werkzeug.utils import redirect
from wtforms.validators import length
from accounts.forms import LoginForm

#QRCODE READER
from flask_qrcode import QRcode

app = Flask(__name__)

#login manager
from flask_login import UserMixin, LoginManager, current_user, login_required, logout_user

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
        self.user = User.query.filter(user_id == id).first()

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

    #MFA info
    MFAkey = db.Column(db.String(32), nullable=False)
    MFA_enabled = db.Column(db.Boolean(), nullable=False)
    is_active = db.Column(db.Boolean(), nullable=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    def __init__(self, email, firstname, lastname, phone, password, MFAkey, MFA_enabled):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.MFAkey = MFAkey
        self.MFA_enabled = MFA_enabled
        self.is_active = True

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter(user_id == id).first()

    def verify_password(submitted_password):
        if User.query.filter_by(password=submitted_password).first() is None:
            return False
        else:
            return True

    def password_integrity_check(submitted_password):
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


# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')


class UserView(ModelView):
    column_display_pk = True  # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = (
    'id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'MFA key', 'MFA activated', 'active')


admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

# IMPORT BLUEPRINTS
from accounts.views import accounts_bp, login
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)


@app.route("/logout")
#@login_required
def logout():
    print(current_user.name)
    logout_user()
    flash('successfully Logged out', category='success')
    return redirect("/login")


@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('errors/429_error.html'), 429
