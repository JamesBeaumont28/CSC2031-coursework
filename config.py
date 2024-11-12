from flask import Flask, url_for

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets

#database import
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData, false
from datetime import datetime

from wtforms.validators import length

from accounts.forms import LoginForm

app = Flask(__name__)

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

   def __init__(self, title, body):
       self.created = datetime.now()
       self.title = title
       self.body = body

   def update(self, title, body):
       self.created = datetime.now()
       self.title = title
       self.body = body
       db.session.commit()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    def __init__(self, email, firstname, lastname, phone, password):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password

    def verify_password(submitted_password):
        if User.query.filter_by(password = submitted_password).first() is None:
            return False
        else:
            return True

    def password_integrity_check(submitted_password):
        if len(submitted_password) < 8 or len(submitted_password) > 15:
            return False;
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
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts')


admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))


# IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp


# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)