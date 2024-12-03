from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.numeric import IntegerField
from wtforms.validators import DataRequired, EqualTo, Email, AnyOf, NoneOf, Regexp, NumberRange


class RegistrationForm(FlaskForm):
    email = StringField(validators=[DataRequired(),Email()])
    firstname = StringField(validators=[DataRequired(),Regexp(r"^[a-zA-Z\-]+$",message='names must not contain special characters')])
    lastname = StringField(validators=[DataRequired(),Regexp(r"^[a-zA-Z\-]+$",message='names must not contain special characters')])
    phone = StringField(validators=[DataRequired(),Regexp(r"^^02\d{8}$|^(011\d|01.1)\d{7}$|^01...\d{5,6}$",message='invalid phone number.'),NumberRange(min=9,max=11)])
    password = PasswordField(validators=[DataRequired()])
    confirm_password = PasswordField(validators=[DataRequired(),EqualTo('password', message='Both password fields must be equal!')])
    submit = SubmitField()

class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    submit = SubmitField()

class MFAForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    submit = SubmitField()

