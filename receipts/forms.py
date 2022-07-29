from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, InputRequired, Email
from flask_wtf import FlaskForm

class Login(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    login = SubmitField('Login')

class Register(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message="Invalid email.")])
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    middlename = StringField('Middle Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
