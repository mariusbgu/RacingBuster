from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from wtforms.fields import IntegerField



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RaceSelectionForm(FlaskForm):
    selection = IntegerField('Select Horse Number', validators=[DataRequired()])
    submit = SubmitField('Submit')

class RaceResultForm(FlaskForm):
    first_position = IntegerField('1st Place', validators=[Optional()], render_kw={"placeholder": "Enter horse #"})
    second_position = IntegerField('2nd Place', validators=[Optional()], render_kw={"placeholder": "Enter horse #"})
    third_position = IntegerField('3rd Place', validators=[Optional()], render_kw={"placeholder": "Enter horse #"})
    locked = BooleanField('Lock Race')
    submit = SubmitField('Save')
