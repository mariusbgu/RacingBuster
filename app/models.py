from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Initialize database
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='user')  # Added 'role' to differentiate admin and user
    @property
    def is_admin(self):
        return self.role == 'admin'

class Race(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    day = db.Column(db.String(20), nullable=False)  # e.g., Tuesday, Wednesday
    locked = db.Column(db.Boolean, default=False)  # True if admin locks it after race starts
    first_position = db.Column(db.Integer, nullable=True)  # ID of horse in 1st position
    second_position = db.Column(db.Integer, nullable=True)  # ID of horse in 2nd position
    third_position = db.Column(db.Integer, nullable=True)  # ID of horse in 3rd position

class Selection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    race_id = db.Column(db.Integer, db.ForeignKey('race.id'), nullable=False)
    selection_value = db.Column(db.Integer, nullable=False)  # User's selected horse ID

    user = db.relationship('User', backref='selections')
    race = db.relationship('Race', backref='selections')

