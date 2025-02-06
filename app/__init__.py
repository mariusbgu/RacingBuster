from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    # Initialize the app
    app = Flask(__name__)

    # App configuration
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Import the models here to avoid circular import issues
    from . import models

    # Create tables in the database
    with app.app_context():
        db.create_all()  # This will create all the tables based on models if they don't exist
        
       

    # Set the login view for the login manager
    login_manager.login_view = 'login'

    # Define user_loader
    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))  # Access models here

    # Register routes
    from . import routes
    app.add_url_rule('/', 'home', routes.home)
    app.add_url_rule('/register', 'register', routes.register, methods=['GET', 'POST'])
    app.add_url_rule('/admin_dashboard', 'admin_dashboard', routes.admin_dashboard, methods=['GET', 'POST'])
    app.add_url_rule('/login', 'login', routes.login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', routes.logout)
    app.add_url_rule('/races/<day>', 'races', routes.races, methods=['GET', 'POST'])
    app.add_url_rule('/leaderboard', 'leaderboard', routes.leaderboard)

    # New Admin Routes
    app.add_url_rule('/admin/users', 'admin_users', routes.admin_users)
    app.add_url_rule('/admin/update_role/<int:user_id>', 'update_role', routes.update_role, methods=['POST'])
    app.add_url_rule('/admin/update_password/<int:user_id>', 'update_password', routes.update_password, methods=['POST'])
    app.add_url_rule('/admin/delete_user/<int:user_id>', 'delete_user', routes.delete_user, methods=['POST'])
    
    app.add_url_rule('/admin/races', 'admin_races', routes.admin_races)
    app.add_url_rule('/admin/edit_race/<int:race_id>', 'edit_race', routes.edit_race, methods=['GET', 'POST'])
    app.add_url_rule('/admin/delete_race/<int:race_id>', 'delete_race', routes.delete_race, methods=['POST'])
    app.add_url_rule('/admin/add_race', 'add_race', routes.add_race, methods=['GET', 'POST'])


    return app
