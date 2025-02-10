from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from .forms import RegistrationForm, LoginForm, RaceSelectionForm, RaceResultForm, AdminSelectionForm
from .models import User, Race, Selection
from . import db
app = Flask(__name__)
# Decorators

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("This email is already registered. Please use a different email.", "danger")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(form.password.data)

        # Always set the role to 'user' for new registrations
        role = "user"

        # Create the new user
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("home"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        selected_day = request.form.get("day")
        if selected_day:
            session['day'] = selected_day
            return redirect(url_for('races', day=selected_day))
    return render_template("home.html")

@app.route("/races/<day>", methods=["GET", "POST"])
@login_required
def races(day):
    if day not in ['Tuesday', 'Wednesday', 'Thursday', 'Friday']:
        flash("Invalid day selected.", "danger")
        return redirect(url_for('home'))

    session['day'] = day  # Store the selected day for future reference
    form = RaceSelectionForm()
    races = Race.query.filter_by(day=day).all()

    # Retrieve the user's previous selections
    user_selections = Selection.query.filter_by(user_id=current_user.id).all()
    user_selected_races = {selection.race_id for selection in user_selections}  # Store race IDs already selected

    if form.validate_on_submit():
        race_id = request.form.get("race_id")
        race = Race.query.get(race_id)

        # Prevent multiple submissions for the same race
        if race and not race.locked and race.id not in user_selected_races:
            selection = Selection(user_id=current_user.id, race_id=race.id, selection_value=form.selection.data)
            db.session.add(selection)
            db.session.commit()
            flash("Your selection has been submitted.", "success")
        else:
            flash("This race is locked, invalid, or you have already submitted a selection.", "danger")

        return redirect(url_for("races", day=day))

    return render_template("races.html", day=day, races=races, form=form, user_selected_races=user_selected_races, user_selections=user_selections)


@app.route("/leaderboard")
@login_required
def leaderboard():
    # Fetch all users
    users = User.query.all()
    
    # Dictionary to store user points
    user_scores = {}

    for user in users:
        total_points = 0  # Initialize user's points

        # Get user's selections
        selections = Selection.query.filter_by(user_id=user.id).all()

        for selection in selections:
            race = Race.query.get(selection.race_id)  # Get race details

            if race:
                if selection.selection_value == race.first_position:
                    total_points += 5  # 1st place match
                elif selection.selection_value == race.second_position:
                    total_points += 3  # 2nd place match
                elif selection.selection_value == race.third_position:
                    total_points += 1  # 3rd place match

        user_scores[user.username] = total_points  # Store points

    # Sort users by points in descending order
    sorted_leaderboard = sorted(user_scores.items(), key=lambda x: x[1], reverse=True)

    return render_template("leaderboard.html", leaderboard=sorted_leaderboard)


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    races = Race.query.all()
    form = RaceResultForm()

    if request.method == 'POST':
        race_id = request.form.get("race_id")  # ✅ Correct key
        print(f"Received race_id: {race_id}")  # ✅ Debugging

        if not race_id:
            flash("No race ID received!", "danger")
            return redirect(url_for("admin_dashboard"))

        race = Race.query.get(race_id)

        if race:
            race.first_position = request.form.get("first_position") or None
            race.second_position = request.form.get("second_position") or None
            race.third_position = request.form.get("third_position") or None
            race.locked = request.form.get("locked") == "on"

            try:
                db.session.commit()
                flash(f"Race {race.name} updated!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving race: {e}", "danger")

        return redirect(url_for("admin_dashboard"))

    return render_template("admin_dashboard.html", races=races, form=form)


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:  
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    users = User.query.all()  
    return render_template('admin_users.html', users=users)

@app.route('/admin/update_role/<int:user_id>', methods=['POST'])
@login_required
def update_role(user_id):
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role")
    user.role = new_role
    db.session.commit()
    
    flash(f"Updated {user.username}'s role to {new_role}.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/update_password/<int:user_id>', methods=['POST'])
@login_required
def update_password(user_id):
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    new_password = request.form.get("new_password")
    user.password = generate_password_hash(new_password)
    db.session.commit()
    
    flash(f"Password updated for {user.username}.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    flash(f"Deleted user {user.username}.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/races')
@login_required
def admin_races():
    if not current_user.is_admin:
        abort(403)  # Forbidden access
    return render_template('admin_races.html', races=Race.query.all())

@app.route('/admin/edit_race/<int:race_id>', methods=['GET', 'POST'])
@login_required
def edit_race(race_id):
    if not current_user.is_admin:
        abort(403)
    race = Race.query.get_or_404(race_id)
    if request.method == 'POST':
        race.name = request.form['name']
        race.date = request.form['date']
        db.session.commit()
        flash("Race updated successfully!", "success")
        return redirect(url_for('manage_races'))
    return render_template('edit_race.html', race=race)

@app.route('/admin/add_race', methods=['GET', 'POST'])
@login_required
def add_race():
    if not current_user.role == 'admin':
        abort(403)
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        new_race = Race(name=name, date=date)
        db.session.add(new_race)
        db.session.commit()
        flash("Race added successfully!", "success")
        return redirect(url_for('admin_races'))
    return render_template('add_race.html')

@app.route('/admin/delete_race/<int:race_id>', methods=['POST'])
@login_required
def delete_race(race_id):
    if not current_user.is_admin:
        abort(403)
    race = Race.query.get_or_404(race_id)
    db.session.delete(race)
    db.session.commit()
    flash("Race deleted successfully!", "success")
    return redirect(url_for('manage_races'))

@app.route("/admin/selections", methods=["GET", "POST"])
@login_required
@admin_required  # Make sure only admins can access this
def admin_selections():
    users = User.query.all()  # Fetch all users
    selected_user_id = request.args.get("user_id", type=int)  # Get user from dropdown
    selections = None

    if selected_user_id:
        selections = Selection.query.filter_by(user_id=selected_user_id).all()

    form = AdminSelectionForm()

    if form.validate_on_submit():
        selection_id = request.form.get("selection_id")
        new_value = form.selection.data
        selection = Selection.query.get(selection_id)

        if selection:
            selection.selection_value = new_value
            db.session.commit()
            flash("Selection updated successfully.", "success")
        else:
            flash("Invalid selection.", "danger")

        return redirect(url_for("admin_selections", user_id=selected_user_id))

    return render_template(
        "admin_selections.html", 
        users=users, 
        selections=selections, 
        selected_user_id=selected_user_id, 
        form=form
    )


# Error Handlers

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
