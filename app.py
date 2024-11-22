from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# Database Configuration
DATABASE_CONFIG = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "Error#four0four!",  
    "port": "5432"
}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect unauthorized users to the login page


# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash, role_id, department_id):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role_id = role_id
        self.department_id = department_id



def get_db_connection():
    """Create and return a new database connection."""
    return psycopg2.connect(**DATABASE_CONFIG)


def role_required(*allowed_role_ids):
    """Restrict access to users with specific role IDs."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role_id not in allowed_role_ids:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@login_manager.user_loader
def load_user(user_id):
    """Load user from database by user_id."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, role_id, department_id FROM users WHERE id = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    conn.close()

    if user_data:
        return User(id=user_data[0], username=user_data[1], password_hash=user_data[2],
                    role_id=user_data[3], department_id=user_data[4])
    return None


# Routes
@app.route('/')
def home():
    """Render the home page."""
    return render_template("index.html", current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role_id, department_id FROM users WHERE username = %s", (username,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()

        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], password_hash=user_data[2],
                        role_id=user_data[3], department_id=user_data[4])
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch role_id for the given role
        cur.execute("SELECT id FROM roles WHERE role_name = %s", (role,))
        role_id = cur.fetchone()
        if not role_id:
            conn.close()
            return "Invalid role selected", 400

        # Insert new user into the database
        cur.execute(
            "INSERT INTO users (username, password_hash, role_id) VALUES (%s, %s, %s)",
            (username, password_hash, role_id[0])
        )
        conn.commit()
        conn.close()

        flash('Signup successful!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/users')
@login_required
@role_required(1)  # Assuming role_id 1 corresponds to 
def view_users():
    """View all users (Admin only)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role_id, department_id FROM users")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('users.html', users=users)

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(1)  # Assuming only admins can edit users
def edit_user(user_id):
    """Edit user details."""
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        # Get updated details from the form
        username = request.form['username']
        role_id = int(request.form['role_id'])
        department_id = int(request.form['department_id'])

        # Update the user in the database
        cur.execute("""
            UPDATE users 
            SET username = %s, role_id = %s, department_id = %s 
            WHERE id = %s
        """, (username, role_id, department_id, user_id))
        conn.commit()
        cur.close()
        conn.close()

        flash('User updated successfully!', 'success')
        return redirect(url_for('view_users'))

    # Fetch user details to pre-fill the form
    cur.execute("SELECT id, username, role_id, department_id FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('view_users'))

    # Fetch roles and departments for the form
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, role_name FROM roles")
    roles = cur.fetchall()
    cur.execute("SELECT dno, name FROM department")
    departments = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('edit_user.html', user=user, roles=roles, departments=departments)





@app.route('/register', methods=['GET', 'POST'])
@login_required
@role_required(1)  
def register_user():
    """Register a new user (Admin only)."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_id = int(request.form['role_id'])
        department_id = int(request.form['department_id'])

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, role_id, department_id) VALUES (%s, %s, %s, %s)",
                    (username, hashed_password, role_id, department_id))
        conn.commit()
        cur.close()
        conn.close()

        flash('User registered successfully!', 'success')
        return redirect(url_for('view_users'))

    # Fetch roles and departments for the form
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, role_name FROM roles")
    roles = cur.fetchall()
    cur.execute("SELECT dno, name FROM department")
    departments = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('register_user.html', roles=roles, departments=departments)


# Main Entry Point
if __name__ == '__main__':
    app.run(debug=True)
