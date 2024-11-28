from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv  
import os
# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'your_secret_key' 
load_dotenv() 
# Database Configuration
DATABASE_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT"),
    "host" : "localhost",
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # unauthorized users go to the login page



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
        return User(id=user_data[0], username=user_data[1], password_hash=user_data[2], role_id=user_data[3], department_id=user_data[4])
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
        department_id = request.form.get('department_id')

        # Hash the password
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch role_id for the given role
        cur.execute("SELECT id FROM roles WHERE role_name = %s", (role,))
        role_id = cur.fetchone()
        if not role_id:
            conn.close()
            return "Invalid role selected", 400

        # Insert the new user into the database
        try:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role_id, department_id)
                VALUES (%s, %s, %s, %s)
                """,
                (username, password_hash, role_id[0], None if role == "Super Admin" else department_id)
            )

            conn.commit()
            flash('User created successfully!', 'success')
        except psycopg2.Error as e:
            conn.rollback()
            flash('Error during signup: ' + str(e), 'danger')
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('view_users'))  # Redirect to user management after creation

    # Fetch roles and departments for the form
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, role_name FROM roles")
    roles = cur.fetchall()
    cur.execute("SELECT dnumber, dname FROM department")
    departments = cur.fetchall()
    cur.close()
    conn.close()

    # Pass is_admin=True for rendering an admin-focused user creation form
    return render_template('signup.html', roles=roles, departments=departments, is_admin=True)

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required(1, 2, 3)  # Allow Super Admin, Department Admin, and Normal Users
def view_users():
    if request.method == 'POST':
        view_users.filterDepartmentId = request.form['department_id']
        return redirect(url_for('view_users'))

    """View users with role-based access control."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Retrieve logged-in user's role and department
    logged_in_user_role = current_user.role_id
    logged_in_user_department = current_user.department_id

    if logged_in_user_role == 1:  # Super Admin
        if view_users.filterDepartmentId is not None:
            query = """
                SELECT u.id, u.username, u.role_id, r.role_name, u.department_id, d.dname AS department_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                LEFT JOIN department d ON u.department_id = d.dnumber
                WHERE u.department_id = %s
            """
            cur.execute(query, (view_users.filterDepartmentId,))
            view_users.filterDepartmentId = None
        else:
            query = """
                SELECT u.id, u.username, u.role_id, r.role_name, u.department_id, d.dname AS department_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                LEFT JOIN department d ON u.department_id = d.dnumber
            """
            cur.execute(query)

    elif logged_in_user_role in [2, 3]:  # Department Admin or Normal User
        query = """
            SELECT u.id, u.username, u.role_id, r.role_name, u.department_id, d.dname AS department_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            LEFT JOIN department d ON u.department_id = d.dnumber
            WHERE u.department_id = %s
        """
        cur.execute(query, (logged_in_user_department,))

    else:
        # Restrict access for any other role
        cur.close()
        conn.close()
        return "Access Denied", 403

    # Fetch and close connection
    users = cur.fetchall()
    print("Query Result for Users:", users)  # Debugging output

    # Fetch departments for the dropdowm
    departments = []
    if current_user.role_id == 1: # Super Admin
        try:
            # Super Admin can select from all departments
            cur.execute("SELECT dnumber, dname FROM department")
            departments = cur.fetchall()
        except psycopg2.Error as e:
            print(f"Error fetching departments: {e.pgcode}, {e.pgerror}")
            flash("Unable to fetch departments.", "danger")

    cur.close()
    conn.close()

    return render_template('users.html', users=users, departments=departments)
view_users.filterDepartmentId = None



@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(1,2)  # Assuming only admins can edit users
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
    cur.execute("SELECT dnumber, dname FROM department")
    departments = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('edit_user.html', user=user, roles=roles, departments=departments)


# View All Departments
@app.route('/departments')
@login_required
@role_required(1, 2, 3)  # Allow Super Admin, Department Admin, and Normal Users
def view_departments():
    """View departments with role-based filtering."""
    conn = get_db_connection()
    cur = conn.cursor()

    logged_in_user_role = current_user.role_id
    logged_in_user_department = current_user.department_id

    if logged_in_user_role == 1:
        query = "SELECT dnumber, dname FROM department"
        cur.execute(query)

    elif logged_in_user_role in [2, 3]:  # Department Admin or Normal User
        # Department Admin and Normal Users can only view their department
        query = "SELECT dnumber, dname FROM department WHERE dnumber = %s"
        cur.execute(query, (logged_in_user_department,))

    else:
        cur.close()
        conn.close()
        return "Access Denied", 403

    departments = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("departments.html", departments=departments)


@app.route('/create_department', methods=['GET', 'POST'])
@login_required
@role_required(1)  # Super Admins are the onyl roles that shoudl be able to create departments
def create_department():
    """Create a new department."""
    if request.method == 'POST':
        department_name = request.form['name']

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO department (dname) VALUES (%s)", (department_name,))
            conn.commit()
            flash('Department created successfully!', 'success')
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('Department name must be unique.', 'danger')
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('home'))

    return render_template('create_department.html')
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required(1, 2)  
def add_user():
    """Add a new user."""
    if request.method == 'POST':
        # Debugging: Print all form data
        print(request.form)

        username = request.form['username']
        password = request.form['password']

        try:
            role_id = int(request.form['role_id'])  # Ensure role_id matches the form field
        except KeyError:
            flash("Role selection is required.", "danger")
            return redirect(url_for('add_user'))

        department_id = request.form.get('department_id')

        # Hash the password
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role_id, department_id)
                VALUES (%s, %s, %s, %s)
                """,
                (username, password_hash, role_id, department_id),
            )
            conn.commit()
            flash("User created successfully!", "success")
        except psycopg2.Error as e:
            conn.rollback()
            flash(f"Error creating user: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('view_users'))

    # Fetch roles and departments for the form
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, role_name FROM roles")
    roles = cur.fetchall()
    cur.execute("SELECT dnumber, dname FROM department")
    departments = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('add_user.html', roles=roles, departments=departments)



@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(1, 2)  # Allow Super Admin and Department Admin
def delete_user(user_id):
    """Delete a user based on role permissions."""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Fetch details of the user to be deleted
        cur.execute("SELECT department_id FROM users WHERE id = %s", (user_id,))
        user_to_delete = cur.fetchone()

        if not user_to_delete:
            flash("User not found.", "danger")
            return redirect(url_for('view_users'))

        # Restrict Department Admin to only delete users in their department
        if current_user.role_id == 2 and user_to_delete[0] != current_user.department_id:
            flash("You are not authorized to delete this user.", "danger")
            return redirect(url_for('view_users'))

        # Proceed to delete the user
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_users'))

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
@role_required(1, 2)  # Allow only Super Admins and Department Admins
def create_project():
    """Create a new project."""
    if request.method == 'POST':
        project_name = request.form['project_name']
        department_id = request.form['department_id']

        # Ensure type consistency
        try:
            department_id = int(department_id)
        except ValueError:
            flash("Invalid department selection.", "danger")
            return redirect(url_for('create_project'))

        # Restrict Department Admin to their department
        if current_user.role_id == 2 and department_id != int(current_user.department_id):
            flash("You can only create projects for your own department.", "danger")
            return redirect(url_for('create_project'))

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            print(f"Inserting project: {project_name}, department_id: {department_id}")
            cur.execute(
                """
                INSERT INTO projects (name, department_id)
                VALUES (%s, %s)
                """,
                (project_name, department_id),
            )
            conn.commit()
            flash('Project created successfully!', 'success')
        except psycopg2.Error as e:
            conn.rollback()
            print(f"Database error: {e.pgcode}, {e.pgerror}")
            flash(f'Error creating project: {str(e)}', 'danger')
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('view_projects'))

    # Fetch departments for the dropdown
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if current_user.role_id == 1:
            # Super Admin can select from all departments
            cur.execute("SELECT dnumber, dname FROM department")
        else:
            # Department Admin only sees their own department
            cur.execute("SELECT dnumber, dname FROM department WHERE dnumber = %s", (current_user.department_id,))
        departments = cur.fetchall()
        print("Departments fetched for dropdown:", departments)
    except psycopg2.Error as e:
        departments = []
        flash("Unable to fetch departments.", "danger")
    finally:
        cur.close()
        conn.close()

    return render_template('create_project.html', departments=departments, current_department=current_user.department_id)


@app.route('/projects', methods=['GET', 'POST'])
@login_required
@role_required(1, 2, 3)
def view_projects():
    if request.method == 'POST':
        view_projects.filterDepartmentId = request.form['department_id']
        return redirect(url_for('view_projects'))

    conn = get_db_connection()
    cur = conn.cursor()

    if current_user.role_id == 1:  # Super Admin
        if view_projects.filterDepartmentId is not None:
            query = "SELECT * FROM DepartmentProjects WHERE department_id = %s"
            cur.execute(query, (view_projects.filterDepartmentId,))
            view_projects.filterDepartmentId = None
        else:
            query = "SELECT * FROM DepartmentProjects"
            cur.execute(query)
    else:  # Department Admin or Normal User
        query = "SELECT * FROM DepartmentProjects WHERE department_id = %s" # get department id to further filter table
        cur.execute(query, (current_user.department_id,)) 

    projects = cur.fetchall()

    departments = []
    if current_user.role_id == 1: # Super Admin
        # Fetch departments for the dropdown
        try:
            # Super Admin can select from all departments
            cur.execute("SELECT dnumber FROM department")
            departments = cur.fetchall()
            print("Departments fetched for dropdown:", departments)
        except psycopg2.Error as e:
            print(f"Error fetching departments: {e.pgcode}, {e.pgerror}")
            flash("Unable to fetch departments.", "danger")

    cur.close()
    conn.close()

    return render_template('projects.html', projects=projects, departments=departments)
view_projects.filterDepartmentId = None

@app.context_processor
def inject_user():
    return {'current_user': current_user}

if __name__ == '__main__':
    app.run(debug=True)
