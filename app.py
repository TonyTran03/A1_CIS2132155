from flask import Flask, render_template, jsonify, request
from psycopg2 import sql
app = Flask(__name__) # this line creates a Flask app
@app.route('/')
def home():
    return render_template("index.html", name="FML")
DATABASE_CONFIG = {
"dbname": "postgres",
"user": "postgres",
"password": "Error#four0four!",
"host": "localhost",
"port": "5432"
}

import psycopg2
def get_db_connection():
    conn = psycopg2.connect(**DATABASE_CONFIG)
    return conn



# check if a user is a Super Admin
def is_super_admin(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role_id FROM Users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result and result[0] == 1
    except Exception as e:
        return False

@app.route('/account/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    user_id = data.get("user_id") 
    username = data.get("username")
    password = data.get("password")
    role_id = data.get("role_id") 
    department_id = data.get("department_id", None) 

    if not is_super_admin(user_id): 
        return jsonify({"error": "Unauthorized. Only Super Admins can create users."}), 403

    if role_id != 1 and department_id is None: 
        return jsonify({"error": "Non-Super Admin users must have a department_id"}), 400

    # Create the new user
    hashed_password = generate_password_hash(password)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        insert_query = sql.SQL("""
            INSERT INTO Users (username, password_hash, role_id, department_id)
            VALUES (%s, %s, %s, %s)
        """)
        cursor.execute(insert_query, (username, hashed_password, role_id, department_id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "User created successfully!"})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Username already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500






if __name__ == '__main__':
    app.run(debug=True)