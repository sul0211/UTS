from flask import Flask, render_template, request, redirect, session, url_for, flash
import pymysql
from Crypto.Cipher import DES
import base64
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# DES encryption/decryption functions
def pad(text):
    # Pad text to be a multiple of 8 bytes
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_password(password):
    # Generate a random key for DES
    key = os.urandom(8)  # 8 bytes key for DES
    cipher = DES.new(key, DES.MODE_ECB)
    padded_password = pad(password)
    encrypted_password = cipher.encrypt(padded_password.encode())
    return base64.b64encode(encrypted_password).decode(), base64.b64encode(key).decode()

def decrypt_password(encrypted_password, key):
    cipher = DES.new(base64.b64decode(key), DES.MODE_ECB)
    decrypted_password = cipher.decrypt(base64.b64decode(encrypted_password))
    return decrypted_password.decode().strip()

# Database connection function
def get_db_connection():
    return pymysql.connect(
        host="127.0.0.1",
        user="root",
        password="",
        db="motor",
        cursorclass=pymysql.cursors.DictCursor
    )

# Dashboard route
@app.route("/index")
def dashboard():
    if 'username' in session:
        return render_template("index.html", username=session['username'])
    else:
        flash("You must log in first.", "danger")
        return redirect('/')

# Login route
@app.route("/", methods=["GET", "POST"])
def checklogin():
    if request.method == "POST":
        Un = request.form['Username']
        Pw = request.form['Password']

        connection = get_db_connection()
        cursor = connection.cursor()

        query1 = "SELECT Username, Password, `Key` FROM users WHERE Username = %s"
        cursor.execute(query1, (Un,))
        row = cursor.fetchone()

        cursor.close()
        connection.close()

        if row:
            decrypted_password = decrypt_password(row['Password'], row['Key'])
            if decrypted_password == Pw:
                session['username'] = Un
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password.", "danger")
        else:
            flash("Invalid username or password.", "danger")

        return redirect("/")  # Redirect to login page on failure

    return render_template("login.html")  # Render login form on GET request

# Registration route
@app.route("/register", methods=["GET", "POST"])
def registerpage():
    if request.method == "POST":
        dUn = request.form['DUsername']
        dPw = request.form['DPassword']
        Uemail = request.form['EmailUser']
        # Encrypt the password
        encrypted_password, key = encrypt_password(dPw)
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            # Check if the username already exists
            cursor.execute("SELECT Username FROM users WHERE Username = %s", (dUn,))
            if cursor.fetchone():
                flash("Username already exists. Please choose another.", "danger")  # Show error message
                return redirect("/register")

            # Insert new user into the database
            query1 = "INSERT INTO users (Username, Password, Email, `Key`) VALUES (%s, %s, %s, %s)"
            cursor.execute(query1, (dUn, encrypted_password, Uemail, key))
            connection.commit()
            flash("Registration successful! You can now log in.", "success")  # Show success message
            return redirect("/")  # Redirect to login after registration
        except pymysql.MySQLError as e:
            print(f"MySQL error: {e}")  # Log MySQL error
            flash(f"An error occurred while trying to register: {e}", "danger")  # Show error message
        except Exception as e:
            print(f"General error: {e}")  # Log general errors
            flash("An unexpected error occurred. Please try again.", "danger")  # Show error message
        finally:
            cursor.close()
            connection.close()
    return render_template("register.html")  # Render registration form on GET request


# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "success")  # Show logout message
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
