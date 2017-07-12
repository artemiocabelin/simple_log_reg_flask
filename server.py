from flask import Flask, render_template, request, session, flash, redirect
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "k3yb04rdc4t"

mysql = MySQLConnector(app, 'simple_log_reg')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=["POST"])
def register():
    form = request.form
    errors = []

    if len(form['first_name']) == 0:
        errors.append('Please enter your first name.')
    elif len(form['first_name']) < 2:
        errors.append('First name must be at least 2 letters long.')
    elif not form['first_name'].isalpha():
        errors.append('First name can only contain letters.')

    if len(form['last_name']) == 0:
        errors.append('Please enter your last name.')
    elif len(form['last_name']) < 2:
        errors.append('Last name must be at least 2 letters long.')
    elif not form['last_name'].isalpha():
        errors.append('Last name can only contain letters.')

    if len(form['email']) == 0:
        errors.append('Please enter your email.')
    elif not EMAIL_REGEX.match(form['email']):
        errors.append("Please enter a valid format email address.")

    if len(form['password']) == 0:
        errors.append('Please choose a password.')
    elif len(form['password']) < 8:
        errors.append('Password must be at least 8 characters long.')
    elif form['password'] != form['passconf']:
        errors.append("Password and confirmation fields must match.")

    if len(errors) > 0:
        #do some flash messaging here
        for error in errors:
            flash(error, 'errors')
    else:
        #if there were no errors lets add to the database.
        #but first lets check if that email already exists:
        check_email = mysql.query_db('SELECT * FROM users WHERE email = :email', {'email': form['email']})
        if len(check_email) > 0:
            flash("Account at that email already exists.", 'errors')
        else:
            #the email is not taken:

            query = '''INSERT INTO users
            (first_name, last_name, email, password, created_at, updated_at)
            VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())'''

            hashed_password = bcrypt.generate_password_hash(form['password'])
            data = {
                'first_name': form['first_name'],
                'last_name': form['last_name'],
                'email': form['email'],
                'password': hashed_password
            }

            try:
                user_id = mysql.query_db(query, data)
                flash("You have successfully registered! Please login to continue.", "success")
            except:
                flash("Something went wrong. :(", "errors")

    return redirect('/')

@app.route('/login', methods=["POST"])
def login():
    form = request.form
    if EMAIL_REGEX.match(form['email']):
        users = mysql.query_db('SELECT * FROM users WHERE email = :email', {'email': form['email']})
        if len(users) > 0:
            user = users[0]
            #if we get here check their password.
            if bcrypt.check_password_hash(user['password'], form['password']):
                #if this is true we have a valid login!
                session['current_user'] = user['id']
                flash("Successful login! Welcome!", "success")
                return redirect('/success')

    flash('Invalid login credentials.', 'errors')
    return redirect('/')

@app.route('/success')
def success():
    if 'current_user' not in session:
        #then kick them out!
        flash("You must be logged in to go there!", "errors")
        return redirect('/')

    current_user = mysql.query_db("SELECT * FROM users WHERE id = :id", {"id": session['current_user']})
    return render_template('the_wall.html', user=current_user[0])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

app.run(debug=True)
