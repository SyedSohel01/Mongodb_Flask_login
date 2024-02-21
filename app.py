from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_bootstrap import Bootstrap
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret_key" 
client = MongoClient("mongodb://localhost:27017/")
db = client["user_db"]
users_collection = db["users"]
Bootstrap(app)

# Define RegistrationForm
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# Define LoginForm
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    registration_form = RegistrationForm()
    login_form = LoginForm()
    return render_template('registration.html', registration_form=registration_form, login_form=login_form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    registration_form = RegistrationForm()

    if request.method == 'POST' and registration_form.validate():
        username = registration_form.username.data
        password = registration_form.password.data

        # Check if the username already exists
        if users_collection.find_one({'username': username}):
            return render_template('register.html', registration_form=registration_form, message="Username already exists! Choose another username.")

        hashed_password = generate_password_hash(password, method='sha256')

        users_collection.insert_one({'username': username, 'password': hashed_password})
        # Redirect to the login page after successful registration
        return redirect(url_for('login'))

    return render_template('register.html', registration_form=registration_form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()

    if request.method == 'POST' and login_form.validate():
        username = login_form.username.data
        password = login_form.password.data

        user = users_collection.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            # Redirect to the dashboard after successful login
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', login_form=login_form, message="Invalid username or password.")

    return render_template('login.html', login_form=login_form)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
