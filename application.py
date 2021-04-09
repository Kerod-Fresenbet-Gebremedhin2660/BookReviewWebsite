import os
import random
from flask import Flask, render_template, session, flash, jsonify, url_for, redirect
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_login import UserMixin

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
if not os.getenv("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY is not set")

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
# db = scoped_session(sessionmaker(bind=engine))
db = SQLAlchemy(app)


# Model
class UserModel(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255), unique=True)

    def __init__(self, username, password):
        self.id = random.randint(1000, 100000)
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User %r>' % self.username


class NameForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, UserModel=UserModel, app=app)


@app.route('/')
def landing_page():
    return render_template('landing_page.html')


@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    name_form = NameForm()
    if name_form.validate_on_submit():
        query_user = UserModel.query.filter_by(username=str(name_form.email.data)).first()
        if query_user is None:
            hashed_password = generate_password_hash(str(name_form.password.data), "sha256")
            new_user = UserModel(name_form.email.data, hashed_password)
            name_form.email.data = ''
            name_form.password.data = ''
            db.session.add(new_user)
            db.session.commit()
            session['username'] = name_form.email.data
        else:
            name_form.email.data = ''
            name_form.password.data = ''
            return jsonify({"message": "Email is already associated with a user"})
    name_form.email.data = ''
    name_form.password.data = ''
    return render_template('signup.html', name_form=name_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    name_form = NameForm()
    if name_form.validate_on_submit():
        username = name_form.email.data
        password = str(name_form.password.data)
        if session.get('username') is username:
            flash('You are already logged in', 'danger')
            return render_template('protected.html')
        user_db = UserModel.query.filter_by(username=name_form.email.data).first()
        if user_db is not None:
            if check_password_hash(str(user_db.password), password):
                print(user_db.password)
                print(password)
                session['username'] = name_form.email.data
                name_form.email.data = ''
                name_form.password.data = ''
                return render_template('protected.html')
            else:
                name_form.email.data = ''
                name_form.password.data = ''
                return jsonify({"message": "Sign Up"})
        else:
            name_form.email.data = ''
            name_form.password.data = ''
            return jsonify({"message": "No Such User"})
    return render_template("login.html", name_form=name_form)


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
        return redirect(url_for('landing_page'))

