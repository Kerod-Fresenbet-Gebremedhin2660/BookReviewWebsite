import os
import random
from flask import Flask, render_template, session, flash, jsonify, url_for, redirect
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, NumberRange
from flask_login import UserMixin
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from functools import wraps
from markupsafe import Markup

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

if not os.getenv("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY is not set")

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
# Configure session to use filesystem
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


# Model
# class UserModel(UserMixin, db.Model):
#     __tablename__ = 'Users'
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(255), unique=True)
#     password = db.Column(db.String(255), unique=True)
#
#     def __init__(self, username, password):
#         self.id = random.randint(1000, 100000)
#         self.username = username
#         self.password = password
#
#     def __repr__(self):
#         return '<User %r>' % self.username


class NameForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class Search(FlaskForm):
    book_search = StringField('Search for Book using ISBN', validators=[DataRequired()])
    submit = SubmitField('Search')


# Custom Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None or session.get('logged_in') is False:
            return render_template('landing_page.html')
        return f(*args, **kwargs)

    return decorated_function


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, app=app)


@app.route('/')
def landing_page():
    return render_template('landing_page.html')


@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    name_form = NameForm()
    if name_form.validate_on_submit():
        stmt = "SELECT username FROM public.\"Users\" WHERE username =:username"
        query = db.execute(stmt, {"username": name_form.email.data}).fetchone()
        if query is None:
            hashed_password = generate_password_hash(str(name_form.password.data), "sha256")
            ins_stmt = "INSERT into public.\"Users\" (id, username, password) VALUES(:id, :username, :password)"
            db.execute(ins_stmt, {"id": random.randint(10000, 100000), "username": name_form.email.data,
                                  "password": hashed_password})
            db.commit()
            name_form.email.data = ''
            name_form.password.data = ''
            session['username'] = name_form.email.data
            session['logged_in'] = True
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
        password = str(name_form.password.data)
        if session.get('username') == name_form.email.data:
            flash('You are already logged in', 'danger')
            return render_template('protected.html', check="Still in Session")

        stmt = "SELECT * FROM public.\"Users\" WHERE username =:username"
        query = db.execute(stmt, {"username": name_form.email.data}).fetchone()
        if query is not None:
            if check_password_hash(query['password'], password):
                session['username'] = name_form.email.data
                session['logged_in'] = True
                name_form.email.data = ''
                name_form.password.data = ''
                return render_template('protected.html', check="New Login")
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
        session['logged_in'] = False
        return redirect(url_for('landing_page'))


@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html')


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    book_search = Search()
    if book_search.validate_on_submit():
        isbn = str(book_search.book_search.data)
        stmt = 'SELECT * FROM public.\"books\" WHERE isbn = :isbn'
        query = db.execute(stmt, {"isbn": isbn}).fetchone()
        return render_template('book.html', query=query)
    return render_template('search.html', book_search=book_search)


@app.errorhandler(401)
def unauthorized():
    return render_template('unauthorized.html')


