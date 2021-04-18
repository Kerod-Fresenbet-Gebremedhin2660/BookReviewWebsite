import os
import random
from flask import Flask, render_template, session, flash, jsonify, url_for, redirect, request, make_response
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, NumberRange, Length
from flask_login import UserMixin
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from functools import wraps
from markupsafe import Markup
from flask_bootstrap import Bootstrap

app = Flask(__name__)
bootstrap = Bootstrap(app)
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


class Review(FlaskForm):
    rating = IntegerField('Enter your rating out of 5', validators=[NumberRange(min=0, max=5)])
    review = TextAreaField('Enter your review here', validators=[Length(min=600, max=2000)])
    submit = SubmitField('Submit Review')


# Custom Decorator to require login for session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None or session.get('logged_in') is False:
            return render_template('landing_page.html')
        return f(*args, **kwargs)

    return decorated_function


# Custom Decorator to require login for user agent access through basic authentication
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        stmt = "SELECT * FROM public.\"Users\" WHERE username =:username"
        result = db.execute(stmt, {"username": auth.username}).fetchone()
        print(result)
        if auth and check_password_hash(result['password'], auth.password):
            return f(*args, **kwargs)

        return make_response('Could not verify your login!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return decorated


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
        return render_template('search_result.html', query=query)
    return render_template('search.html', book_search=book_search)


@app.route('/api/v1/isbn/<int:isbn>')
@auth_required
def api_access(isbn):
    stmt = 'SELECT * FROM public.\"books\" WHERE isbn=:isbn'
    query = db.execute(stmt, {"isbn": str(isbn)}).fetchone()
    print(query)
    if query is not None:
        return jsonify(
            isbn=query['isbn'],
            title=query['title'],
            author=query['author'],
            year=query['year']
        )
    else:
        return jsonify(
            message="No Book Like that in the Database"
        )


@app.route('/review/<isbn>', methods=['GET', 'POST'])
@login_required
def review(isbn):
    rev = Review()
    if rev.validate_on_submit():
        print(rev.review.data)
        query_user = "SELECT * FROM public.\"Users\" WHERE username=:username"
        res = db.execute(query_user, {"username": session.get('username')}).fetchone()
        if res is not None:
            query = "INSERT into public.\"reviews\" (id, rating, review, fk_isbn, fk_id) VALUES(:id, :rating, :review, :fk_isbn, :fk_id)"
            fk_id = res['id']
            db.execute(query, {"id": random.randint(1, 10000), "rating": rev.rating.data, "review": rev.review.data,
                               "fk_isbn": isbn, "fk_id": fk_id})
            db.commit()
        else:
            return redirect(unauthorized)
    return render_template('review.html', rev=rev)


@app.errorhandler(401)
def unauthorized():
    return render_template('unauthorized.html')
