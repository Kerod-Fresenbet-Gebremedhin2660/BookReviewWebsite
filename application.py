import os
import random
import requests
import json
from flask import Flask, render_template, session, flash, jsonify, url_for, redirect, request, make_response
from flask_session import Session
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, IntegerField, TextAreaField, RadioField
from wtforms.validators import DataRequired, Email, NumberRange, Length
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from functools import wraps
from flask_bootstrap import Bootstrap
import config

app = Flask(__name__)
bootstrap = Bootstrap(app)

app.config['SECRET_KEY'] = config.SECRET_KEY
# Configure session to use filesystem
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URL
Session(app)

# Set up database
engine = create_engine(config.DATABASE_URL, pool_size=10, max_overflow=20)
db = scoped_session(sessionmaker(bind=engine))


class NameForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class Search(FlaskForm):
    radio_field = RadioField(label='Search By', choices=[('ISBN', 'ISBN'), ('TITLE', 'TITLE'), ('AUTHOR', 'AUTHOR')])
    book_search = StringField('Search for Book using ISBN', validators=[DataRequired()])
    submit = SubmitField('Search')


class Review(FlaskForm):
    rating = IntegerField('Enter your rating out of 5', validators=[NumberRange(min=0, max=5)])
    review = TextAreaField('Enter your review here', validators=[Length(min=30, max=10000)])
    submit = SubmitField('Submit Review')


def handler(isbn):
    open_lib_request = requests.get(
        'https://openlibrary.org/api/books?bibkeys=ISBN:' + str(isbn) + '&jscmd=details&format=json').content
    open_lib_request = json.loads(open_lib_request.decode('utf-8'))
    open_lib_request = open_lib_request.get('ISBN:' + str(isbn))
    # Data to be sent to the template
    publishers = {"publishers": str(open_lib_request.get('details').get('publishers')).strip("['']")}
    nop = {"pages": str(open_lib_request.get('details').get('number_of_pages')).strip("['']")}
    if nop is None:
        nop = {"date": str(open_lib_request.get('details').get('publish_date')).strip("['']")}

    return {"pub": publishers, "nop": nop}


def detail_fetcher(isbn):
    """
    For Fetching details on the books from Remote API Open Library
    :param isbn:
    :return: title, first sentence and book cover, isbn
    :return: also returns 0s if the API can not resolve the ISBN
    """
    title = get_title(isbn)
    first_sentence = get_first_sentence(isbn)
    open_lib_cover = "http://covers.openlibrary.org/b/isbn/" + str(isbn) + "-L.jpg"
    return {"title": title, "fs": first_sentence, "olc": open_lib_cover, "isbn": isbn}


def get_title(isbn):
    pay_load = requests.get(
        "https://openlibrary.org/api/books?bibkeys=ISBN:" + str(isbn) + "&jscmd=details&format=json").content
    pay_load = json.loads(pay_load.decode('utf-8'))

    if pay_load is None:
        return "There is no information available for this particular book."
    pay_load = pay_load.get('ISBN:' + str(isbn))
    if pay_load is None:
        return "There is no information available for this particular book."
    pay_load = pay_load.get('details')
    if pay_load is None:
        return "There is no information available for this particular book."
    title = pay_load.get('title')
    if title is None:
        return "There is no title information available for this particular book"
    return title


def get_first_sentence(isbn):
    pay_load = requests.get(
        "https://openlibrary.org/api/books?bibkeys=ISBN:" + str(isbn) + "&jscmd=details&format=json").content
    pay_load = json.loads(pay_load.decode('utf-8'))

    if pay_load is None:
        return "There is no information available for this particular book."
    pay_load = pay_load.get('ISBN:' + str(isbn))
    if pay_load is None:
        return "There is no information available for this particular book."
    pay_load = pay_load.get('details')
    if pay_load is None:
        return "There is no information available for this particular book."
    first_sentence = pay_load.get('first_sentence')
    if first_sentence is None:
        first_sentence = pay_load.get('details')
        if first_sentence is None:
            return "There is no information available for this particular book."
        first_sentence = first_sentence.get('description')[:20] + '...'
        return first_sentence
    first_sentence = first_sentence.get('value')
    return first_sentence


def goodreads(isbn):
    res = requests.get('https://www.goodreads.com/book/review_counts.json?k&isbns=' + isbn).content
    res = json.loads(res.decode('utf-8'))
    res = res.get('books')[0]

    reviews_count = res.get('reviews_count')
    ratings_count = res.get('ratings_count')
    average_score = res.get('average_rating')
    return {"rc": ratings_count, "rec": reviews_count, "avg": average_score}


# Custom Decorator to require login for session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        name_form = NameForm()
        if session.get('username') is None or session.get('logged_in') is False:
            flash("You need to be logged in!")
            return redirect(url_for('login', name_form=name_form))
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
@app.route('/home')
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
            return redirect(url_for('search', check='New Login'))
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
            flash("You are already logged in", "login")
            return redirect(url_for('search', check="Still in Session"))

        stmt = "SELECT * FROM public.\"Users\" WHERE username =:username"
        query = db.execute(stmt, {"username": name_form.email.data}).fetchone()
        if query is not None:
            if check_password_hash(query['password'], password):
                session['username'] = name_form.email.data
                session['logged_in'] = True
                name_form.email.data = ''
                name_form.password.data = ''
                return redirect(url_for('search', check="New Login"))
            else:
                name_form.email.data = ''
                name_form.password.data = ''
                flash("Improper Credentials", "login")
                return redirect(url_for('login'))
        else:
            name_form.email.data = ''
            name_form.password.data = ''
            return redirect(url_for('login'))
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
    remote_api_data = dict()
    if book_search.validate_on_submit():
        search_by = book_search.radio_field.data
        print(search_by)
        print(type(search_by))
        if search_by == 'ISBN':
            isbn = '%' + str(book_search.book_search.data) + '%'
            stmt = 'SELECT * FROM public.\"books\" WHERE isbn LIKE :isbn'
            try:
                query = db.execute(stmt, {"isbn": isbn}).fetchall()
            except ConnectionError:
                return jsonify(
                    message="The request could not be processed"
                )
            if not query:
                flash("Wrong Inputs!")
            return render_template('search.html', book_search=book_search, query=query)
        elif search_by == 'AUTHOR':
            author = str(book_search.book_search.data) + '%'
            stmt = 'SELECT * FROM public.\"books\" WHERE author LIKE :author'
            try:
                query = db.execute(stmt, {"author": author}).fetchall()
            except ConnectionError:
                return render_template('unauthorized.html')
            return render_template('search.html', book_search=book_search, query=query)
        elif search_by == 'TITLE':
            title = str(book_search.book_search.data)
            stmt = 'SELECT * FROM public.\"books\" WHERE title LIKE :title'
            try:
                query = db.execute(stmt, {"title": title + '%'}).fetchall()
            except ConnectionError:
                return render_template('unauthorized.html')
            return render_template('search.html', book_search=book_search, query=query)

    return render_template('search.html', book_search=book_search)


# TODO: Make sure to fix the API access
@app.route('/details/<string:isbn>', methods=['GET', 'POST'])
@login_required
def details(isbn):
    # Review Fetch from DB
    query = 'SELECT * FROM public.\"reviews\" WHERE fk_isbn = :isbn'
    res = db.execute(query, {"isbn": isbn}).fetchall()

    rev = Review()
    if rev.validate_on_submit():
        try:
            review(isbn, int(rev.rating.data), str(rev.review.data))
        except:
            flash("you have already submitted a review!")
            return redirect(url_for('landing_page'))

    rev.review.data = ''
    rev.rating.data = ''

    dets = detail_fetcher(isbn)
    more_dets = handler(isbn)
    counts = goodreads(isbn)
    return render_template('review.html', rev=rev, dets=dets, more_dets=more_dets, res=res, counts=counts)


# :TODO Make sure to test the search feature
@app.route('/api/v1/isbn/<string:isbn>')
@auth_required
def api_access(isbn):
    json_ret = {}
    ratings_count = goodreads(isbn).get("rec")
    average_score = goodreads(isbn).get("avg")

    isbn = isbn + '%'
    stmt = 'SELECT * FROM public.\"books\" WHERE isbn LIKE :isbn'
    query = db.execute(stmt, {"isbn": str(isbn)}).fetchall()
    if query is not None:
        for book in query:
            json_ret['book'] = serializer(book)
        json_ret = json_ret.get('book')
        json_ret['review_count'] = ratings_count
        json_ret['average_score'] = average_score
        return jsonify(json_ret)
    else:
        return jsonify(
            message="No Book Like that in the Database"
        )


# Auto Complete Search Endpoint
@app.route('/api/v1/isbn/<string:isbn>')
def ajax_endpoint(isbn):
    json_ret_aj = {}
    isbn = isbn + '%'
    stmt = 'SELECT * FROM public.\"books\" WHERE isbn LIKE :isbn'
    query = db.execute(stmt, {"isbn": str(isbn)}).fetchall()
    if query is not None:
        for book in query:
            json_ret_aj[book['isbn']] = serializer(book)
        return jsonify(json_ret_aj)
    else:
        return jsonify(
            message="No Book Like that in the Database"
        )


def serializer(obj):
    return dict(
        title=obj['title'],
        author=obj['author'],
        year=obj['year'],
        isbn=obj['isbn']
    )


@app.route('/review/<string:isbn>', methods=['GET', 'POST'])
@login_required
def review(isbn, rating, review):
    query_user = "SELECT * FROM public.\"Users\" WHERE username=:username"
    res = db.execute(query_user, {"username": session.get('username')}).fetchone()
    if res is not None:
        query = "INSERT into public.\"reviews\" (id, rating, review, fk_isbn, fk_id) VALUES(:id, :rating, :review, :fk_isbn, :fk_id)"
        fk_id = res['id']
        db.execute(query, {"id": random.randint(1, 10000), "rating": rating, "review": review,
                           "fk_isbn": isbn, "fk_id": fk_id})

        result = db.commit()
        if result is None:
            flash('A Review has already been submitted!')
    else:
        return redirect(unauthorized)


# :TODO Make this better
@app.errorhandler(401)
def unauthorized():
    return render_template('unauthorized.html')



