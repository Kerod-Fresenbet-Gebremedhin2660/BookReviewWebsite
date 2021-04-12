from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from dictMaker import dictmaker
import os
from flask import Flask, render_template, request

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
# Configure session to use filesystem
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

books_list = dictmaker()
# print(books_list)
for i in range(len(books_list)):
    db.execute("INSERT into public.\"books\" (isbn, title, author, year) VALUES(:isbn, :title, :author, :year)",
               {"isbn": books_list[i].get('isbn'), "title": books_list[i].get('title'),
                "author": books_list[i].get('author'), "year": books_list[i].get('year')})
    db.commit()
