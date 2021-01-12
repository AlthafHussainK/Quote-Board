import os
from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import Column, Integer, String, Sequence, create_engine
from sqlalchemy.ext.declarative import declarative_base

from helpers import login_required

project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "quotes.db"))

app = Flask(__name__)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

app.config["SQLALCHEMY_DATABASE_URI"] = database_file


db = SQLAlchemy(app)
engine = create_engine('sqlite:///')
Base = declarative_base()

class Users(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    
class Quote(db.Model):
    id = db.Column(db.Integer, autoincrement=False)
    quote = db.Column(db.String, primary_key=True)
    author = db.Column(db.String)
    label = db.Column(db.String)

Base.metadata.create_all(engine)
   
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    session.clear()

    if request.method == 'POST':
        if not request.form.get("username"):
            return "Missing username."
        elif not request.form.get("password"):
            return "Missing password"
        elif request.form.get("password") != request.form.get("confirm_password"):
            return "Password does not match!"
        
        hash = generate_password_hash(request.form.get("password"))
        user = Users(username=request.form.get("username"), password=hash)
        db.session.add(user)   
        db.session.commit()

        return redirect("/login")
    return render_template("signup.html")

 
@app.route('/login', methods=['GET','POST'])
def login():

    session.clear()

    if request.method == 'POST':
        #username1 = request.form.get("username")
        if not request.form.get("username"):
            return "Must provide username"

        user = Users.query.filter_by(username=request.form.get("username")).first()
        
        if Users.query.filter_by(username=request.form.get("username")).first() is None :
            return "Username not found."
        if not request.form.get("password"):
            return "Must provide password"

        pwd = request.form.get("password")

        if not check_password_hash(user.password, pwd):
            return "Invalid password"
        
        session['user_id'] = user.id
       
        return redirect('/board')
    return render_template("login.html")


@app.route("/board", methods=["GET", "POST"])
@login_required   
def board():
    if request.method == "POST":
        quote = Quote(id=session['user_id'], quote=request.form.get("quote"), author=request.form.get("author"), label=request.form.get("label"))
        db.session.add(quote)
        db.session.commit()

    quotes = Quote.query.filter_by(id=session['user_id']).all()
    labels = db.engine.execute("SELECT DISTINCT label FROM quote WHERE id=:id", id=session['user_id'])
    authors = db.engine.execute("SELECT DISTINCT author FROM quote WHERE id=:id", id=session['user_id'])
   
    return render_template("board.html", quotes=quotes, labels=labels, authors=authors)

@app.route("/logout")
def logout():
    session.clear()

    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)