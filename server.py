from flask import Flask, render_template, request, redirect, session, flash, url_for
from mysqlconnection import connectToMySQL
app=Flask(__name__)
from flask_bcrypt import Bcrypt
bcrypt=Bcrypt(app)

import re
EMAIL_REGREX= re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app.secret_key="klsjdlka"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=["POST"])
def register():
    is_valid=True
    if len(request.form["fname"]) <2:
        is_valid=False
        flash ("Require first name")
    if len(request.form["lname"]) <2:
        is_valid=False
        flash ("Require last name")
    if not EMAIL_REGREX.match(request.form['email']):
        is_valid=False
        flash("Invalid email")
    if len(request.form["password"]) <8:
        is_valid=False
        flash ("Password minimum length is 8 characters")
    if (request.form["password"]) != (request.form["pw_confirm"]):
        is_valid=False
        flash("Passwords must match. Try again")
    db=connectToMySQL("first_flask_mysql")
    query = "SELECT email from login_info;"
    em_result=db.query_db(query)
    for user in em_result:
        if user['email']== request.form['email']:
            is_valid=False
            flash("Email already used. Try another")
    if not is_valid:
        return redirect('/')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print("hashed password:", pw_hash)
        db=connectToMySQL("first_flask_mysql")
        query = "INSERT INTO login_info (first_name, last_name, email, pw) VALUES (%(fn)s,%(ln)s,%(em)s,%(pw)s);"
        data ={
            "fn": request.form["fname"],
            "ln": request.form["lname"],
            "em": request.form["email"],
            "pw": pw_hash
        }
    session['user_info']=db.query_db(query, data)
    return redirect ('/success')

@app.route('/success')
def success():
    db=connectToMySQL("first_flask_mysql")
    query = "SELECT * FROM login_info WHERE id= %(id)s"
    data ={
        "id": session['user_info']
    }
    user=db.query_db(query, data)
    return render_template('success.html', user=user)

@app.route('/login', methods=["POST"])
def login():
    db=connectToMySQL("first_flask_mysql")
    query="SELECT id, pw FROM login_info WHERE email = %(lem)s;" #checks if email is in db, returns id and pw
    data = {
        "lem": request.form['email']
    }
    info=db.query_db(query, data)
    pw_hash = bcrypt.check_password_hash(info[0]["pw"], request.form["pw"]) #see if password inputted is equal to hashed pw in db, returns boolean expression t/f
    if pw_hash: #reads if true, run commands below
        print("SUCCESS")
        session["user_info"]=info[0]["id"]
    print("info from query:", info)
    return redirect ('/success')
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
if __name__=="__main__":
    app.run(debug=True)