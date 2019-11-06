import sqlite3, os, subprocess, flask_login
from datetime import datetime
from flask import Flask, render_template, session, escape, request, Response, redirect, url_for, session, flash
from flask_login import current_user, login_user, logout_user
from flask_wtf import FlaskForm
from functools import wraps
from prettytable import PrettyTable
from sqlite3 import Error
from string import Template
from wtforms import TextAreaField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '|3]Ds=Ns+hS9:QG~}QQx>Yx.GhZzM9'
database = 'sqlite_database.db'

# login_manager = flask_login.LoginManager()
# login_manager.init_app(app)

# class User(flask_login.UserMixin):


#     # flask-login integration
#     def is_authenticated(self):
#         return True
#     def is_active(self):
#         return True
#     def is_anonymous(self):
#         return False
#     def get_id(self):
#         return self.id

#     pass

# @login_manager.user_loader
# def user_loader(user):
#     return user

# @login_manager.request_loader
# def request_loader(request):
#     user = User()
#     return user


# FORMS
class RegistrationForm(FlaskForm):
	username = StringField('Username', id='uname', validators=[DataRequired(), Length(min=3, max=15)])
	password = PasswordField('Password', id='pword', validators=[DataRequired()])
	tfa = StringField('tfa', id='2fa', validators=[Length(max=11)])
	submit = SubmitField('Register')

class LoginForm(FlaskForm):
	username = StringField('Username', id='uname', validators=[DataRequired(), Length(min=3, max=15)])
	password = PasswordField('Password', id='pword', validators=[DataRequired()])
	tfa = StringField('tfa', id='2fa', validators=[Length(max=11)])
	submit = SubmitField('Sign in')

class HistoryForm(FlaskForm):
    user = StringField('Username', id='uname')
    submit = SubmitField('Submit')

class SpellcheckForm(FlaskForm):
	text = StringField('Input text', id='inputtext', validators=[DataRequired()])
	submit = SubmitField('Submit')

class LoginHistory(FlaskForm):
	userid = StringField('', id='userid', validators=[DataRequired(), Length(min=3,max=15)])
	submit = SubmitField('Submit')

#******************************************************************************#
#******************************************************************************#
#******************************************************************************#

# DATABASE

# create connection to db
def sql_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn, create_table_sql):
    try:
        cr = conn.cursor()
        cr.execute(create_table_sql)
    except Error as e:
        print(e)
        
def create_users(conn, users):
    sql = "INSERT INTO users(name, password, tfa) VALUES(?,?,?)"
    cr = conn.cursor()
    cr.execute(sql, users)
    return cr.lastrowid

def create_admin(conn):
    sql = "INSERT INTO users(name, password, tfa) VALUES(?, ?, ?)"
    cr = conn.cursor()
    hash_pw = generate_password_hash("Administrator@1")
    user = ("admin", hash_pw, "12345678901")
    cr.execute(sql, user)
    return cr.lastrowid

def check_users(conn, user):
    try:
        cr = conn.cursor()
        cr.execute("SELECT name FROM users WHERE name = ?", (user,))
        data = cr.fetchone()
        if data is None:
            return True
        elif user == data[0]:
            return False
        else:
            return True
    except Error as e:
        print(e)
        
def store_text(conn, user, text, result):
    sql = "INSERT INTO text(user, submitted_text, result_text) VALUES(?, ?, ?)"
    cr = conn.cursor()
    cr.execute(sql, (user, text, result))
    return cr.lastrowid

# log user in and log user out time
def log_time(conn, log, user):
    print(log)
    if log == 'login':
        cr = conn.cursor()
        cr.execute("SELECT * FROM timestamp WHERE user = ? AND logout_time = 'N/A'", (user,))
        data = cr.fetchall()
        if len(data) is not 0:
            return 'User is already logged in'
        else:
            cr.execute("INSERT INTO timestamp(user, login_time, logout_time) values (?,?,?)", (user, datetime.now(), "N/A"))
        return cr.lastrowid
    if log == 'logout': # logout
        cr = conn.cursor()
        cr.execute("SELECT * FROM timestamp WHERE user = ? AND logout_time = 'N/A'", (user,))
        data = cr.fetchone()
        if data[3] == 'N/A':
            print('found')
            time = datetime.now()
            cr.execute("UPDATE timestamp SET logout_time = ? WHERE logout_time = 'N/A' AND user = ?", (time, user,))

# retireve histroy
def retrieve_queries(conn, user):
    cr = conn.cursor()
    cr.execute("SELECT * FROM text WHERE user = ?", (user,))
    data = cr.fetchall()
    for i in data:
        print()
    return data


def spellcheck():
	data = subprocess.check_output("./a.out ./text.txt ./wordlist.txt", shell=True)
	redata = data.decode().strip().replace("\n",", ")
	return redata
    # data = subprocess.check_output("./a.out {0} ./wordlist.txt".format(data), shell=True)


#******************************************************************************#
#******************************************************************************#
#******************************************************************************#

# ROUTES

@app.before_request
def before_request():
    if not os.path.exists(database):
        sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY,
                                        name text NOT NULL,
                                        password text NOT NULL,
                                        tfa text
                                        ); """
        
        sql_create_text_table = """ CREATE TABLE IF NOT EXISTS text (
                                        id integer PRIMARY KEY,
                                        user text NOT NULL,
                                        submitted_text text NOT NULL,
                                        result_text text NOT NULL
                                ); """

        sql_create_textresults_table = """ CREATE TABLE IF NOT EXISTS results (
                                            id integer PRIMARY KEY,
                                            spellcheck_results text NOT NULL
                                ); """

        sql_create_timestamp_table = """ CREATE TABLE IF NOT EXISTS timestamp (
                                            id integer PRIMARY KEY,
                                            user text NOT NULL,
                                            login_time date,
                                            logout_time date
                                ); """
        # create tables 
        with sqlite3.connect(database) as conn:
            create_table(conn, sql_create_users_table)
            print('created the users table')
            create_table(conn, sql_create_timestamp_table)
            print('created the timestamp table')
            create_table(conn, sql_create_text_table)
            print('created the text table')
            create_table(conn, sql_create_textresults_table)
            print('created the results table')
            create_admin(conn)
        conn.close()
    else:
        print('database exists')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        usr = form.username.data
        psw = form.password.data
        tfa = form.tfa.data
        # establish DB connection
        with sqlite3.connect(database) as conn:
            ind = check_users(conn, usr)
            # ? add date acct created ?
            if ind:
                psw_hash = generate_password_hash(psw)
                if tfa == '':
                    user = (usr, psw_hash, '')
                    create_users(conn, user)
                    success_status = 'Success, account has been created'
                    return render_template('register.html', title='Register', form=form, success_status=success_status)
                else:
                    user = (usr, psw_hash, tfa)
                    create_users(conn, user)
                    success_status = 'Success, account has been created'
                    return render_template('register.html', title='Register', form=form, success_status=success_status)
            else:
                failure_status = 'Failure, username must be unique'
                return render_template('register.html', title='Register', form=form, failure_status=failure_status)
            conn.close()
    else:
        return render_template('register.html', title='Register', form=form)

# LOGIN_REQUIRED
def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'username' in session:
			return f(*args, **kwargs)
		else:
			flash('You need to login first.')
			return redirect(url_for('login'))
	return wrap

@app.route('/')
def index():
    if 'username' in session:
        return 'Logged in as %s' % escape(session['username'])
    return 'You are not logged in'

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    # flask_login.logout_user()
    current_user = escape(session['username'])
    session.pop('username', None)
    with sqlite3.connect(database) as conn:
        log_time(conn, 'logout', current_user)
    conn.close()
    flash('You are now logged out')
    return redirect(url_for('login'))

# LOGIN
@app.route('/login', methods=['GET','POST'])
def login():
    # print('user is already authenticated')
    # if current_user.is_authenticated:
    #     return redirect(url_for('spell_check'))
    form = LoginForm()
    if form.validate_on_submit():
        usr = form.username.data
        psw = form.password.data
        tfa = form.tfa.data
        # establish DB connection 
        with sqlite3.connect(database) as conn:
            cr = conn.cursor()
            cr.execute("SELECT * FROM users WHERE name = ?", (usr,))
            data = cr.fetchone()
            # need to set user login timer to N/A
            if data is None:
                result = 'Incorrect - username and password DO NOT match'                
                return render_template('login.html', title='Sign in', form=form, result=result)
            if usr == data[1]:
                print(data)
                psw_check = check_password_hash(data[2], psw)
                if tfa == '':
                    if usr == data[1] and psw_check:
                        # flask_login.login_user(usr)
                        session['username'] = usr
                        log_time(conn, 'login', usr)
                        result='Success - username, password, and tfa match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    else:
                        result = 'Incorrect - username and password DO NOT match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                else:
                    if usr == data[1] and psw_check and data[3] == tfa:
                        # flask_login.login_user(usr)
                        session['username'] = usr
                        log_time(conn, 'login', usr)
                        result='Success - username, password, and tfa match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    elif usr == data[1] and psw_check and data[3] != tfa:
                        result='Incorrect - tfa is incorrect'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    else:                        
                        result = 'Incorrect - username and password DO NOT match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
            conn.close()
    return render_template('login.html', title='Sign in', form=form)

# @login_manager.unauthorized_handler
# def unauthorized_handler():
#     return 'Unauthorized'

# SPELLCHECK
@app.route('/spell_check', methods=['GET','POST'])
@login_required
def spell_check():
    form = SpellcheckForm()
    if form.validate_on_submit():
        text = form.text.data
        f = open("text.txt","w")
        f.write(text)
        f.close()
        results = spellcheck()
        current_user = escape(session['username'])
        with sqlite3.connect(database) as conn:
            store_text(conn, current_user, text, results)
        conn.close()
        return render_template('spell_check.html', title='Misspelled', form=form, results=results, text=text)
    else:
        return render_template('spell_check.html', title='Spellcheck', form=form)


# HISTORY 
# display number of queries
# be able to view user's queries each with their respective query id
@app.route('/history')#, methods=['GET','POST'])
# @app.route('/history/<query>')
def history():
    form = HistoryForm()
    current_user = escape(session['username'])
    with sqlite3.connect(database) as conn:
        # store list of queries
        query = retrieve_queries(conn, current_user)
        numqueries = len(query)
        for i in query:
            print(i)
    return render_template('history.html', title='History', form=form, numqueries=numqueries, query=query)

@app.route('/history/<query>')
def query(query):
    '''
    1. The query id in an element with id=queryid
    2. The username of the account that submitted the query in an element with id=username
    3. The query text in an element with id=querytext
    4. The query results in an element with id=queryresults
    '''
    with sqlite3.connect(database) as conn:
        queryid = 8
        cr = conn.cursor()
        cr.execute("SELECT * FROM text WHERE id = ?", (queryid,))
        data = cr.fetchone()
        username = data[1]
        querytext = data[2]
        queryresult = data[3]
        # query = retrieve_queries(conn, current_user)
    conn.close()
    return render_template('query.html', queryid=queryid, username=username, querytext=querytext, queryresult=queryresult)

@app.route('/login_history', methods=['GET','POST'])
def login_history():
    form = LoginHistory()
    if form.validate_on_submit():
        usr = form.userid.data
        with sqlite3.connect(database) as conn:
            cr = conn.cursor()
            cr.execute("SELECT * FROM timestamp WHERE user = ?", (usr,))
            data = cr.fetchall()
            table = PrettyTable(["LOGIN ID", "USERNAME", "LOGIN TIME", "LOGOUT TIME"])
            i = 0
            for item in range (len(data)):
                word = 'login{}'.format(data[i][0])
                table.add_row([word, data[i][1], data[i][2], data[i][3]])
                i += 1
            print(table)
        return render_template('login_history.html', form=form, tbl=table.get_html_string(attributes = {"class": "foo"}))
    else:
        return render_template('login_history.html', form=form)

# each query id is clickable to enter a review page or the text & result
    # subpage history/query#
    # subpage will display query id; username of the acct; query text; query result
    # NULL query empty page


# if user is ADMIN then can view all queries


#******************************************************************************#
#******************************************************************************#
#******************************************************************************#

# MAIN

def main():
    
    # create a db connection
    with sqlite3.connect(database) as conn:
        # find user 
        # results = check_users(conn, 'user')
        # print(results)
        # create_admin(conn)
        # current_user = escape(session['username'])
        # data = retrieve_queries(conn, 'wonton')
        # print(len(data))
        # for i in data:
        #     print(i)

        queryid = 8
        cr = conn.cursor()
        cr.execute("SELECT * FROM text WHERE id = ?", (queryid,))
        data = cr.fetchone()
        # username = data[1]
        # querytext = data[2]
        # queryresult = data[3]
        print(data[0])
        # usr = 'wonton'
        # psw = 'qwe'
        # tfa = 'qwe'
        # # this loops through and find per unit
        # c.execute("SELECT * FROM users WHERE name = ?", (usr,))
        # data = c.fetchone()
        # print(data[2])
        # for name in data:
        #     print('')
        #     if usr == data[0][1]:
        #         psw_check = check_password_hash(name[2], psw)
        #         if tfa == '':
        #             if usr == data[0][1] and psw_check:
        #                 print('username and password match')
        #             else:
        #                 print('username and password DO NOT match')
        #         else:
        #             if usr == data[0][1] and psw_check and data[3] == tfa:
        #                 print('username, password, and tfa match')
        #             elif usr == data[0][1] and psw_check  and data[3] != tfa:
        #                 print('tfa is incorrect')
        #             else:
        #                 print('username and password incorrect')

    conn.close()


if __name__ == '__main__':
    app.run(debug=True)
    # main()