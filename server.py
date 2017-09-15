from flask import Flask, request, redirect, render_template, session, flash
import re
from mysqlconnection import MySQLConnector
import md5
import os, binascii 

app = Flask(__name__)
mysql = MySQLConnector(app,'the_wall')
app.secret_key = 'qwertyuiop123456789'

@app.route('/')
def index():
    if 'id' in session and 'user' in session:
        return render_template('index.html')
    else:
        session['id'] = ''
        session['user'] =''
        return render_template('index.html')

#####################################################
@app.route('/registration', methods=['POST'])
def user_register():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confir_pw = request.form['confir_pw']
    
    name_regex = re.compile(r'^[A-Z][a-z]+$')
    email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    pw_regex = re.compile(r'^[a-zA-Z0-9.+_-]{8,}$')
    count = 0
    # first name
    if len(first_name) < 1:
        flash(u'Your first name cannot be empty!',"error")
    else:
        if len(first_name) < 2:
            flash(u"Name should have at least 2 characters","error")
        else:
            if not name_regex.match(first_name):
                 flash(u"Incorrect name format","error")
            else:
                count += 1
    #last name
    if len(last_name) < 1:
        flash(u'Your first name cannot be empty!',"error")
    else:
        if len(last_name) < 2:
            flash(u"Name should have at least 2 characters","error")
        else:
            if not name_regex.match(last_name):
                 flash(u"Incorrect name format","error")
            else:
                count += 1

    #email
    if len(email) < 1:
        flash(u'Your email cannot be empty!',"error")
    else:
        if not email_regex.match(email):
            flash(u"Incorrect email format","error")
        else:
            query = "SELECT email FROM users"
            all_emails = mysql.query_db(query)
            email_found = False
            for the_email in all_emails:
                if email == the_email['email']:
                    found_email = True
                    flash(u"Email has been registered, please use other emails!","error")
            if not email_found:
                count += 1

    #Password
    if len(password) < 1:
        flash(u'Your password cannot be empty!',"error")
    else:
        if not pw_regex.match(password):
            flash(u"Password should have at least 8 characters!","error")
        else:
            count += 1

    # confir_pw
    if confir_pw != password:
        flash(u"Password confirmation do not match!","error")
    else:
        count += 1 


    if (count == 5):
        user_query ="INSERT INTO users (first_name,last_name,email,password,salt,created_at,updated_at) \
        VALUES (:first_name,:last_name,:email,:password,:salt,NOW(),NOW())"

        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(password + salt).hexdigest()

        data = {
                'first_name':first_name,
                'last_name':last_name,
                'email':email,
                'password':hashed_pw,
                'salt':salt,
        }
        mysql.query_db(user_query,data)

        current_query = "SELECT MAX(id) as id FROM users"
        user_id = mysql.query_db(current_query)
        session['id'] = user_id[0]['id']
        session['user'] = first_name+" "+last_name
        return redirect('/wall')

    return redirect('/')
########################################################################
@app.route('/login', methods=['POST'])
def user_login():
    login_email = request.form['login_email']
    login_pw = request.form['login_pw']
    email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    email_found = False

    if len(login_email) < 1:
        flash(u'Your email cannot be empty!',"error")
    else:
        if not email_regex.match(login_email):
            flash(u"Incorrect email format","error")
        else:
            query = "SELECT id, email FROM users"
            all_info = mysql.query_db(query)
            for info in all_info:
                if login_email == info['email']:
                    email_found = True
                    session['id'] = info['id']

    if email_found:
        if len(login_pw) < 1:
            flash(u'Your password cannot be empty!','error')
        else:
            query = "SELECT concat_ws(' ', first_name, last_name) as name,password, salt FROM users WHERE id = :id"
            query_data = {'id': session['id'],}
            users_info = mysql.query_db(query,query_data)
            encrypted_pw = md5.new(login_pw + users_info[0]['salt']).hexdigest()
            if encrypted_pw == users_info[0]['password']:
                session['user'] = users_info[0]['name']
                return redirect('/wall')
            else:
                flash(u'Your password is incorrect!','error')
                
    return redirect('/')


######################################################################
@app.route('/wall')
def the_wall():
    query = "SELECT messages.id,concat_ws(' ',first_name, last_name) as name, \
            date_format(messages.created_at, '%M %D %Y') as date, messages.message, users.id as u_id \
            FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC;"
    all_messages = mysql.query_db(query)

    query = "SELECT messages.id,concat_ws(' ',first_name, last_name) as name, \
            date_format(comments.created_at, '%M %D %Y') as date, comments.comment FROM \
            users JOIN comments ON users.id = comments.user_id JOIN messages ON \
            messages.id = comments.message_id ORDER BY comments.created_at DESC;"
    all_comments = mysql.query_db(query)

    return render_template('wall.html', all_messages = all_messages, all_comments = all_comments) 

#######################################################################
@app.route('/message',methods=['POST'])
def post_message():
    message = request.form['message']
    if len(message) < 1:
        flash(u'You did not write anything','error')
    else:
        query = "INSERT INTO messages (message,created_at,updated_at,user_id) \
                 VALUES (:message,NOW(),NOW(),:user_id)"
        data = {
                'message':message,
                'user_id':session['id'],
        }

        mysql.query_db(query,data)  


    return redirect('/wall')

##################################################################################        
@app.route('/comment',methods=['POST'])
def post_comment():
    comment = request.form['comment']
    message_id = request.form['message_id']
    if len(comment) < 1:
        flash(u'You did not write anything','error')
    else:
        query = "INSERT INTO comments (comment,created_at,updated_at,message_id,user_id) \
                 VALUES (:comment,NOW(),NOW(),:message_id,:user_id)"
        data = {
                'comment':comment,
                'message_id': message_id,
                'user_id':session['id'],
        }

        mysql.query_db(query,data)  


    return redirect('/wall')
#############################################################################################

@app.route('/delete',methods=['POST'])
def delete_message():
    
    delete_id = request.form['delete']
    query = "DELETE FROM comments WHERE message_id = :id"
    data = {'id':delete_id}
    mysql.query_db(query,data)

    query = "DELETE FROM messages WHERE id = :id"
    data = {'id':delete_id}
    mysql.query_db(query,data)
    
    
    return redirect('/wall')
####################################################################

@app.route('/logoff',methods=['POST'])
def logoff_user():
    session.clear()
    return redirect('/')

app.run(debug=True)
