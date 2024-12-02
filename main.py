from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_mysqldb import MySQL
import bcrypt
from MySQLdb.cursors import DictCursor

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.config['CURSORCLASS'] = 'DictCursor'
app.secret_key = 'jtsfxfcg'

mysql = MySQL(app)

# Register Form
class RegisterForm(FlaskForm):
    name = StringField("Vārds", validators=[DataRequired()])
    email = StringField("E-pasts", validators=[DataRequired(), Email()])
    password = PasswordField("Parole", validators=[DataRequired()])
    submit = SubmitField("Reģistrēties")

# Login Form
class LoginForm(FlaskForm):
    email = StringField("E-pasts", validators=[DataRequired(), Email()])
    password = PasswordField("Parole", validators=[DataRequired()])
    submit = SubmitField("Pieteikties")

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (form.email.data,))
        if cursor.fetchone():
            flash("E-pasts jau ir reģistrēts!", "danger")
            return redirect(url_for('register'))
        
        # Hashing password
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Inserting user into the database
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", 
                       (form.name.data, form.email.data, hashed_password))
        mysql.connection.commit()
        cursor.close()
        
        flash("Reģistrācija veiksmīga!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        # Fetch user from database
        cursor = mysql.connection.cursor(DictCursor)  # Specify DictCursor here
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()  # Always close your cursor after usage
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']  # Store user ID in session
            flash("Pieteikšanās veiksmīga!", "success")
            return redirect(url_for('index'))
        else:
            flash("E-pasts vai parole ir nepareizi.", "error")
    
    return render_template('login.html', form=form)


# Dashboard Route (only accessible if logged in)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    
    return render_template('dashboard.html', user=user)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    flash("Jūs esat veiksmīgi izlogojies.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
