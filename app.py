from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask.logging import create_logger
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret key'
log = create_logger(app)

# Config MySQl
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# initMySQL
mysql = MySQL(app)


Articles = Articles()


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    return render_template('articles.html', articles=Articles)


@app.route('/article/<string:id>')
def article(id):
    return render_template('article.html', id=id)


class RegisterForm(Form):
    name = StringField('Nome', [validators.Length(min=1, max=50)])
    username = StringField('Usuário', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Senha', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Senhas devem ser iguais!')
    ])
    confirm = PasswordField('Confirme a Senha')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Cria cursor
        cur = mysql.connection.cursor()

        cur.execute('INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)',
                    (name, email, username, password))

        # Commit
        mysql.connection.commit()

        # Fecha a conexão
        cur.close()

        flash('Vocês está registrado e pode fazer login', 'success')

        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Obtem os campos do form
        username = request.form['username']
        password_candidate = request.form['password']

        # Cria cursor
        cur = mysql.connection.cursor()

        # Obtem usuário
        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Obtem hash
            data = cur.fetchone()
            password = data['password']

            # Compara as senhas
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('Vocês está logado', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Login inválido'
                return render_template('login.html', error=error)

            cur.close()
        else:
            error = 'Usuário não foi encontrado'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Checa se usuário está logado


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Acesso negado, por favor faça login', 'danger')
            return redirect(url_for('login'))

    return wrap


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Você fez logout', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)
