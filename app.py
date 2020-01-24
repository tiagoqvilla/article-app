from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask.logging import create_logger
#from data import Articles
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


#Articles = Articles()

@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    # Cria o cursor
    cur = mysql.connection.cursor()

    # Obtem os artigos
    result = cur.execute('SELECT * FROM articles')

    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'Nenhum artigo foi encontrado!'
        return render_template('articles.html', msg=msg)

    # Fecha a conexão
    cur.close()


@app.route('/article/<string:id>')
def article(id):
    # Cria o cursor
    cur = mysql.connection.cursor()

    # Obtem os artigos
    result = cur.execute('SELECT * FROM articles WHERE id = %s', [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Classe Form Registrar
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
@is_logged_in
def logout():
    session.clear()
    flash('Você fez logout', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Cria o cursor
    cur = mysql.connection.cursor()

    # Obtem os artigos
    result = cur.execute('SELECT * FROM articles')

    articles = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'Nenhum artigo foi encontrado!'
        return render_template('dashboard.html', msg=msg)

    # Fecha a conexão
    cur.close()


# Classe Form Artigo
class ArticleForm(Form):
    title = StringField('Título', [validators.Length(min=1, max=200)])
    body = TextAreaField('Texto', [validators.Length(min=30)])


# Adiciona Artigo
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Cria cursor
        cur = mysql.connection.cursor()

        # Executa
        cur.execute('INSERT INTO articles(title, body, author) VALUES(%s,%s,%s)',
                    (title, body, session['username']))

        # Commit
        mysql.connection.commit()

        # Encerra a conexão
        cur.close()

        flash('Artigo criado!', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
