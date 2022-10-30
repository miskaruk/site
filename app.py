from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
app = Flask(__name__)
app.secret_key = 'c4f8b4c494e4edb3f7336f45ab4cbd2f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Article %r>' % self.id


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1024), nullable=False)

    def __init__(self, text, tags):
        self.text = text.strip()
        self.tags = [
            Tag(text=tag.strip()) for tag in tags.split(',')
        ]


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(32), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    message = db.relationship('Message', backref=db.backref('tags', lazy=True))


class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, default = 0)

@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
@app.route('/home')
def index():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template("index.html", articles=articles)

@app.route('/add', methods=['POST','GET'])
def create_article():
    if current_user.is_authenticated:
        if current_user.login == "admin":
            if request.method == 'POST':
                title = request.form['title']
                intro = request.form['intro']
                text = request.form['text']

                article = Article(title=title, intro=intro, text=text)

                try:
                    db.session.add(article)
                    db.session.commit()
                    return redirect('/')
                except:
                    return "При добавлении произошла ошибка"

            else:
                return render_template("create-article.html")
        else:
            return "Отказано в доступе"
    else:
        return "Вы не вошли в систему"


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/gallery')
def gallery():
    return render_template("gallery.html")


@app.route('/directions')
def directions():
    return render_template("directions.html")


@app.route('/contacts')
def contacts():
    return render_template("contacts.html")

@app.route('/posts/<int:id>')
def post(id):
    article = Article.query.get(id)
    return render_template("post.html",article=article)

@app.route('/posts/<int:id>/del')
def post_del(id):
    if current_user.is_authenticated:
        if current_user.login == "admin":
            article = Article.query.get_or_404(id)
            try:
                db.session.delete(article)
                db.session.commit()
                return redirect('/')
            except:
                return "При удалении статьи произошла ошибка"
        else:
            return "Отказано в доступе"
    else:
        return "Вы не вошли в систему"
@app.route('/posts/<int:id>/update', methods=['POST','GET'])
def post_update(id):
    if current_user.is_authenticated:
        if current_user.login == "admin":
            article = Article.query.get(id)
            if request.method == 'POST':
                article.title = request.form['title']
                article.intro = request.form['intro']
                article.text = request.form['text']
                try:
                    db.session.commit()
                    return redirect('/')
                except:
                    return "При редактировании произошла ошибка"

            else:

                return render_template("post_update.html", article=article)
        else:
            return "Отказано в доступе"
    else:
        return "Вы не вошли в систему"
@app.route('/login', methods=['GET', 'POST'])
def login():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect("/")
        else:
            flash('Неверный логин или пароль!')
    else:
        flash('Введите логин и пароль!')
    return render_template("login.html")
@app.route('/registration', methods=['GET', 'POST'])
def registration():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Заполните все поля!')
        elif password != password2:
            flash('Пароли не совпадают!')
        else:
            user = User.query.filter_by(login=login).first()
            if user is not None:
                flash('Имя пользователя занято!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(login=login, password=hash_pwd)
                db.session.add(new_user)
                db.session.commit()
                return redirect("/")

    return render_template("registration.html")
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect("/")
@app.route('/user/<string:login>')
def user(login):
    return render_template("profile.html", login=login, score = 0)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)