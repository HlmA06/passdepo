from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=50)])
    password = PasswordField('Şifre', validators=[DataRequired()])
    confirm_password = PasswordField('Şifreyi Doğrula', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Hesap Oluştur')

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')

class PostForm(FlaskForm):
    content = TextAreaField('Metin Girin', validators=[DataRequired()])
    submit = SubmitField('Gönder')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class UserAdminView(ModelView):
    column_list = ['username', 'email']
    can_delete = True
    can_edit = True
    can_create = True

class PostAdminView(ModelView):
    column_list = ['content', 'author']
    can_delete = True
    can_edit = True
    can_create = True

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if not current_user.is_authenticated:
            return False
        return current_user.username == 'admin'

admin = Admin(app, index_view=MyAdminIndexView(), name='Admin Panel', template_mode='bootstrap3')
admin.add_view(UserAdminView(User, db.session))
admin.add_view(PostAdminView(Post, db.session))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Hesabınız Oluşturuldu! Giriş Yapabilirsiniz.', 'Başarılı')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Giriş Yapma Başarısız. Kullanıcı Adı Ve Şifreyi Kontrol Edin.', 'Hata')

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = PostForm()

    if form.validate_on_submit():
        post = Post(content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Gönderiniz Oluşturuldu!', 'Başarılı')

    posts = Post.query.filter_by(user_id=current_user.id).all()

    return render_template('dashboard.html', user=current_user, form=form, posts=posts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        flash('Sadece Kendi Gönderilerinizi Silebilirsiniz!', 'Hata')
        return redirect(url_for('dashboard'))

    db.session.delete(post)
    db.session.commit()
    flash('Gönderiniz Silindi!', 'Başarılı')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=3030)
