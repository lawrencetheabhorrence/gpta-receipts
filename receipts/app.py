from flask import Flask, render_template, url_for, redirect, flash, session
from flask_mongoengine import MongoEngine
from flask_mongoengine.wtf import model_form
from wtforms import ValidationError, PasswordField
from wtforms.validators import DataRequired
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, confirm_login, AnonymousUserMixin, UserMixin
from flask_admin import Admin
from flask_admin.contrib.mongoengine import ModelView
from flask_bootstrap import Bootstrap
# import mongoengine as me

app = Flask(__name__)
app.config.from_pyfile('conf.py')
db = MongoEngine(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
admin = Admin(app, name="receipts", template_mode="bootstrap3")

class Receipt(db.Document):
    label = db.StringField(max_length=250, required=False)
    refno = db.StringField(max_length=300, required=True)
    image = db.URLField()

class Student(db.Document):
    firstname = db.StringField(max_length=100, required=True)
    lastname = db.StringField(max_length=100, required=True)
    middlename = db.StringField(max_length=100, required=False, default="")
    batch = db.IntField(min_value=2023, max_value=2028)
    receipts = db.ListField(db.ReferenceField(Receipt))

    @property
    def name(self):
        return f"{self.firstname} {self.middlename} {self.lastname}"

class AnonymousUser(AnonymousUserMixin):
    @property
    def isAdmin(self):
        return False

class User(db.Document, UserMixin):
    isAdmin = db.BooleanField(required=True, default=False)
    email = db.EmailField(required=True, unique=True)
    firstname = db.StringField(max_length=100, required=False)
    lastname = db.StringField(max_length=100, required=False)
    middlename = db.StringField(max_length=100, required=False)
    username = db.StringField(max_length=25, required=True, unique=True)
    password_hash = db.StringField(required=True, db_field='password')

    def __init__(self, *args, **kwargs):
        db.Document.__init__(self, *args, **kwargs)

        if 'password' in kwargs:
            self.password = kwargs['password']

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

def check_password(form, field):
    user = User.objects.get_or_404(username=form.username.data)
    print(field, field.data)
    if not bcrypt.check_password_hash(user.password, field.data):
        raise ValidationError('Wrong username/password combination')

reg_form = model_form(User, only=['email','firstname','lastname','middlename','username','password'], field_args={"password": {"password": True}})
login_form = model_form(User, only=['username','password'])
login_form.password = PasswordField('password', [DataRequired(), check_password])

class UserView(ModelView):
    column_list = ['isAdmin', 'email', 'username', 'firstname', 'lastname', 'middlename', 'password']
    form_columns = ('isAdmin', 'email', 'username', 'firstname', 'lastname', 'middlename')
    form_extra_fields = {
        'password': PasswordField('password')
    }
    column_searchable_list = ('email', 'username')

admin.add_view(ModelView(Student))
admin.add_view(ModelView(Receipt))
admin.add_view(UserView(User))

login_manager.anonymous_user = AnonymousUser

@login_manager.user_loader
def load_user(uid):
    try:
        return User.objects.get(pk=uid)
    except:
        return None

@app.route("/register", methods=['GET','POST'])
def register():
    form = reg_form()
    if form.validate_on_submit():
        u = User(firstname=form.firstname,middlename=form.middlename,lastname=form.lastname,
             username=form.username, password=form.password)
        u.save()
        login_user(u)
        session['logged_in'] = True
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route("/login", methods=['GET','POST'])
def login():
    form = login_form()
    if form.validate_on_submit():
        session['logged_in'] = True
        user = User.objects.get_or_404(username=form.username.data)
        login_user(user)
        flash("Logged in successfully")
        if user.isAdmin:
            return redirect(url_for('admin.index'))
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    session['logged_in'] = False
    logout_user()
    return redirect(url_for('login'))

@app.route("/")
def entry():
    confirm_login()
    if current_user.isAdmin:
        print(current_user)
        return redirect(url_for('admin.index'))
    try:
        return redirect(url_for('index')) if current_user.is_authenticated else redirect(url_for('login'))
    except KeyError:
        return redirect(url_for('login'))

@app.route("/index", methods=['GET'])
@login_required
def index():
    return render_template('index.html')

@app.route("/students", methods=['GET'])
@login_required
def students():
    students = Student.objects.paginate(page=1, per_page=15)
    return render_template('students.html', paginated_students=students)

@app.route("/student/<sid>", methods=['GET'])
@login_required
def student_view(sid=None):
    s = Student.objects.get_or_404(pk=sid)
    paginated_receipts = s.paginate_field('receipts', 1, per_page=5)
    return render_template('student.html',name=f"{s.firstname} {s.middlename} {s.lastname}",
                           paginated_receipts=paginated_receipts)

@app.route("/receipt/<rid>", methods=['GET'])
@login_required
def receipt_view(rid=None):
    receipt = Receipt.objects.get_or_404(pk=rid)
    return render_template('receipt.html', student=receipt.student, label=receipt.label, refno=receipt.refno, url=receipt.url)
