from . import app, bcrypt, admin
from receipts.models import User, Receipt, Student
from flask_admin.contrib.mongoengine import ModelView
from receipts.forms import Register, Login
from flask import request, redirect, url_for, render_template
from flask_login import current_user, login_user, logout_user, confirm_login, login_required
from wtforms import PasswordField, Field
from wtforms.widgets import PasswordInput

@app.route("/register", methods=['GET','POST'])
def register():
    form = Register()
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                u = User(isAdmin=False,
                         email=form.email.data,
                         firstname=form.firstname.data,
                         middlename=form.middlename.data,
                         lastname=form.lastname.data,
                         username=form.username.data,
                         password_hash=hashpass).save()
                login_user(u)
                return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET','POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('admin.index')) if current_user.isAdmin else redirect(url_for('index'))
    form = Login()
    if request.method == 'POST':
        if form.validate():
            check = User.objects(username=form.username.data).first()
            if check and bcrypt.check_password_hash(check.password_hash, form.password.data):
                login_user(check)
                return redirect(url_for('admin.index')) if current_user.isAdmin else redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route("/logout", methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/", methods=['GET'])
def entry():
    confirm_login()
    if current_user.isAdmin:
        print(current_user)
        return redirect(url_for('admin.index'))
    try:
        return redirect(url_for('index')) if current_user.is_authenticated else redirect(url_for('login'))
    except KeyError:
        return redirect(url_for('login'))

def get_all_names():
    return [(s.name,str(s.pk)) for s in Student.objects]


def get_all_ref():
    return [(r.refno,str(r.pk)) for r in Receipt.objects]

@app.route("/index", methods=['GET', 'POST'])
@login_required
def index():
    if request.method == "POST":
        print(request.form)
        search = request.form['refsearch']
        if request.form['nameref'] == 'name':
            return redirect(url_for('students', query=search))
        else:
            return redirect(url_for('receipt_view',refno=search))
    return render_template('index.html')

@app.route("/students/<query>", methods=['GET'])
@login_required
def students(query=None):
    page_num = int(request.args.get("page") or 1)
    paginated_students = Student.objects.paginate(page=page_num, per_page=15)
    if(query):
        print(query)
        collection = get_all_names()
        results = [c[1] for c in collection if query in c[0]]
        paginated_students = Student.objects(pk__in=results).paginate(page=page_num,per_page=15)
    return render_template('students.html', paginated_students=paginated_students)

@app.route("/student/<sid>", methods=['GET'])
@login_required
def student_view(sid=None):
    s = Student.objects.get_or_404(pk=sid)
    paginated_receipts = s.paginate_field('receipts', 1, per_page=5)
    return render_template('student.html',name=f"{s.firstname} {s.middlename} {s.lastname}",
                           paginated_receipts=paginated_receipts)

@app.route("/receipt/<refno>", methods=['GET'])
@login_required
def receipt_view(refno=None):
    receipt = Receipt.objects.get_or_404(refno=refno)
    return render_template('receipt.html', student=receipt.student, schoolyear=receipt.schoolyear, refno=receipt.refno)

class PasswordCreateField(Field):
    widget = PasswordInput()

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = bcrypt.generate_password_hash(str(valuelist[0])).decode('utf-8')

    def _value(self):
        return str(bcrypt.generate_password_hash(str(self.data)).decode('utf-8')) if self.data is not None else ""

class UserView(ModelView):
    column_list = ['isAdmin', 'email', 'username', 'firstname', 'lastname', 'middlename','password_hash']
    form_overrides = dict(password_hash=PasswordCreateField)
    column_searchable_list = ('email', 'username')


admin.add_view(ModelView(Student))
admin.add_view(ModelView(Receipt))
admin.add_view(UserView(User))
