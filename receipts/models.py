from . import db, login_manager
from flask_login import AnonymousUserMixin, UserMixin

class Receipt(db.Document):
    schoolyear = db.StringField(max_length=9, required=False)
    refno = db.StringField(max_length=300, required=True)

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

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

login_manager.anonymous_user=AnonymousUser
