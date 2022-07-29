from flask import Flask
from flask_mongoengine import MongoEngine
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_admin import Admin

app = Flask(__name__)
app.config.from_pyfile('conf.py')
db = MongoEngine(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
admin = Admin(app, name="receipts", template_mode="bootstrap3")

import receipts.views
