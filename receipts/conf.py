import os
MONGODB_SETTINGS = {
    "host": os.environ['DB_HOST']
}
SECRET_KEY = os.environ['SECRET_KEY']
