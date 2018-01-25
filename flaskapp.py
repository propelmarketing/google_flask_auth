import os
from flask_login import login_required
from flask import Flask

from google_flask_auth import configure_app
app = Flask(__name__)
app, login_manager = configure_app(os.environ.get('GOOGLE_CLIENT_ID'),
                                   os.environ.get('GOOGLE_CLIENT_SECRET'),
                                   'localhost:5000',
                                   app_to_configure=app,
                                   limit_domain='thrivehive.com')


@app.route('/')
@login_required
def index():
    return 'foo'


app.run(threaded=True, debug=True)
