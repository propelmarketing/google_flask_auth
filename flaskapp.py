import os
from flask_login import login_required

from google_flask_auth import configure_app

app, login_manager = configure_app(os.environ.get('GOOGLE_CLIENT_ID'),
                                   os.environ.get('GOOGLE_CLIENT_SECRET'),
                                   'localhost:5000')


@app.route('/')
@login_required
def index():
    return 'foo'

app.run(threaded=True, debug=True)
