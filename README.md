# google_flask_auth
module that will add google oauth to a flask app

## Installation
```
pip install -e git+https://github.com/propelmarketing/google_flask_auth#egg=google_flask_auth
```
This will install from the github repository.

## Usage
```python
import os
from flask_login import login_required

from google_flask_auth import configure_app

app, login_manager = configure_app(os.environ.get('GOOGLE_CLIENT_ID'),
                                   os.environ.get('GOOGLE_CLIENT_SECRET'),)

# called in this way, you can pass your own app in.
#app, login_manager = configure_app(os.environ.get('GOOGLE_CLIENT_ID'),
#                                   os.environ.get('GOOGLE_CLIENT_SECRET'), app=app)


@app.route('/')
@login_required
def index():
    return 'foo'

app.run(threaded=True)

```
