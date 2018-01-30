import os
import json
import time
import urllib

from flask import Flask, url_for, redirect, \
    session
from flask_jwt import JWT, _jwt_required, current_identity
from flask_login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask import request
from werkzeug.security import safe_str_cmp

basedir = os.path.abspath(os.path.dirname(__file__))

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

"""App Configuration"""


class Auth:
    """Google Project Credentials"""
    CLIENT_ID = None
    CLIENT_SECRET = None
    REDIRECT_URI = 'http://{0}/gCallback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
    USER_INFO = 'https://www.googleapis.com/oauth2/v2/userinfo'
    TOKEN_INFO_URI = 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    SCOPE = ['profile', 'email']
    LIMIT_DOMAIN = None


class Config:
    """Base config"""
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"


def configure_app(client_id, client_secret, base_domain, limit_domain=None, app_to_configure=None):
    Auth.CLIENT_ID = client_id
    Auth.CLIENT_SECRET = client_secret
    Auth.REDIRECT_URI = Auth.REDIRECT_URI.format(base_domain)
    if limit_domain:
        Auth.LIMIT_DOMAIN = limit_domain
    if not app_to_configure:
        app_to_configure = Flask(__name__)

    app_to_configure.config.from_object(Config)

    # app_to_configure.before_request_funcs.setdefault(None, []).append(foo)

    Auth.APP = app_to_configure
    login_manager = LoginManager(app_to_configure)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"
    login_manager.user_callback = load_user

    jwt = JWT(app_to_configure, authenticate, identity)
    Auth.JWT = jwt

    app_to_configure.add_url_rule("/login", "login", login)
    app_to_configure.add_url_rule("/logout", "logout", logout)
    app_to_configure.add_url_rule("/gCallback", "gCallback", callback)

    return app_to_configure, login_manager


class User(UserMixin):
    def __init__(self, id, username=None, password=None):
        self.password = password
        self.username = username
        self.id = id


def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user


def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)


#users = [
#    User(1, 'user1', 'abcxyz'),
#    User(2, 'user2', 'abcxyz'),
#]

with open('myfile', 'a+') as f:
    lines = f.readlines()
    users = []
    for line in lines:
        elements = line.split(' ')
        users.append(User(*elements))

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}


def load_user(user_id):
    token = Auth.JWT.request_callback()
    if token:
        _jwt_required(Auth.APP.config['JWT_DEFAULT_REALM'])
        return current_identity

    access_token = json.loads(user_id)
    if access_token['expires_at'] < time.time():
        google = get_google_auth()
        resp = google.refresh_token(Auth.TOKEN_URI, refresh_token=access_token['refresh_token'],
                                    client_secret=Auth.CLIENT_SECRET, client_id=Auth.CLIENT_ID)
        return User(json.dumps(resp))
    google = get_google_auth(token=json.loads(user_id))
    resp = google.get(Auth.TOKEN_INFO_URI + urllib.quote_plus(
        access_token['access_token']))
    response_object = resp.json()
    if 'email' in response_object:
        user = User(user_id)
        user.email = response_object['email']
        if not Auth.LIMIT_DOMAIN or Auth.LIMIT_DOMAIN in user.email:
            return User(user_id)
    return None


""" OAuth Session creation """


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth


def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline', hd=Auth.LIMIT_DOMAIN, prompt='consent')
    session['oauth_state'] = state
    return redirect(auth_url)


def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
            resp = google.get(Auth.TOKEN_INFO_URI + urllib.quote_plus(
                token['access_token']))
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            user = User(json.dumps(token))
            user.email = user_data['email']
            if not Auth.LIMIT_DOMAIN or Auth.LIMIT_DOMAIN in user.email:
                login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'


@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    """APP creation and configuration"""
    app, login_manager = configure_app()


    @app.route('/')
    @login_required
    def index():
        return 'foo'


    app.run(threaded=True)
