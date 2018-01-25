import os
import json
import time
import urllib

from flask import Flask, url_for, redirect, \
    session, request
from flask_login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError

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
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    TOKEN_INFO_URI = 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    SCOPE = ['profile', 'email']



class Config:
    """Base config"""
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"




def configure_app(client_id, client_secret, base_domain, app_to_configure=None):
    Auth.CLIENT_ID = client_id
    Auth.CLIENT_SECRET = client_secret
    Auth.REDIRECT_URI = Auth.REDIRECT_URI.format(base_domain)
    if not app_to_configure:
        app_to_configure = Flask(__name__)

    app_to_configure.config.from_object(Config)

    login_manager = LoginManager(app_to_configure)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"
    login_manager.user_callback = load_user

    app_to_configure.add_url_rule("/login", "login", login)
    app_to_configure.add_url_rule("/logout", "logout", logout)
    app_to_configure.add_url_rule("/gCallback", "gCallback", callback)

    return app_to_configure, login_manager


class User(UserMixin):
    def __init__(self, id):
        self.id = id


def load_user(user_id):
    access_token = json.loads(user_id)
    if access_token['expires_at'] < time.time():
        google = get_google_auth()
        resp = google.refresh_token(Auth.TOKEN_URI, refresh_token=access_token['refresh_token'],
                                    client_secret=Auth.CLIENT_SECRET, client_id=Auth.CLIENT_ID)
        return User(json.dumps(resp))
    google = get_google_auth(token=json.loads(user_id))
    resp = google.get(Auth.TOKEN_INFO_URI + urllib.quote_plus(
        access_token['access_token']))
    if 'email' in resp.json():
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
        Auth.AUTH_URI, access_type='offline', hd='thrivehive.com', prompt='consent')
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
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = None
            if user is None:
                user = User(json.dumps(token))
                user.email = email
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
