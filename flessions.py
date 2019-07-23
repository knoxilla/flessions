#!/usr/bin/env python

from flask import Flask, session, redirect, url_for, escape, request
from flask_session import Session

app = Flask(__name__)

# using flask_session to replace Flask.session
# will persist session dictionaries as string-valued keys
# (basically python pickles) to redis at 127.0.0.1:6379

# TIP to watch the set/get action while this app is running,
# enter 'redis-cli monitor' in another shell
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
Session(app)

# helpful for in-browser debugging - not really necessary
try:
    from flask_debugtoolbar import DebugToolbarExtension
    toolbar = DebugToolbarExtension()
    app.config['DEBUG_TB_ENABLED'] = True
    toolbar.init_app(app)
    print(">>>>>> Using sweet debug toolbar.")
except ImportError:
    pass

# now for the Box-y parts...
from boxsdk import OAuth2
from boxsdk import Client
from boxsdk.exception import BoxAPIException
from boxsdk.object.collaboration import CollaborationRole

import configparser
config = configparser.RawConfigParser()
config.read('boxapp.cfg')

CLIENT_ID = config.get('boxapp', 'CLIENT_ID')
CLIENT_SECRET = config.get('boxapp', 'CLIENT_SECRET')

# In the box developer console, set your app's callback URL to
#     http://localhost:5000/callback

GOHOME = 'Back to <a href="/">home page</a>.</p>'

## define various Flask routes

# start oauth-ing
@app.route('/auth/')
def authenticate(oauth_class=OAuth2):
    oauth = oauth_class(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )

    # where should they go?
    auth_url, csrf_token = oauth.get_authorization_url('http://localhost:5000/callback')
    # save so we can verify in the callback
    session['csrf_token'] = csrf_token
    # go get authorized
    return redirect(url_for('auth'))

# finish oauth-ing
@app.route('/callback')
def get_tokens(oauth_class=OAuth2):
    # welcome back 'friend', if that _is_ your real name
    # get the auth code so we can exchange it for an access token
    auth_code = {}
    auth_code['auth_code'] = request.args.get('code')
    auth_code['state'] = request.args.get('state')

    # does our nonce match up?
    print(auth_code['state'])
    print(session['csrf_token','nope'])
    #assert auth_code['state'] == session['csrf_token']

    oauth = oauth_class(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )

    # onwards!
    access_token, refresh_token = oauth.authenticate(auth_code['auth_code'])
    store_tokens(access_token, refresh_token)

    #return "<p>access_token: {} <br/>refresh_token: {}</p>".format(access_token, refresh_token)

    return redirect(url_for('index'))

# extracted to method b/c we can use it as a callback in the Oauth2() definition...
def store_tokens(access_token, refresh_token):
    session['access_token'] = access_token
    session['refresh_token'] = refresh_token

# Now that the access_token is in the session, we can construct a
# box client to act on behalf of the user.  only until the current
# session expires.

# TODO: But if we store a 'username' key based on Cosign or
# Shibboleth in redis, we can use that key to call up the access
# and refresh tokens per user each time they show up and login.

# simple box api invocation
@app.route('/whoami')
def whoami():
    # TODO extract this to a method so all routes can call it
    # IDEA flask has a 'run-method-pre-this-route' annotation...
    oauth = OAuth2(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_token=session['access_token'],
        refresh_token=session['refresh_token'],
    )
    client = Client(oauth)
    return whoami_guts(client) + GOHOME

def whoami_guts(client):
    # 'me' is a handy value to get info on the current authenticated user.
    me = client.user(user_id='me').get(fields=['login'])
    return ('<p>Box says your login name is: {0}</p>'.format(me['login']))

# another simple box api invocation
@app.route('/mystuff')
def mystuff():
    # TODO extract this to a method so all routes can call it
    oauth = OAuth2(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_token=session['access_token'],
        refresh_token=session['refresh_token'],
    )
    client = Client(oauth)
    return mystuff_guts(client) + GOHOME

def mystuff_guts(client):
    # 'me' is a handy value to get info on the current authenticated user.
    root = client.folder(folder_id='0').get()
    items = root.get_items(limit=50, offset=0)
    thegoods = ("<p>Box says these are some of your folders and items:</p>" +
             "<p>" +
             '<br/>'.join([item.name for item in items]) +
             "</p>")
    return thegoods

### just exercising redis sessions here.  get or set.

# storing session data in redis
@app.route('/set/<key>/<value>')
def set(key,value):
    session[key] = value
    return '<p>OK. <a href="/get/{}">Check it?</a></p>'.format(key)

# getting it back
@app.route('/get/<key>')
def get(key):
    return session.get(key, 'not set')

### playing with fake username data in redis

# landing page invites you to 'login', or remembers you if your
# redis session has not yet expired.
@app.route('/')
def index():
    if 'username' in session:
        # logged in?
        login_status = '''
            <p>Logged in as %s.  <a href="/logout">Logout</a></p>
            ''' % (escape(session['username']))
        # box authorized?
        box_auth_status = '''
            <p><a href="/auth/">Authorize Box?</a></p>
        '''
        if 'refresh_token' in session:
            box_auth_status = '''
                <p>Box authorized! <a href="/whoami">Use it</a>, and maybe <a href="/mystuff">use it again</a.</p>
            '''
        # tell 'em how it is
        return login_status + box_auth_status
    return '<p>You are not logged in.  <a href="/login">Login</a></p>'

# be who you were meant to be...
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('index'))
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>
    '''

# go back to oblivion...
# TODO would make sense to purse the session entirely here,
# but we're keeping it around until it expires naturally.
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))

# only invoked when running a la 'python <thisfile>.py'
# if you do 'flask run' you will not be in debug mode
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)

