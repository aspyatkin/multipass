import time
import os
import binascii
import redis
from flask import Flask, render_template, request, redirect, abort
from beaker.middleware import SessionMiddleware
import urllib.parse
import requests
import json


app = Flask(__name__)
cache = redis.Redis(host='redis', port=6379, db=1)

session_options = {
    'session.cookie_domain': os.getenv('MULTIPASS_ACCOUNTS_FQDN'),
    'session.cookie_expires': True,
    'session.cookie_path': '/',
    'session.httponly': True,
    'session.key': 'multipass_accounts_session',
    'session.secure': False,
    'session.serializer': 'json',
    'session.timeout': 3600,
    'session.type': 'redis',
    'session.url': 'redis:6379',
    'session.db': 2
}

app.wsgi_app = SessionMiddleware(app.wsgi_app, session_options)


def drop_session():
    request.environ['beaker.session'].delete()


def is_authenticated():
    return request.environ['beaker.session'].get('authenticated', False)


def get_username():
    return request.environ['beaker.session'].get('username', None)


def start_login_session(username):
    session = request.environ['beaker.session']
    session['authenticated'] = True
    session['username'] = username
    session.save()


def start_shared_session():
    session = request.environ['beaker.session']
    session['shared_service'] = request.args.get('service', None)
    session['shared_popup'] = request.args.get('popup', 'no') == 'yes'
    session.save()


def get_shared_service():
    return request.environ['beaker.session'].get('shared_service', None)


def is_shared_popup():
    return request.environ['beaker.session'].get('shared_popup', True)


def start_oauth_session(state_token):
    session = request.environ['beaker.session']
    session['oauth_state_token'] = state_token
    session.save()


def get_oauth_state_token():
    return request.environ['beaker.session'].get('oauth_state_token', None)


@app.route('/')
def index():
    return render_template('index.html', authenticated=is_authenticated(), username=get_username())


def valid_login(username, password):
    return username == 'vagrant' and password == 'vagrant'


def generate_token():
    return binascii.b2a_hex(os.urandom(16)).decode('ascii')


def issue_token(username):
    token = generate_token()
    key_name = 'multipass:{0}'.format(token)
    cache.set(key_name, username)
    cache.expire(key_name, 10)
    return token


def service_origin(service):
    if service == 'quark':
        return 'https://{0}'.format(os.getenv('MULTIPASS_QUARK_FQDN'))
    elif service == 'lepton':
        return 'https://{0}'.format(os.getenv('MULTIPASS_LEPTON_FQDN'))
    else:
        abort(401)


def service_url(service, token, close):
    return '{0}/login?token={1}&close={2}'.format(service_origin(service), token, 'yes' if close else 'no')


def token_flow():
    token = issue_token(get_username())
    return redirect(service_url(get_shared_service(), token, is_shared_popup()))


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if not is_authenticated() and request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            start_login_session(request.form['username'])
            if request.args.get('service', None) in ['quark', 'lepton']:
                start_shared_session()
                return token_flow()
            return redirect('/')
        else:
            error = 'Invalid username/password'

    if is_authenticated() and request.method == 'GET' and request.args.get('service', None) in ['quark', 'lepton']:
        start_shared_session()
        return token_flow()
    return render_template('login.html', error=error, authenticated=is_authenticated(), username=get_username())


@app.route('/logout')
def logout():
    if is_authenticated():
        drop_session()
    return redirect('/')


def initiate_oauth():
    start_oauth_session(generate_token())
    start_shared_session()

    params = {
        'display': 'popup',
        'client_id': os.getenv('FACEBOOK_CLIENT_ID'),
        'response_type': 'code',
        'scope': 'email',
        'redirect_uri': 'https://{0}/oauth'.format(os.getenv('MULTIPASS_ACCOUNTS_FQDN')),
        'state': get_oauth_state_token()
    }

    url = 'https://www.facebook.com/v{0}/dialog/oauth?{1}'.format(
        os.getenv('FACEBOOK_API_VERSION'),
        urllib.parse.urlencode(params)
    )
    return redirect(url)


def exchange_code(code):
    url = 'https://graph.facebook.com/v{0}/oauth/access_token'.format(
        os.getenv('FACEBOOK_API_VERSION')
    )
    params = {
        'code': code,
        'client_id': os.getenv('FACEBOOK_CLIENT_ID'),
        'client_secret': os.getenv('FACEBOOK_CLIENT_SECRET'),
        'redirect_uri': 'https://{0}/oauth'.format(os.getenv('MULTIPASS_ACCOUNTS_FQDN'))
    }
    r = requests.get(url, params=params)
    data = {}
    if r.status_code == 200:
        data = r.json()
    return data.get('access_token', None)


def obtain_user_info(access_token):
    url = 'https://graph.facebook.com/v{0}/me?fields=email,first_name,last_name'.format(
        os.getenv('FACEBOOK_API_VERSION')
    )
    headers = {'Authorization': 'Bearer {0}'.format(access_token) }
    r = requests.get(url, headers=headers)
    data = {}
    if r.status_code == 200:
        data = r.json()
    return data


def valid_user_info(user_info):
    return 'email' in user_info and 'first_name' in user_info and 'last_name' in user_info


def verify_oauth(state_token, code):
    if get_oauth_state_token() != state_token:
        app.logger.error('error 1')
        return abort(500)

    access_token = exchange_code(code)
    if access_token is None:
        app.logger.error('error 2')
        return abort(500)

    user_info = obtain_user_info(access_token)
    if not valid_user_info(user_info):
        app.logger.error('error 3')
        return abort(500)

    app.logger.debug('User info is ' + json.dumps(user_info))
    username = '{first_name} {last_name} <{email}>'.format(**user_info)
    start_login_session(username)

    if get_shared_service() in ['quark', 'lepton']:
        return token_flow()

    return redirect('/close')


@app.route('/oauth')
def oauth():
    if is_authenticated():
        if request.args.get('service', None) in ['quark', 'lepton']:
            start_shared_session()
            return token_flow()
        else:
            return redirect('/')
    else:
        if request.args.get('state', None) and request.args.get('code', None):
            return verify_oauth(request.args['state'], request.args['code'])
        else:
            return initiate_oauth()


@app.route('/close')
def close():
    return render_template('close.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
