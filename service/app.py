import os
import time
import redis
from flask import Flask, render_template, request, redirect, abort
from beaker.middleware import SessionMiddleware


def get_service_name():
    return os.getenv('MULTIPASS_SERVICE')


def get_token_db():
    return int(os.getenv('MULTIPASS_TOKEN_DB'))


def get_session_db():
    return int(os.getenv('MULTIPASS_SESSION_DB'))


app = Flask(__name__)
cache = redis.Redis(host='redis', port=6379, db=get_token_db())

session_options = {
    'session.cookie_domain': os.getenv('MULTIPASS_{0}_FQDN'.format(get_service_name().upper())),
    'session.cookie_expires': True,
    'session.cookie_path': '/',
    'session.httponly': True,
    'session.key': 'multipass_{0}_session'.format(get_service_name()),
    'session.secure': False,
    'session.serializer': 'json',
    'session.timeout': 3600,
    'session.type': 'redis',
    'session.url': 'redis:6379',
    'session.db': get_session_db()
}

app.wsgi_app = SessionMiddleware(app.wsgi_app, session_options)


def get_hit_count():
    retries = 5
    while True:
        try:
            return cache.incr('hits')
        except redis.exceptions.ConnectionError as exc:
            if retries == 0:
                raise exc
            retries -= 1
            time.sleep(0.5)


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


@app.route('/')
def index():
    accounts_fqdn = os.getenv('MULTIPASS_ACCOUNTS_FQDN')
    return render_template(
        'index.html',
        count=get_hit_count(),
        authenticated=is_authenticated(),
        username=get_username(),
        accounts_fqdn=accounts_fqdn,
        service_name=get_service_name()
    )


@app.route('/login')
def login():
    if is_authenticated():
        return redirect('/')

    token = request.args.get('token', None)
    if token is None:
        abort(401)

    key_name = 'multipass:{0}'.format(token)
    username = cache.get(key_name)
    if username is not None:
        cache.delete(key_name)
        username = username.decode('utf-8')
        start_login_session(username)
        close = request.args.get('close', 'no') == 'yes'
        return redirect('/close' if close else '/')
    else:
        abort(401)


@app.route('/logout')
def logout():
    if is_authenticated():
        drop_session()
    return redirect('/')


@app.route('/close')
def close():
    return render_template('close.html', service=get_service_name())


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
