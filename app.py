"""Standalone accounts and owner-scoped SQLite solve APIs."""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path
from flask import Flask, abort, g, jsonify, render_template, request, send_from_directory, session
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from database_interactions import initialize, get_db, close_db

ROOT = Path(__file__).parent

def create_app(config=None):
    app = Flask(__name__, static_url_path='')
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY'),
        DATABASE=os.environ.get('DATABASE_PATH', str(ROOT / 'instance' / 'cubetastic.sqlite3')),
        SESSION_COOKIE_NAME='cubetastic_session', SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') == '1',
        SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    if config:
        app.config.update(config)
    if not app.secret_key:
        raise RuntimeError('Set SECRET_KEY to a server-generated random secret.')
    if os.environ.get('TRUST_PROXY') == '1':
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    initialize(app.config['DATABASE'])
    app.teardown_appcontext(close_db)

    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def require_user():
        if g.user is None:
            abort(401, 'Sign in to access your account.')
        supplied = request.form.get('uid')
        if supplied is not None and supplied != g.user['id']:
            abort(403, 'This account does not own that data.')
        return g.user['id']

    def public_user(user):
        if user is None:
            return None
        return dict(uid=user['id'], username=user['username'], displayName=user['username'],
                    email=user['email'], **json.loads(user['profile']))

    def rate_limit(name, maximum, seconds=900):
        now = int(time.time())
        bucket = name + ':' + digest(request.remote_addr or 'unknown')
        with get_db() as db:
            db.execute('DELETE FROM rate_limits WHERE expires < ?', (now,))
            db.execute('INSERT INTO rate_limits VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1', (bucket, now + seconds))
            count = db.execute('SELECT count FROM rate_limits WHERE bucket=?', (bucket,)).fetchone()[0]
        if count > maximum:
            abort(429, 'Too many attempts. Please try again later.')

    def sign_in(uid):
        old_token = session.get('token')
        session.clear()
        session.permanent = True
        session['token'] = secrets.token_urlsafe(32)
        session['csrf'] = secrets.token_urlsafe(32)
        with get_db() as db:
            if old_token:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (digest(old_token),))
            db.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
            db.execute('INSERT INTO sessions VALUES (?,?,?)', (digest(session['token']), uid, int(time.time()) + 14 * 86400))

    def payload():
        data = request.get_json(silent=True) if request.is_json else request.form
        if not hasattr(data, 'get'):
            abort(400, 'Expected an object.')
        return data

    def text(data, key, maximum=500, required=False):
        value = data.get(key, '')
        if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
            abort(400, 'Invalid ' + key + '.')
        return value.strip()

    def password(data, key='password'):
        value = data.get(key, '')
        if not isinstance(value, str) or not 12 <= len(value) <= 256:
            abort(400, 'Use a password of 12-256 characters.')
        return value

    def integer(value, minimum=0, maximum=10**15):
        try:
            result = int(value)
        except (ValueError, TypeError, OverflowError):
            abort(400, 'Expected an integer.')
        if str(result) != str(value) or not minimum <= result <= maximum:
            abort(400, 'Number is outside the accepted range.')
        return result

    def safe_field(value, maximum):
        if not isinstance(value, str) or len(value) > maximum or any(c in value for c in '<>|\x00'):
            abort(400, 'Invalid solve text.')
        return value

    @app.before_request
    def authenticate():
        g.user = None
        token = session.get('token')
        if token:
            g.user = get_db().execute('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?', (digest(token), int(time.time()))).fetchone()
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            expected = session.get('csrf', '')
            actual = request.headers.get('X-CSRF-Token', '')
            if not expected or not secrets.compare_digest(expected, actual):
                abort(403, 'Refresh this page and retry (CSRF token required).')
            origin = request.headers.get('Origin')
            if origin and origin != request.host_url.rstrip('/'):
                abort(403, 'Cross-origin writes are not allowed.')

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: https:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        if request.path.startswith('/api/') or request.method == 'POST' or response.mimetype == 'text/html':
            response.headers['Cache-Control'] = 'no-store'
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    @app.get('/healthz')
    def health():
        get_db().execute('SELECT 1 FROM users LIMIT 1').fetchone()
        return jsonify(status='ok', revision=os.environ.get('RELEASE_SHA', 'development'))

    @app.get('/api/session')
    def session_info():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return jsonify(user=public_user(g.user), csrf=session['csrf'])

    @app.post('/api/signup')
    def signup():
        rate_limit('signup', 10, 3600)
        data = payload()
        username = text(data, 'username', 32, True)
        email = text(data, 'email', 254, True).lower()
        if not re.fullmatch(r'[A-Za-z0-9_\-]{3,32}', username) or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            abort(400, 'Use a valid email and a username with 3-32 letters, numbers, underscores or hyphens.')
        hashed = generate_password_hash(password(data))
        recovery = secrets.token_urlsafe(24)
        uid = secrets.token_hex(16)
        try:
            with get_db() as db:
                db.execute('INSERT INTO users(id,username,email,password_hash,recovery_hash) VALUES (?,?,?,?,?)', (uid, username, email, hashed, digest(recovery)))
        except sqlite3.IntegrityError:
            abort(409, 'That username or email is already registered.')
        sign_in(uid)
        return jsonify(recovery_code=recovery), 201

    @app.post('/api/login')
    def login():
        rate_limit('login', 20)
        data = payload()
        username = text(data, 'username', 254, True)
        candidate = data.get('password', '')
        if not isinstance(candidate, str) or len(candidate) > 256:
            abort(400, 'Invalid password.')
        user = get_db().execute('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE', (username, username)).fetchone()
        stored = user['password_hash'] if user else app.config['DUMMY_PASSWORD_HASH']
        valid = check_password_hash(stored, candidate)
        if user is None or not valid:
            abort(401, 'Incorrect username/email or password.')
        sign_in(user['id'])
        return jsonify(ok=True)

    @app.post('/api/logout')
    def logout():
        with get_db() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (digest(session.get('token', '')),))
        session.clear()
        return jsonify(ok=True)

    @app.post('/api/recover')
    def recover():
        rate_limit('recover', 10)
        data = payload()
        username = text(data, 'username', 254, True)
        recovery = text(data, 'recovery_code', 128, True)
        user = get_db().execute('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE', (username, username)).fetchone()
        if not user or not secrets.compare_digest(user['recovery_hash'], digest(recovery)):
            abort(401, 'Incorrect account or recovery code.')
        new_hash = generate_password_hash(password(data))
        new_recovery = secrets.token_urlsafe(24)
        with get_db() as db:
            db.execute('UPDATE users SET password_hash=?, recovery_hash=? WHERE id=?', (new_hash, digest(new_recovery), user['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
        sign_in(user['id'])
        return jsonify(recovery_code=new_recovery)

    @app.post('/api/profile')
    def profile_update():
        uid = require_user()
        data = payload()
        profile = {field: text(data, field, 500) for field in ('phone', 'location', 'bio')}
        with get_db() as db:
            db.execute('UPDATE users SET profile=? WHERE id=?', (json.dumps(profile), uid))
        return jsonify(ok=True)

    @app.post('/api/password')
    def change_password():
        uid = require_user()
        rate_limit('password', 10)
        data = payload()
        if not check_password_hash(g.user['password_hash'], text(data, 'current_password', 256, True)):
            abort(401, 'Incorrect current password.')
        new_hash = generate_password_hash(password(data))
        with get_db() as db:
            db.execute('UPDATE users SET password_hash=? WHERE id=?', (new_hash, uid))
            db.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
        sign_in(uid)
        return jsonify(ok=True)

    @app.get('/api/state')
    def state():
        uid = require_user()
        times = {}
        for row in get_db().execute('SELECT * FROM solves WHERE user_id=? ORDER BY id', (uid,)):
            times.setdefault('session' + str(row['session']), {})[f"{row['id']:016d}"] = '|'.join(str(row[key]) for key in ('category', 'time', 'scramble', 'penalty', 'solved_at', 'comment'))
        profile = public_user(g.user)
        profile['settings'] = g.user['settings']
        return jsonify(users={uid: profile}, times={uid: times})

    def insert_solve(uid, number, category, duration, scramble, penalty, date, comment=''):
        get_db().execute('INSERT INTO solves(user_id,session,category,time,scramble,penalty,solved_at,comment) VALUES (?,?,?,?,?,?,?,?)',
            (uid, integer(number, 1, 10000), safe_field(category, 40), integer(duration, 0, 86400000), safe_field(scramble, 5000), integer(penalty, 0, 2), integer(date), safe_field(comment, 500)))

    @app.post('/saveTime')
    def save_time():
        uid = require_user()
        data = request.form
        with get_db():
            insert_solve(uid, data.get('session'), data.get('category'), data.get('time'), data.get('scramble'), data.get('plus_two'), data.get('solve_date'))
        return 'saved time'

    @app.post('/uploadSolves')
    def upload_solves():
        uid = require_user()
        try:
            rows = json.loads(request.form.get('solves', ''))
        except (ValueError, TypeError):
            abort(400, 'Invalid solve import.')
        if not isinstance(rows, list) or not 2 <= len(rows) <= 10002:
            abort(400, 'Import up to 10,000 solves at a time.')
        with get_db():
            for row in rows[2:]:
                if not isinstance(row, list) or not 4 <= len(row) <= 5:
                    abort(400, 'Invalid solve row.')
                insert_solve(uid, rows[0], rows[1], row[0], row[1], row[2], row[3], row[4] if len(row) == 5 else '')
        return 'Done!'

    @app.post('/deleteSolve')
    @app.post('/penalizeSolve')
    def modify_solve():
        uid = require_user()
        try:
            key = int(request.form.get('key', ''))
        except ValueError:
            abort(400, 'Invalid solve key.')
        number = integer(request.form.get('session'), 1, 10000)
        row = get_db().execute('SELECT penalty FROM solves WHERE id=? AND user_id=? AND session=?', (key, uid, number)).fetchone()
        if row is None:
            abort(404, 'Solve not found.')
        with get_db() as db:
            if request.path == '/deleteSolve':
                db.execute('DELETE FROM solves WHERE id=? AND user_id=?', (key, uid))
                return 'Deleted solve.'
            penalty = integer(request.form.get('penalty'), 1, 2)
            db.execute('UPDATE solves SET penalty=? WHERE id=? AND user_id=?', (penalty if row['penalty'] == 0 else 0, key, uid))
        return 'Done!'

    @app.post('/deleteSession')
    def delete_session():
        uid = require_user()
        number = integer(request.form.get('session'), 1, 10000)
        with get_db() as db:
            db.execute('DELETE FROM solves WHERE user_id=? AND session=?', (uid, number))
        return 'Deleted session.'

    @app.post('/saveSettings')
    def save_settings():
        uid = require_user()
        settings = text(request.form, 'settings', 20000, True)
        with get_db() as db:
            db.execute('UPDATE users SET settings=? WHERE id=?', (settings, uid))
        return 'Saved settings'

    @app.post('/sendFeedback')
    def feedback():
        rate_limit('feedback', 10, 3600)
        data = payload()
        with get_db() as db:
            db.execute('INSERT INTO feedback(user_id,title,message,created_at) VALUES (?,?,?,?)', (g.user['id'] if g.user else None, text(data, 'title', 200, True), text(data, 'message', 5000, True), int(time.time())))
        return 'Done!'

    @app.get('/healthz/revision')
    def revision():
        return os.environ.get('RELEASE_SHA', 'development')

    @app.get('/')
    @app.get('/<page>')
    def page(page='index'):
        if page in ('index', 'solve', 'timer', 'installpwa', 'contactMe', 'signin', 'signup', 'profile', 'recover'):
            return render_template(page + '.html')
        if page in ('sw.js', 'firebase-messaging-sw.js', 'manifest.json', 'manifest1.json', 'sitemap.xml'):
            return send_from_directory(ROOT / 'static', page)
        abort(404)

    @app.get('/<directory>/<path:filename>')
    def assets(directory, filename):
        if directory not in ('js', 'css', 'images', 'videos', 'audio', 'fonts'):
            abort(404)
        return send_from_directory(ROOT / directory, filename)

    app.config['DUMMY_PASSWORD_HASH'] = generate_password_hash(secrets.token_urlsafe(24))
    return app
