"""Google OpenID Connect with explicit, authenticated account linking."""
import json
import re
import secrets
import sqlite3
import time
from urllib.parse import urlparse

from authlib.integrations.flask_client import OAuth
from flask import abort, flash, g, jsonify, redirect, request, session
from werkzeug.security import check_password_hash
from database_interactions import get_db


def init_google(app, sign_in, rate_limit):
    enabled = bool(app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET'])
    oauth = OAuth(app)
    google = oauth.register(
        'google', client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile', 'code_challenge_method': 'S256', 'timeout': 15},
    ) if enabled else None
    app.extensions['google_oauth_client'] = google

    @app.context_processor
    def google_context():
        return {'google_enabled': enabled}

    def fail(message, target='/signin'):
        session.pop('google_flow', None)
        flash(message, 'error')
        return redirect(target)

    @app.get('/auth/google/start')
    def start():
        if not google:
            return fail('Google sign-in is not available yet. You can still use your email and password.')
        rate_limit('google-start', 30)
        linking = request.args.get('link') == '1'
        if linking and not g.user:
            return fail('Sign in to your existing account before connecting Google.')
        if g.user and not linking:
            return redirect('/profile')
        session['google_flow'] = {'started': int(time.time()), 'uid': g.user['id'] if linking else None}
        try:
            return google.authorize_redirect(app.config['GOOGLE_REDIRECT_URI'], prompt='select_account')
        except Exception:
            return fail('Google sign-in is temporarily unavailable. Please try again.')

    @app.get('/auth/google/callback')
    def callback():
        flow = session.get('google_flow')
        if not google or not flow or int(time.time()) - flow.get('started', 0) > 600:
            return fail('Your sign-in request expired. Please try again.')
        target = '/profile' if flow.get('uid') else '/signin'
        if request.args.get('error'):
            return fail('Google sign-in was cancelled. No account changes were made.', target)
        try:
            # Authlib verifies OAuth state, PKCE, JWT signature, issuer, audience,
            # expiry and the nonce from the original authorization request.
            token = google.authorize_access_token()
            claims = token.get('userinfo')
            if not claims or claims.get('email_verified') is not True:
                return fail('Google must verify your email before you can use it here.', target)
            subject, email = claims.get('sub'), claims.get('email', '').strip().lower()
            if not isinstance(subject, str) or not 1 <= len(subject) <= 255 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(email) > 254:
                return fail('Google did not return a usable account identity.', target)
        except Exception:
            # Never log provider tokens, authorization codes or client secrets.
            return fail('Google sign-in could not be verified. Please try again.', target)
        session.pop('google_flow', None)
        db = get_db()
        identity = db.execute("SELECT * FROM oauth_identities WHERE provider='google' AND subject=?", (subject,)).fetchone()
        try:
            if flow.get('uid'):
                if not g.user or g.user['id'] != flow['uid']:
                    return fail('Your session changed. Sign in again before linking Google.')
                if email != g.user['email'].lower():
                    return fail('Choose the Google account matching your Cubetastic email.', '/profile')
                if identity and identity['user_id'] != g.user['id']:
                    return fail('That Google account is already connected to another Cubetastic account.', '/profile')
                existing = db.execute("SELECT subject FROM oauth_identities WHERE provider='google' AND user_id=?", (g.user['id'],)).fetchone()
                if existing and existing['subject'] != subject:
                    return fail('This account already has a different Google account connected.', '/profile')
                with db:
                    db.execute("INSERT INTO oauth_identities VALUES ('google',?,?,?) ON CONFLICT(provider,subject) DO UPDATE SET email=excluded.email", (subject, g.user['id'], email))
                sign_in(g.user['id'])
                flash('Google is connected. Your existing solves and settings are unchanged.', 'success')
                return redirect('/profile')
            if identity:
                uid = identity['user_id']
                with db:
                    db.execute('UPDATE users SET email=? WHERE id=?', (email, uid))
                    db.execute("UPDATE oauth_identities SET email=? WHERE provider='google' AND subject=?", (email, subject))
            else:
                # Matching email alone never links accounts. Password users must
                # authenticate first, then explicitly link in their profile.
                if db.execute('SELECT 1 FROM users WHERE email=? COLLATE NOCASE', (email,)).fetchone():
                    return fail('An account already uses this email. Sign in with your password, then connect Google in your profile.')
                uid = secrets.token_hex(16)
                base = re.sub(r'[^a-z0-9_]', '', email.split('@')[0].lower())[:20] or 'cuber'
                username = base + '_' + secrets.token_hex(4)
                name = claims.get('name', '')
                profile = {'display_name': name[:100] if isinstance(name, str) else ''}
                picture = claims.get('picture', '')
                if isinstance(picture, str):
                    url = urlparse(picture)
                    if url.scheme == 'https' and (url.hostname or '').endswith('.googleusercontent.com'):
                        profile['picture'] = picture[:2000]
                with db:
                    db.execute('INSERT INTO users(id,username,email,password_hash,recovery_hash,profile) VALUES (?,?,?,\'\',\'\',?)', (uid, username, email, json.dumps(profile)))
                    db.execute("INSERT INTO oauth_identities VALUES ('google',?,?,?)", (subject, uid, email))
            sign_in(uid)
            return redirect('/timer')
        except sqlite3.IntegrityError:
            return fail('This email or Google account is already linked. Sign in to the existing account first.', target)

    @app.post('/api/google/unlink')
    def unlink():
        if not g.user:
            abort(401, 'Sign in first.')
        if not g.user['password_hash']:
            abort(400, 'Google is your only sign-in method and cannot be disconnected.')
        rate_limit('google-unlink', 10)
        data = request.get_json(silent=True)
        password = data.get('password', '') if isinstance(data, dict) else ''
        if not isinstance(password, str) or len(password) > 256 or not check_password_hash(g.user['password_hash'], password):
            abort(401, 'Enter your current Cubetastic password to disconnect Google.')
        with get_db() as db:
            db.execute("DELETE FROM oauth_identities WHERE provider='google' AND user_id=?", (g.user['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?', (g.user['id'],))
        sign_in(g.user['id'])
        return jsonify(ok=True)
