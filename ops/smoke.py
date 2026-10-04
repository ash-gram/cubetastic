"""Verify live HTTPS accounts and persistence; remove only this generated test user."""
import http.cookiejar
import json
import secrets
import sqlite3
import urllib.parse
import urllib.request

BASE = 'https://cubetastic.duckdns.org'
username = 'smoke_' + secrets.token_hex(8)
password = secrets.token_urlsafe(32)
uid = None

def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def get(browser, path):
    with browser.open(BASE + path, timeout=20) as response:
        return json.load(response)

def post(browser, path, data, form=False):
    csrf = get(browser, '/api/session')['csrf']
    body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    request = urllib.request.Request(BASE + path, body, headers={
        'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json',
        'X-CSRF-Token': csrf, 'Origin': BASE})
    with browser.open(request, timeout=20) as response:
        return response.read()

first, second = client(), client()
try:
    post(first, '/api/signup', dict(username=username, email=username+'@example.invalid', password=password))
    uid = get(first, '/api/session')['user']['uid']
    post(first, '/saveTime', dict(uid=uid, session='1', time='12345', category='3x3x3', scramble="R U R'", plus_two='0', solve_date='1710000000000'), True)
    post(second, '/api/login', dict(username=username, password=password))
    state = get(second, '/api/state')
    assert len(state['times'][uid]['session1']) == 1
    post(first, '/api/logout', {})
    assert get(first, '/api/session')['user'] is None
    assert len(get(second, '/api/state')['times'][uid]['session1']) == 1
    print('Live HTTPS signup, login, cross-session solve persistence and logout: passed')
finally:
    # Match both the random username and its ID; never delete real user accounts.
    with sqlite3.connect('/var/lib/cubetastic/cubetastic.sqlite3') as db:
        db.execute('PRAGMA foreign_keys=ON')
        if uid:
            db.execute('DELETE FROM users WHERE id=? AND username=?', (uid, username))
        else:
            db.execute('DELETE FROM users WHERE username=?', (username,))
    print('Temporary smoke-test account removed')
