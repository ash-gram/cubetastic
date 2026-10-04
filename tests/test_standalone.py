import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from app import create_app
from database_interactions import connect

class StandaloneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / 'test.sqlite3')
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'test-only-secret', 'DATABASE': self.db, 'SESSION_COOKIE_SECURE': False})
        self.a = self.app.test_client()
        self.b = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def post(self, client, path, data, form=False):
        csrf = client.get('/api/session').json['csrf']
        return client.post(path, **({'data': data} if form else {'json': data}), headers={'X-CSRF-Token': csrf})

    def signup(self, client, name):
        response = self.post(client, '/api/signup', {'username': name, 'email': name+'@example.test', 'password': 'test-long-password'})
        self.assertEqual(response.status_code, 201, response.json)
        return client.get('/api/session').json['user']['uid'], response.json['recovery_code']

    def save(self, client, uid, **overrides):
        data = dict(uid=uid, session='1', time='12345', scramble="R U R'", category='3x3x3', plus_two='0', solve_date='1710000000000')
        data.update(overrides)
        return self.post(client, '/saveTime', data, True)

    def test_signup_login_and_hashed_storage(self):
        uid, recovery = self.signup(self.a, 'alice')
        with closing(connect(self.db)) as db:
            row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            self.assertNotEqual(row['password_hash'], 'test-long-password')
            self.assertNotEqual(row['recovery_hash'], recovery)
        self.post(self.a, '/api/logout', {})
        self.assertEqual(self.a.get('/api/state').status_code, 401)
        self.assertEqual(self.post(self.a, '/api/login', {'username': 'ALICE', 'password': 'test-long-password'}).status_code, 200)
        self.assertEqual(self.post(self.b, '/api/login', {'username': 'alice', 'password': 'wrong'}).status_code, 401)

    def test_csrf_and_origin_checks(self):
        self.assertEqual(self.a.post('/api/signup', json={}).status_code, 403)
        csrf = self.a.get('/api/session').json['csrf']
        self.assertEqual(self.a.post('/api/login', json={}, headers={'X-CSRF-Token': csrf, 'Origin': 'https://evil.example'}).status_code, 403)

    def test_account_isolation_and_forged_uid(self):
        alice, _ = self.signup(self.a, 'alice')
        bob, _ = self.signup(self.b, 'bob')
        self.assertEqual(self.save(self.a, alice).status_code, 200)
        self.assertEqual(self.save(self.b, alice).status_code, 403)
        self.assertEqual(self.b.get('/api/state').json['times'], {bob: {}})
        key = next(iter(self.a.get('/api/state').json['times'][alice]['session1']))
        for path in ['/deleteSolve', '/penalizeSolve']:
            self.assertEqual(self.post(self.b, path, dict(uid=bob, session='1', key=key, penalty='2'), True).status_code, 404)
        self.assertEqual(self.post(self.b, '/deleteSession', dict(uid=alice, session='1'), True).status_code, 403)
        self.assertEqual(len(self.a.get('/api/state').json['times'][alice]['session1']), 1)

    def test_solve_penalty_delete_and_settings(self):
        uid, _ = self.signup(self.a, 'alice')
        self.save(self.a, uid)
        state = self.a.get('/api/state').json
        key = next(iter(state['times'][uid]['session1']))
        self.assertEqual(self.post(self.a, '/penalizeSolve', dict(uid=uid, session='1', key=key, penalty='2'), True).status_code, 200)
        self.assertEqual(self.a.get('/api/state').json['times'][uid]['session1'][key].split('|')[3], '2')
        self.post(self.a, '/saveSettings', dict(uid=uid, settings='theme|test'), True)
        self.assertEqual(self.a.get('/api/state').json['users'][uid]['settings'], 'theme|test')
        self.post(self.a, '/deleteSolve', dict(uid=uid, session='1', key=key), True)
        self.assertEqual(self.a.get('/api/state').json['times'][uid], {})

    def test_atomic_import_and_validation(self):
        uid, _ = self.signup(self.a, 'alice')
        rows = [1, '3x3x3', [1000, 'R', 0, 1710000000000], [2000, '<script>', 0, 1710000000001]]
        self.assertEqual(self.post(self.a, '/uploadSolves', dict(uid=uid, solves=json.dumps(rows)), True).status_code, 400)
        self.assertEqual(self.a.get('/api/state').json['times'][uid], {})
        rows[-1][1] = 'U'
        self.assertEqual(self.post(self.a, '/uploadSolves', dict(uid=uid, solves=json.dumps(rows)), True).status_code, 200)
        self.assertEqual(len(self.a.get('/api/state').json['times'][uid]['session1']), 2)
        self.assertEqual(self.save(self.a, uid, time='-1').status_code, 400)
        self.assertEqual(self.save(self.a, uid, session='0').status_code, 400)

    def test_recovery_rotates_code_and_revokes_other_sessions(self):
        uid, recovery = self.signup(self.a, 'alice')
        self.post(self.b, '/api/login', dict(username='alice', password='test-long-password'))
        result = self.post(self.a, '/api/recover', dict(username='alice', recovery_code=recovery, password='changed-password-123'))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.b.get('/api/state').status_code, 401)
        self.assertEqual(self.post(self.b, '/api/recover', dict(username='alice', recovery_code=recovery, password='changed-password-123')).status_code, 401)
        self.assertNotEqual(result.json['recovery_code'], recovery)

    def test_password_change_and_logout_revoke_tokens(self):
        self.signup(self.a, 'alice')
        self.post(self.b, '/api/login', dict(username='alice', password='test-long-password'))
        self.assertEqual(self.post(self.a, '/api/password', dict(current_password='wrong', password='changed-password-123')).status_code, 401)
        self.assertEqual(self.post(self.a, '/api/password', dict(current_password='test-long-password', password='changed-password-123')).status_code, 200)
        self.assertEqual(self.b.get('/api/state').status_code, 401)
        old_cookie = self.a.get_cookie('cubetastic_session').value
        self.post(self.a, '/api/logout', {})
        self.a.set_cookie('cubetastic_session', old_cookie)
        self.assertEqual(self.a.get('/api/state').status_code, 401)

    def test_constraints_and_rate_limit(self):
        self.signup(self.a, 'alice')
        self.assertEqual(self.post(self.b, '/api/signup', dict(username='ALICE', email='other@example.test', password='test-long-password')).status_code, 409)
        self.assertEqual(self.post(self.b, '/api/signup', dict(username='other', email='other@example.test', password='short')).status_code, 400)
        for _ in range(20):
            self.post(self.b, '/api/login', dict(username='missing', password='wrong'))
        self.assertEqual(self.post(self.b, '/api/login', dict(username='missing', password='wrong')).status_code, 429)

    def test_persistence_and_pages(self):
        uid, _ = self.signup(self.a, 'alice')
        self.save(self.a, uid)
        other = create_app({'TESTING': True, 'SECRET_KEY': 'test-only-secret', 'DATABASE': self.db, 'SESSION_COOKIE_SECURE': False}).test_client()
        self.post(other, '/api/login', dict(username='alice', password='test-long-password'))
        self.assertEqual(len(other.get('/api/state').json['times'][uid]['session1']), 1)
        for path in ['/', '/timer', '/solve', '/signin', '/signup', '/profile', '/recover', '/installpwa', '/contactMe']:
            response = other.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertNotIn(b'gstatic.com/firebase', response.data)
            self.assertNotIn(b'googletagmanager', response.data)
        self.assertIn("connect-src 'self'", other.get('/timer').headers['Content-Security-Policy'])
        self.assertEqual(other.get('/api/state').headers['Cache-Control'], 'no-store')
        with other.get('/js/main.js') as response:
            self.assertEqual(response.status_code, 200)
        with other.get('/sw.js') as response:
            self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
