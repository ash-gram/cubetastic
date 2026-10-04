"""OIDC route checks without contacting Google or using real client secrets."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app import create_app
from database_interactions import get_db

METADATA = dict(issuer='https://accounts.google.com', authorization_endpoint='https://accounts.google.com/o/oauth2/v2/auth', token_endpoint='https://oauth2.googleapis.com/token', jwks_uri='https://www.googleapis.com/oauth2/v3/certs', id_token_signing_alg_values_supported=['RS256'])

class GoogleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(dict(TESTING=True, SECRET_KEY='test-only', DATABASE=str(Path(self.temp.name)/'db.sqlite3'), SESSION_COOKIE_SECURE=False,
                                   GOOGLE_CLIENT_ID='test.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET='test-secret'))
        self.client = self.app.test_client()
        self.google = self.app.extensions['google_oauth_client']

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data):
        csrf = self.client.get('/api/session').json['csrf']
        return self.client.post(path, json=data, headers={'X-CSRF-Token':csrf})

    def start(self, link=False):
        with patch.object(self.google, 'load_server_metadata', return_value=METADATA):
            return self.client.get('/auth/google/start' + ('?link=1' if link else ''))

    def finish(self, email='google@example.test', subject='google-subject-123', **extras):
        claims = dict(sub=subject, email=email, email_verified=True, name='Google Cuber', picture='https://lh3.googleusercontent.com/a/photo')
        claims.update(extras)
        with patch.object(self.google, 'authorize_access_token', return_value={'userinfo':claims}):
            return self.client.get('/auth/google/callback?code=test&state=test')

    def count(self):
        with self.app.app_context():
            return get_db().execute('SELECT count(*) FROM users').fetchone()[0]

    def test_start_uses_fixed_callback_state_nonce_and_pkce(self):
        response = self.start()
        self.assertEqual(response.status_code,302)
        params = parse_qs(urlparse(response.location).query)
        self.assertEqual(params['redirect_uri'], ['https://cubetastic.duckdns.org/auth/google/callback'])
        self.assertEqual(params['scope'], ['openid email profile'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertGreater(len(params['state'][0]),20)
        self.assertGreater(len(params['nonce'][0]),10)

    def test_missing_state_expiry_and_cancel_create_nothing(self):
        self.assertEqual(self.finish().location, '/signin')
        self.start()
        self.assertEqual(self.client.get('/auth/google/callback?code=x&state=wrong').location, '/signin')
        self.start()
        with self.client.session_transaction() as session:
            session['google_flow']['started'] = int(time.time()) - 1000
            session.modified = True
        self.assertEqual(self.finish().location, '/signin')
        self.start()
        self.assertEqual(self.client.get('/auth/google/callback?error=access_denied').location, '/signin')
        self.assertEqual(self.count(),0)

    def test_invalid_id_token_rejected(self):
        response=self.start()
        state=parse_qs(urlparse(response.location).query)['state'][0]
        with patch.object(self.google,'fetch_access_token',return_value={'access_token':'test','id_token':'not.a.valid-token','token_type':'Bearer'}), patch.object(self.google,'load_server_metadata',return_value=METADATA):
            result=self.client.get('/auth/google/callback?code=test&state='+state)
        self.assertEqual(result.location,'/signin')
        self.assertEqual(self.count(),0)

    def test_new_google_account_and_returning_identity(self):
        self.start()
        self.assertEqual(self.finish().location,'/timer')
        user=self.client.get('/api/session').json['user']
        self.assertTrue(user['google_linked'])
        self.assertFalse(user['has_password'])
        self.assertEqual(user['displayName'],'Google Cuber')
        self.assertEqual(self.post('/api/password',dict(password='new-password-123',current_password='')).status_code,400)
        self.assertEqual(self.post('/api/google/unlink',dict(password='')).status_code,400)
        self.post('/api/logout',{})
        self.start()
        self.finish(email='changed@example.test')
        self.assertEqual(self.client.get('/api/session').json['user']['uid'],user['uid'])
        self.assertEqual(self.count(),1)

    def test_unverified_email_is_rejected(self):
        self.start()
        self.assertEqual(self.finish(email_verified=False).location,'/signin')
        self.assertEqual(self.count(),0)

    def test_matching_email_never_auto_links(self):
        self.post('/api/signup',dict(username='existing',email='google@example.test',password='local-password-123'))
        self.post('/api/logout',{})
        self.start()
        self.assertEqual(self.finish().location,'/signin')
        self.assertIsNone(self.client.get('/api/session').json['user'])
        self.assertEqual(self.count(),1)

    def test_explicit_link_preserves_user_and_disconnect_needs_password(self):
        self.post('/api/signup',dict(username='existing',email='google@example.test',password='local-password-123'))
        uid=self.client.get('/api/session').json['user']['uid']
        self.start(link=True)
        self.assertEqual(self.finish().location,'/profile')
        user=self.client.get('/api/session').json['user']
        self.assertEqual(user['uid'],uid)
        self.assertTrue(user['google_linked'])
        self.assertEqual(self.post('/api/google/unlink',dict(password='wrong')).status_code,401)
        self.assertEqual(self.post('/api/google/unlink',dict(password='local-password-123')).status_code,200)
        self.assertFalse(self.client.get('/api/session').json['user']['google_linked'])

    def test_link_rejects_wrong_email_or_changed_session(self):
        self.post('/api/signup',dict(username='existing',email='google@example.test',password='local-password-123'))
        self.start(link=True)
        self.assertEqual(self.finish(email='different@example.test').location,'/profile')
        self.assertFalse(self.client.get('/api/session').json['user']['google_linked'])
        self.start(link=True)
        with self.client.session_transaction() as session:
            session.pop('token')
        self.assertEqual(self.finish().location,'/signin')
        self.assertEqual(self.count(),1)

    def test_profile_edit_preserves_google_identity(self):
        self.start();self.finish()
        response=self.post('/api/profile',dict(username='my_new_handle',display_name='My Name',bio='Cubing!',phone='',location=''))
        self.assertEqual(response.status_code,200)
        user=self.client.get('/api/session').json['user']
        self.assertEqual(user['displayName'],'My Name')
        self.assertTrue(user['google_linked'])
        self.assertIn('googleusercontent.com',user['picture'])

if __name__=='__main__':unittest.main()
