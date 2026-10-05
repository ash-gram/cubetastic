import hashlib
import hmac
import json
from pathlib import Path
from unittest import TestCase
import test_standalone as fixtures

class DeliveryTests(TestCase):
    setUp = fixtures.StandaloneTests.setUp
    tearDown = fixtures.StandaloneTests.tearDown
    post = fixtures.StandaloneTests.post
    signup = fixtures.StandaloneTests.signup
    save = fixtures.StandaloneTests.save

    def test_state_unchanged_is_empty_and_owner_scoped(self):
        uid, _ = self.signup(self.a, 'alice')
        self.signup(self.b, 'bob')
        first = self.a.get('/api/state')
        tag = first.headers['ETag']
        same = self.a.get('/api/state', headers={'If-None-Match': tag})
        self.assertEqual(same.status_code, 304)
        self.assertEqual(same.data, b'')
        self.assertIn('no-store', same.headers['Cache-Control'])
        self.assertEqual(self.b.get('/api/state', headers={'If-None-Match': tag}).status_code, 200)
        self.save(self.a, uid)
        self.assertEqual(self.a.get('/api/state', headers={'If-None-Match': tag}).status_code, 200)

    def test_state_invalidates_after_settings_penalty_and_delete(self):
        uid, _ = self.signup(self.a, 'alice')
        self.save(self.a, uid)
        key = next(iter(self.a.get('/api/state').json['times'][uid]['session1']))
        for endpoint, data in [('/saveSettings', {'uid':uid, 'settings':'updated'}), ('/penalizeSolve', {'uid':uid,'session':'1','key':key,'penalty':'1'}), ('/deleteSolve', {'uid':uid,'session':'1','key':key})]:
            tag = self.a.get('/api/state').headers['ETag']
            self.assertEqual(self.post(self.a, endpoint, data, True).status_code, 200)
            self.assertEqual(self.a.get('/api/state', headers={'If-None-Match':tag}).status_code, 200)

    def test_webhook_rejects_forgery_and_only_signals_main(self):
        signal = Path(self.temp.name) / 'deploy-request'
        self.app.config.update(GITHUB_WEBHOOK_SECRET='server-test-secret', DEPLOY_SIGNAL=str(signal))
        data = {'repository':{'full_name':'ash-gram/cubetastic'}, 'ref':'refs/heads/main'}
        def deliver(data, event='push', valid=True):
            body = json.dumps(data).encode()
            signature = 'sha256=' + hmac.new(b'server-test-secret', body, hashlib.sha256).hexdigest()
            return self.a.post('/hooks/github', data=body, content_type='application/json', headers={'X-GitHub-Event':event,'X-Hub-Signature-256':signature if valid else 'forged'})
        self.assertEqual(deliver(data, valid=False).status_code, 403)
        self.assertFalse(signal.exists())
        for changed in [dict(data,ref='refs/heads/master'),dict(data,deleted=True),dict(data,repository={'full_name':'other/repo'})]:
            self.assertTrue(deliver(changed).json['ignored'])
            self.assertFalse(signal.exists())
        self.assertEqual(deliver(data,'ping').status_code, 200)
        self.assertFalse(signal.exists())
        self.assertEqual(deliver(data).status_code,202)
        self.assertTrue(signal.exists())
        self.assertEqual(deliver(data).status_code,202)

    def test_assets_and_private_cache_boundaries(self):
        page = self.a.get('/timer').text
        self.assertIn('/assets/',page)
        self.assertNotIn('style="display: none">\n  <aside',page)
        self.assertIn('loading="lazy"',page)
        with self.a.get('/assets/development/js/main.js') as asset:
            self.assertEqual(asset.status_code,200)
        self.assertEqual(self.a.get('/assets/development/instance/cubetastic.sqlite3').status_code,404)
        self.assertEqual(self.a.get('/assets/development/js/../../app.py').status_code,404)
        for path in ['/api/session','/signin','/profile']:
            self.assertEqual(self.a.get(path).headers['Cache-Control'],'no-store')
        worker = self.a.get('/sw.js')
        self.assertEqual(worker.headers['Cache-Control'],'no-cache')
        self.assertNotIn('__VERSION__',worker.text)
