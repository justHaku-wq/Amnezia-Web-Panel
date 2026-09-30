"""My Connections must not bounce a logged-in user when self-service is off.

The page asks /api/my/connections/options on load. That answered 403
"Self-service is disabled", and the shared apiCall() helper took every 403 for
an expired session: it sent the browser to /login, which redirects a logged-in
user to '/', so clicking "Connections" landed back on the previous page.
"""
import os
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

import app as panel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class OptionsEndpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.addCleanup(setattr, panel, 'DATA_FILE', panel.DATA_FILE)
        panel.DATA_FILE = os.path.join(tmp, 'data.json')

    def login(self, client):
        response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)

    def test_disabled_self_service_answers_enabled_false(self):
        with TestClient(panel.app) as client:
            self.login(client)
            response = client.get('/api/my/connections/options')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {'enabled': False, 'reason': 'Self-service is disabled'})

    def test_enabled_self_service_still_lists_options(self):
        with TestClient(panel.app) as client:
            self.login(client)
            data = panel.load_data()
            data['settings']['self_service']['enabled'] = True
            panel.save_data(data)
            response = client.get('/api/my/connections/options')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIs(response.json()['enabled'], True)

    def test_without_a_session_it_stays_forbidden(self):
        with TestClient(panel.app) as client:
            response = client.get('/api/my/connections/options')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'error': 'Forbidden'})


class ApiCallForbiddenTests(unittest.TestCase):
    """Text-level check of the fetch helper every page uses."""

    def setUp(self):
        with open(os.path.join(ROOT, 'templates', 'base.html'), encoding='utf-8') as f:
            page = f.read()
        start = page.index('async function apiCall(')
        self.helper = page[start:page.index('\n        }', start)]

    def test_only_a_bare_forbidden_counts_as_an_expired_session(self):
        self.assertIn("data.error === 'Forbidden'", self.helper)
        self.assertNotRegex(self.helper, r"res\.status === 401 \|\| res\.status === 403\)")

    def test_the_session_check_runs_after_the_body_is_parsed(self):
        parsed = self.helper.index('JSON.parse(text)')
        redirect = self.helper.index("window.location.href = '/login'")
        self.assertLess(parsed, redirect)


if __name__ == '__main__':
    unittest.main()
