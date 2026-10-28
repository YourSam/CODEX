import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request

import app
import browser_proxy
import browser_worker


class NativeBrowserPipelineTests(unittest.TestCase):
    def test_browser_exception_shows_code_without_private_url(self):
        error = browser_worker.explain_browser_error(Exception('Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://shop.example/?token=secret-value'))
        self.assertIn('ERR_TUNNEL_CONNECTION_FAILED', str(error))
        self.assertNotIn('secret-value', str(error))
        self.assertNotIn('https://', str(error))

    def test_browser_certificate_error_is_distinct_from_installation(self):
        error = browser_worker.explain_browser_error(Exception('net::ERR_CERT_AUTHORITY_INVALID'))
        self.assertEqual(error.kind, 'browser_tls')
        self.assertNotIn('установ', str(error).lower())

    def test_diagnostic_distinguishes_original_401_and_browser_403(self):
        connection = {'status': 'unknown', 'http_status': 401, 'error_kind': 'http'}
        check = app.finding('browser', 'Браузер', 'unknown', 'Браузер получил HTTP 403')
        check.update(http_status=403, error_kind='http')
        diagnostic = app.browser_diagnostic([check], connection)
        self.assertEqual(diagnostic['state'], 'failed')
        self.assertEqual(diagnostic['http_status'], 403)
        self.assertEqual(connection['http_status'], 401)

    def test_auth_skip_does_not_claim_browser_requested_site(self):
        diagnostic = app.browser_diagnostic([], {'http_status': 401, 'error_kind': 'http_auth'})
        self.assertFalse(diagnostic['attempted'])
        self.assertEqual(diagnostic['state'], 'skipped_auth')
        self.assertIn('WWW-Authenticate', diagnostic['message'])

    def test_anonymous_browser_can_recover_non_auth_401(self):
        resource = app.Resource('https://shop.example/', '<p>shop@example.com Оплата картой.</p>', [])
        checks = []
        with patch.dict('os.environ', {'STORELENS_BROWSER': '1'}), patch('app.fetch', side_effect=app.CheckError('401', kind='http', status=401)), patch('app.browser_render', return_value=resource) as browser:
            self.assertIs(app.load_initial(resource.url, checks), resource)
        browser.assert_called_once()
        self.assertEqual(checks[0]['status'], 'observed')

    def test_explicit_authentication_and_forbidden_are_not_retried(self):
        for kind, status in [('http_auth', 401), ('http', 403)]:
            with self.subTest(kind=kind), patch.dict('os.environ', {'STORELENS_BROWSER': '1'}), patch('app.fetch', side_effect=app.CheckError('Denied', kind=kind, status=status)), patch('app.browser_render') as browser:
                with self.assertRaises(app.CheckError):
                    app.load_initial('https://shop.example/', [])
                browser.assert_not_called()

    def test_browser_denial_does_not_loop_or_hide_original_status(self):
        checks = []
        with patch.dict('os.environ', {'STORELENS_BROWSER': '1'}), patch('app.fetch', side_effect=app.CheckError('Original 401', kind='http', status=401)), patch('app.browser_render', side_effect=app.CheckError('Browser 401', kind='http', status=401)) as browser:
            with self.assertRaises(app.CheckError) as caught:
                app.load_initial('https://shop.example/', checks)
        browser.assert_called_once()
        self.assertEqual(str(caught.exception), 'Original 401')
        self.assertIn('Browser 401', checks[0]['summary'])

    def test_missing_browser_prevents_server_start(self):
        with patch.dict('os.environ', {}, clear=True), patch('sys.argv', ['app.py', '--browser']), patch('app.browser_worker_call', side_effect=app.CheckError('Playwright missing')), patch('app.Server') as server, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                app.main()
        self.assertEqual(caught.exception.code, 2)
        server.assert_not_called()

    def test_probe_checks_browser_without_starting_server(self):
        with patch('sys.argv', ['app.py', '--check-browser']), patch('app.browser_worker_call', return_value={'ok': True}) as worker, patch('app.Server') as server, patch('app.BROWSER_READY', False), contextlib.redirect_stdout(io.StringIO()):
            app.main()
        worker.assert_called_once_with({'action': 'probe'})
        server.assert_not_called()

    def test_browser_worker_retains_structured_error(self):
        process = unittest.mock.MagicMock()
        process.communicate.return_value = (json.dumps({'ok': False, 'error': 'Browser HTTP 401', 'kind': 'http', 'status': 401}), '')
        with patch('subprocess.Popen', return_value=process):
            with self.assertRaises(app.CheckError) as caught:
                app.browser_worker_call({'action': 'render', 'url': 'https://shop.example/'})
        self.assertEqual(caught.exception.status, 401)


class BrowserProxyTests(unittest.TestCase):
    def test_private_dns_is_rejected_before_connect(self):
        with patch('browser_proxy.public_addresses', side_effect=app.CheckError('private')), patch('socket.create_connection') as connection:
            with self.assertRaises(app.CheckError):
                browser_proxy.connect_destination('private.example', 443, 'https')
        connection.assert_not_called()

    def test_direct_transport_pins_public_ip(self):
        with patch('browser_proxy.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.getproxies', return_value={}), patch('socket.create_connection') as connection:
            browser_proxy.connect_destination('shop.example', 443, 'https')
        connection.assert_called_once_with(('93.184.216.34', 443), timeout=5)

    def test_upstream_denial_never_falls_back_to_direct(self):
        fake = unittest.mock.MagicMock()
        fake.recv.side_effect = [bytes([c]) for c in b'HTTP/1.1 403 Forbidden\r\n\r\n']
        with patch('browser_proxy.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.getproxies', return_value={'https': 'http://proxy.example:8080'}), patch('urllib.request.proxy_bypass', return_value=False), patch('socket.create_connection', return_value=fake) as connection:
            with self.assertRaises(app.CheckError):
                browser_proxy.connect_destination('shop.example', 443, 'https')
        connection.assert_called_once_with(('proxy.example', 8080), timeout=5)
        fake.close.assert_called_once()

    def test_connect_tunnels_bytes_without_tls_interception(self):
        def connector(host, port, scheme):
            self.assertEqual((host, port, scheme), ('shop.example', 443, 'https'))
            source, destination = socket.socketpair()
            def echo():
                with destination:
                    destination.sendall(destination.recv(100))
            threading.Thread(target=echo, daemon=True).start()
            return source
        with browser_proxy.BrowserProxy(connector=connector) as url:
            port = int(url.rsplit(':', 1)[1])
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.sendall(b'CONNECT shop.example:443 HTTP/1.1\r\nHost: shop.example:443\r\n\r\n')
                response = bytearray()
                while not response.endswith(b'\r\n\r\n'):
                    response.extend(client.recv(1))
                self.assertIn(b'200 Connection established', response)
                client.sendall(b'opaque TLS bytes')
                self.assertEqual(client.recv(100), b'opaque TLS bytes')


class MacLauncherTests(unittest.TestCase):
    def run_launcher(self, fail_pip=False):
        with tempfile.TemporaryDirectory(prefix='storelens launcher ') as temp:
            root = Path(temp)
            project = root / 'project'
            project.mkdir()
            shutil.copyfile(app.ROOT / 'start-mac.command', project / 'start-mac.command')
            (project / 'app.py').write_text('fixture')
            (project / 'requirements-browser.txt').write_text('fixture')
            fake_bin = root / 'old environment' / 'bin'
            fake_bin.mkdir(parents=True)
            executable = root / 'base-python'
            executable.write_text('''#!/bin/bash
printf '%s|%s\\n' "$PWD" "$*" >> "$TEST_LOG"
if [[ "$1" == '-c' ]]; then
  if [[ "$2" == *'_base_executable'* ]]; then printf '%s\\n' "$TEST_BASE"; fi
elif [[ "$1" == '-m' && "$2" == 'venv' ]]; then
  mkdir -p "$3/bin"
  cp "$TEST_BASE" "$3/bin/python"
  chmod +x "$3/bin/python"
elif [[ "$1" == '-m' && "$2" == 'pip' && "$TEST_FAIL_PIP" == '1' ]]; then
  exit 23
elif [[ "$1" == 'app.py' ]]; then
  printf 'SERVER_STARTED\\n' >> "$TEST_LOG"
fi
''')
            executable.chmod(0o755)
            shutil.copyfile(executable, fake_bin / 'python3')
            (fake_bin / 'python3').chmod(0o755)
            log = root / 'calls.txt'
            env = {**os.environ, 'PATH': str(fake_bin) + os.pathsep + os.environ.get('PATH', ''),
                   'TEST_BASE': str(executable), 'TEST_LOG': str(log), 'TEST_FAIL_PIP': '1' if fail_pip else '0'}
            result = subprocess.run(['bash', str(project / 'start-mac.command')], cwd=root, env=env, capture_output=True, text=True, timeout=10)
            return result, log.read_text(), str(project)

    def test_old_active_environment_and_wrong_cwd_use_current_checkout(self):
        result, log, project = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SERVER_STARTED', log)
        self.assertTrue(all(line.startswith(project + '|') for line in log.splitlines() if line != 'SERVER_STARTED'))
        self.assertIn('app.py --browser --port 8001', log)

    def test_failed_install_never_continues_to_server(self):
        result, log, _ = self.run_launcher(fail_pip=True)
        self.assertEqual(result.returncode, 23)
        self.assertNotIn('SERVER_STARTED', log)
        self.assertNotIn('-m playwright install', log)


if __name__ == '__main__':
    unittest.main()
