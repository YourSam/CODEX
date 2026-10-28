"""Optional real Chromium regression with entirely controlled local content."""
import argparse
import http.client
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from browser_worker import render


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-no-sandbox', action='store_true', help='Only for this fixed offline fixture in a restricted test container')
    args = parser.parse_args()
    observed = []

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            observed.append((self.path, self.headers.get('User-Agent', ''), self.headers.get('Cookie', '')))
            if 'Chrome' not in self.headers.get('User-Agent', ''):
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json' if self.path == '/info' else 'text/html')
            self.send_header('Set-Cookie', 'anonymous=ready; Path=/')
            self.end_headers()
            if self.path == '/info':
                assert 'anonymous=ready' in self.headers.get('Cookie', '')
                self.wfile.write(b'{"text":"shop@example.com"}')
            else:
                self.wfile.write(b'''<div id="app"></div><script>fetch('/info').then(r=>r.json()).then(d=>document.querySelector('#app').textContent=d.text);fetch('http://127.0.0.1/private').catch(()=>{});fetch('/post',{method:'POST'}).catch(()=>{});</script>''')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def connector(host, port, scheme):
        # No live destination is reachable from this test's transport.
        if (host, port, scheme) != ('shop.example', 80, 'http'):
            raise app.CheckError('Fixture rejects every other destination')
        return socket.create_connection(('127.0.0.1', server.server_port), timeout=5)

    try:
        direct = http.client.HTTPConnection('127.0.0.1', server.server_port)
        direct.request('GET', '/')
        assert direct.getresponse().status == 401
        direct.close()
        options = {'chromium_sandbox': False} if args.fixture_no_sandbox else None
        result = render('http://shop.example/', connector=connector, launch_options=options)
        assert result['url'] == 'http://shop.example/'
        assert 'shop@example.com' in result['html']
        assert any(path == '/info' and 'anonymous=ready' in cookie for path, ua, cookie in observed)
        assert not any(path in ('/private', '/post') for path, ua, cookie in observed)
        checks = []
        resource = app.Resource(result['url'], result['html'], [])
        with patch.dict('os.environ', {'STORELENS_BROWSER': '1'}), patch('app.fetch', side_effect=app.CheckError('HTTP 401', kind='http', status=401)), patch('app.browser_render', return_value=resource):
            recovered = app.load_initial('http://shop.example/', checks)
        assert 'shop@example.com' in recovered.text and checks[0]['status'] == 'observed'
        print('PASS: non-browser 401, native Chromium 200, JavaScript, anonymous cookies, blocked private URL/POST, recovered pipeline. No live external sites used.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
