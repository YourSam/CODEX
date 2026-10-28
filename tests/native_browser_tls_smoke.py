"""Optional TLS regression. An untrusted fixture certificate MUST be rejected."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from browser_worker import render


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-no-sandbox', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        cert, key = Path(temp) / 'cert.pem', Path(temp) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=shop.example'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<p>Untrusted fixture</p>')

        server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def connector(host, port, scheme):
            if (host, port, scheme) != ('shop.example', 443, 'https'):
                raise app.CheckError('Fixture rejects every other destination')
            return socket.create_connection(('127.0.0.1', server.server_port), timeout=5)

        try:
            options = {'chromium_sandbox': False} if args.fixture_no_sandbox else None
            try:
                render('https://shop.example/?token=fixture-secret', connector=connector, launch_options=options)
            except app.CheckError as error:
                assert error.kind == 'browser_tls', (error.kind, str(error))
                assert 'ERR_CERT_' in str(error), str(error)
                assert 'fixture-secret' not in str(error), str(error)
            else:
                raise AssertionError('Untrusted TLS certificate was incorrectly accepted')
            print('PASS: native HTTPS tunnel, untrusted certificate rejected, safe browser TLS diagnosis. No live external sites used.')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    main()
