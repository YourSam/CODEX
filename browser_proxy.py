"""Temporary loopback proxy for the isolated browser.

Direct connections pin validated public IPs. Configured platform proxies are
preserved; those proxies must enforce public-only egress too. TLS stays between
Chromium and the destination (no certificate interception).
"""
import base64
import http.client
import select
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

from app import CheckError, MAX_BYTES, normalize_url, public_addresses


def connect_destination(host, port, scheme):
    addresses = public_addresses(host, port)
    proxies = urllib.request.getproxies()
    upstream = proxies.get(scheme) if not urllib.request.proxy_bypass(host) else None
    if not upstream:
        return socket.create_connection((addresses[0], port), timeout=5)
    proxy = urllib.parse.urlsplit(upstream if '://' in upstream else 'http://' + upstream)
    if proxy.scheme not in ('http', 'https') or not proxy.hostname:
        raise CheckError('Неподдерживаемая конфигурация прокси.')
    # The upstream address is trusted environment configuration, not page input.
    sock = socket.create_connection((proxy.hostname, proxy.port or (443 if proxy.scheme == 'https' else 80)), timeout=5)
    try:
        if proxy.scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=proxy.hostname)
        headers = ''
        if proxy.username is not None:
            credentials = urllib.parse.unquote(proxy.username) + ':' + urllib.parse.unquote(proxy.password or '')
            token = base64.b64encode(credentials.encode()).decode()
            headers = 'Proxy-Authorization: Basic ' + token + '\r\n'
        sock.sendall((f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n' + headers + '\r\n').encode())
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            chunk = sock.recv(1)
            if not chunk or len(response) >= 16384:
                raise CheckError('Прокси не завершил ответ.')
            response.extend(chunk)
        if bytes(response).split(b' ', 2)[1] != b'200':
            raise CheckError('Настроенный сетевой прокси отклонил соединение.')
        return sock
    except Exception:
        sock.close()
        raise


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def fail(self):
        self.send_response(502)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def do_CONNECT(self):
        try:
            target = normalize_url('https://' + self.path)
            parsed = urllib.parse.urlsplit(target)
            if parsed.path != '/' or parsed.query:
                raise CheckError('Некорректный CONNECT.')
            upstream = self.server.connector(parsed.hostname, 443, 'https')
        except Exception:
            return self.fail()
        self.send_response(200, 'Connection established')
        self.end_headers()
        self.close_connection = True
        with upstream:
            self.connection.settimeout(5)
            upstream.settimeout(5)
            deadline = time.monotonic() + 20
            transferred = 0
            while time.monotonic() < deadline and transferred <= 16 * MAX_BYTES:
                readable, _, _ = select.select([self.connection, upstream], [], [], 1)
                for source in readable:
                    destination = upstream if source is self.connection else self.connection
                    try:
                        data = source.recv(65536)
                        if not data:
                            return
                        transferred += len(data)
                        destination.sendall(data)
                    except OSError:
                        return

    def do_GET(self):
        upstream = None
        try:
            target = normalize_url(self.path)
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme != 'http':
                raise CheckError('HTTPS требует CONNECT.')
            sock = self.server.connector(parsed.hostname, 80, 'http')
            upstream = http.client.HTTPConnection(parsed.hostname, timeout=5)
            upstream.sock = sock
            hop_headers = {'connection', 'proxy-connection', 'proxy-authorization', 'transfer-encoding', 'content-length', 'host', 'upgrade', 'te', 'trailer', 'keep-alive'}
            headers = {key: value for key, value in self.headers.items() if key.lower() not in hop_headers}
            headers['Host'] = parsed.hostname
            headers['Connection'] = 'close'
            path = parsed.path + ('?' + parsed.query if parsed.query else '')
            upstream.request('GET', path, headers=headers)
            response = upstream.getresponse()
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise CheckError('Ответ слишком велик.')
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in hop_headers:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
        except Exception:
            self.fail()
        finally:
            if upstream:
                upstream.close()

    def do_POST(self):
        self.fail()


class BrowserProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, connector=None):
        self.connector = connector or connect_destination
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(('127.0.0.1', 0), ProxyHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        request.settimeout(5)
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def __enter__(self):
        self.thread.start()
        return f'http://127.0.0.1:{self.server_address[1]}'

    def __exit__(self, *_args):
        self.shutdown()
        self.server_close()
        self.thread.join()
