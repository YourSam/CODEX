"""StoreLens prototype. Python 3.11+, no third-party dependencies."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
MAX_BYTES = 1_500_000
TIMEOUT = 7
SLOTS = threading.BoundedSemaphore(3)


class CheckError(ValueError):
    pass


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise CheckError('Укажите корректную ссылку длиной до 2048 символов.')
    if '://' not in value:
        value = 'https://' + value
    try:
        p = urllib.parse.urlsplit(value)
        host = (p.hostname or '').encode('idna').decode('ascii').lower()
        if p.scheme not in ('https', 'http') or not host or p.username is not None or p.password is not None:
            raise ValueError()
        if p.port not in (None, 80 if p.scheme == 'http' else 443):
            raise ValueError()
        if host.endswith('.') or '.' not in host or '%' in host or '\\' in value:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError()
        if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.')):
            raise ValueError()
        if host.endswith(('.localhost', '.local', '.internal', '.test', '.invalid')):
            raise ValueError()
        path = urllib.parse.quote(p.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = urllib.parse.quote(p.query, safe="%=&?/:@!$'()*+,;~-._")
        return urllib.parse.urlunsplit((p.scheme, host, path, query, ''))
    except (ValueError, UnicodeError):
        raise CheckError('Разрешены только публичные домены и стандартные HTTP/HTTPS-порты. Ссылки с паролями и IP-адресами не принимаются.') from None


def public_addresses(host: str, port: int) -> list[str]:
    try:
        addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    except OSError:
        raise CheckError('Не удалось получить DNS-адрес сайта.') from None
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise CheckError('Доступ к внутренним и служебным адресам запрещён.')
    return addresses


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PinnedHTTP(http.client.HTTPConnection):
    def connect(self):
        addresses = public_addresses(self.host, self.port)
        self.sock = socket.create_connection((addresses[0], self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        addresses = public_addresses(self.host, self.port)
        self.sock = socket.create_connection((addresses[0], self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host)


class SafeHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(PinnedHTTP, req)


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(PinnedHTTPS, req, context=self._context)


@dataclass
class Resource:
    url: str
    text: str
    redirects: list[str]


def fetch(url: str, *, expected: str = 'html') -> Resource:
    """Validate each redirect. Direct connections pin the validated public IP.

    With an inherited proxy, urllib delegates transport/DNS to that trusted proxy;
    its egress policy must also reject private destinations (see README).
    """
    redirects = []
    # Keep the platform proxy and CA trust. Only direct connections need pinning.
    current = normalize_url(url)
    for _ in range(5):
        p = urllib.parse.urlsplit(current)
        public_addresses(p.hostname, 443 if p.scheme == 'https' else 80)
        proxy = urllib.request.getproxies()
        proxied = bool(proxy.get(p.scheme)) and not urllib.request.proxy_bypass(p.hostname)
        handlers = [NoRedirect()]
        if not proxied:
            handlers += [SafeHTTPHandler(), SafeHTTPSHandler()]
        opener = urllib.request.build_opener(*handlers)
        request = urllib.request.Request(current, headers={
            'User-Agent': 'StoreLensPrototype/0.1 (website risk research)',
            'Accept': 'application/json' if expected == 'json' else 'text/html,application/xhtml+xml',
            'Accept-Encoding': 'identity',
        })
        try:
            response = opener.open(request, timeout=TIMEOUT)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and exc.headers.get('Location'):
                target = normalize_url(urllib.parse.urljoin(current, exc.headers['Location']))
                exc.close()
                if p.scheme == 'https' and target.startswith('http:'):
                    raise CheckError('Сайт перенаправляет с HTTPS на незащищённый HTTP. Загрузка остановлена.')
                redirects.append(current)
                current = target
                continue
            code = exc.code
            exc.close()
            raise CheckError(f'Источник вернул HTTP {code}. Это не доказывает мошенничество.') from None
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise CheckError('Источник недоступен: соединение, TLS или сетевые ограничения. Это не доказывает мошенничество.') from None
        with response:
            mime = response.headers.get_content_type()
            if expected == 'html' and mime not in ('text/html', 'application/xhtml+xml'):
                raise CheckError('По ссылке не HTML-страница магазина.')
            if expected == 'json' and not (mime.endswith('/json') or mime.endswith('+json')):
                raise CheckError('Источник не вернул ожидаемые данные JSON.')
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise CheckError('Ответ превышает лимит размера; источник не обработан.')
            charset = response.headers.get_content_charset() or 'utf-8'
            try:
                text = data.decode(charset, errors='replace')
            except LookupError:
                text = data.decode('utf-8', errors='replace')
            return Resource(current, text, redirects)
    raise CheckError('Слишком много перенаправлений; проверка источника остановлена.')


class Page(HTMLParser):
    def __init__(self, source: Resource):
        super().__init__(convert_charrefs=True)
        self.url = source.url
        self.parts = []
        self.links = []
        self.title = ''
        self.hidden = 0
        self.in_title = False
        self.anchor = None
        self.feed(source.text)
        self.text = re.sub(r'\s+', ' ', ' '.join(self.parts)).strip()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'style', 'noscript', 'template'):
            self.hidden += 1
        if tag == 'title':
            self.in_title = True
        if tag == 'a':
            self.anchor = [a.get('href', ''), '']

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript', 'template'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'title':
            self.in_title = False
        if tag == 'a' and self.anchor:
            self.links.append(tuple(self.anchor))
            self.anchor = None

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)
            if self.in_title:
                self.title += data
            if self.anchor:
                self.anchor[1] += data


def related_pages(page: Page) -> list[str]:
    result = []
    host = urllib.parse.urlsplit(page.url).hostname
    for href, label in page.links:
        if not re.search(r'контакт|оплат|достав|возврат|реквизит|contact|payment|delivery|return|refund|legal', href + ' ' + label, re.I):
            continue
        try:
            url = normalize_url(urllib.parse.urljoin(page.url, href))
        except CheckError:
            continue
        if urllib.parse.urlsplit(url).hostname == host and url != page.url and url not in result:
            result.append(url)
    return result[:3]


def finding(key, title, status, summary, sources=None, evidence=None):
    return dict(id=key, title=title, status=status, summary=summary, sources=sources or [], evidence=evidence or [])


def analyze_pages(pages: list[Page]) -> list[dict]:
    definitions = [
        ('contacts', 'Контакты', r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}|(?:\+7|8)[\s(.-]*\d{3}[\s).-]*\d{3}[\s.-]*\d{2}[\s.-]*\d{2}', 'Контакты найдены. Их принадлежность продавцу не подтверждена.'),
        ('company', 'Реквизиты продавца', r'\b(?:ИНН|ОГРН(?:ИП)?)\s*[:№]?\s*\d{10,15}\b', 'Найдены заявленные реквизиты. Проверка по реестру пока не подключена.'),
        ('returns', 'Условия возврата', r'.{0,65}(?:возврат\w*|refund\w*|return policy).{0,110}', 'Найдены упоминания возврата. Полнота и законность условий не подтверждены.'),
        ('payment', 'Условия оплаты', r'.{0,65}(?:оплат\w*|payment|checkout).{0,110}', 'Найдены упоминания оплаты. Это не подтверждает безопасность платежа.'),
    ]
    checks = []
    for key, title, pattern, summary in definitions:
        evidence, sources = [], []
        for page in pages:
            hits = list(dict.fromkeys(re.findall(pattern, page.text, re.I)))[:2]
            if hits:
                evidence.extend(hits)
                sources.append(page.url)
        checks.append(finding(key, title, 'observed' if evidence else 'unknown', summary if evidence else 'На просмотренных страницах сведения не обнаружены. Они могут быть на других страницах или загружаться через JavaScript.', sources, evidence[:4]))
    return checks


def domain_check(host: str) -> dict:
    url = 'https://rdap.org/domain/' + host.removeprefix('www.')
    try:
        resource = fetch(url, expected='json')
        data = json.loads(resource.text)
        dates = [e.get('eventDate') for e in data.get('events', []) if e.get('eventAction') == 'registration']
        if not dates:
            raise CheckError('RDAP не предоставил дату регистрации этого имени.')
        date = dt.datetime.fromisoformat(dates[0].replace('Z', '+00:00'))
        if date.tzinfo is None:
            date = date.replace(tzinfo=dt.timezone.utc)
        age = (dt.datetime.now(dt.timezone.utc) - date).days
        if age < 0:
            raise CheckError('Источник вернул некорректную дату регистрации.')
        young = age < 180
        return finding('domain', 'История домена', 'caution' if young else 'observed', f'Дата регистрации: {date:%d.%m.%Y}. Возраст: {age} дней. ' + ('Домен младше 180 дней; это повод проверить продавца внимательнее, а не доказательство мошенничества.' if young else 'Возраст домена не подтверждает добросовестность текущего продавца.'), [resource.url])
    except (CheckError, ValueError, TypeError, KeyError, AttributeError):
        return finding('domain', 'История домена', 'unknown', 'Дата регистрации не получена: RDAP может быть недоступен или не поддерживать доменную зону / поддомен.', [url])


def check_store(value: str) -> dict:
    started = time.monotonic()
    url = normalize_url(value)
    host = urllib.parse.urlsplit(url).hostname
    social = host == 'instagram.com' or host.endswith('.instagram.com')
    checks = []
    pages = []
    title = host
    if social:
        checks.append(finding('instagram', 'Instagram-профиль', 'unknown', 'Автоматический доступ к Instagram пока не подключён. Возраст instagram.com и его HTTPS не оценивают продавца. Вставьте сайт магазина из описания профиля.'))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            domain = pool.submit(domain_check, host)
            try:
                resource = fetch(url)
                page = Page(resource)
                pages.append(page)
                title = page.title.strip()[:160] or host
                checks.append(finding('connection', 'Загрузка и соединение', 'observed' if resource.url.startswith('https:') else 'caution', 'Страница загружена по HTTPS с проверкой сертификата. Это защищает соединение, но не подтверждает честность продавца.' if resource.url.startswith('https:') else 'Страница загружена по HTTP без шифрования.', [resource.url]))
                original_host = host.removeprefix('www.')
                final_host = urllib.parse.urlsplit(resource.url).hostname.removeprefix('www.')
                if original_host != final_host:
                    checks.append(finding('redirect', 'Переход на другой домен', 'caution', f'Ссылка перенаправляет на {final_host}. Убедитесь, что это ожидаемый магазин.', [url, resource.url]))
                links = related_pages(page)
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as subpool:
                    futures = {subpool.submit(fetch, link): link for link in links}
                    for future, link in futures.items():
                        try:
                            extra = future.result()
                            if urllib.parse.urlsplit(extra.url).hostname != urllib.parse.urlsplit(page.url).hostname:
                                raise CheckError('Страница перенаправляет за пределы магазина.')
                            pages.append(Page(extra))
                        except CheckError as exc:
                            checks.append(finding('page-' + str(len(checks)), 'Дополнительная страница', 'unknown', str(exc), [link]))
                if len(page.text) < 200 or re.search(r'just a moment|verify you are human|checking your browser|captcha|проверка браузера', page.text, re.I):
                    checks.append(finding('content', 'Доступность содержимого', 'unknown', 'Страница содержит мало текста или защиту от ботов. Сведения о магазине могут быть неполными.', [page.url]))
                checks.extend(analyze_pages(pages))
            except CheckError as exc:
                checks.append(finding('connection', 'Загрузка сайта', 'unknown', str(exc), [url]))
            checks.append(domain.result())
    checks.extend([
        finding('threats', 'Базы фишинга и вредоносных сайтов', 'not_connected', 'Источник угроз пока не подключён. Проверка по базам не выполнялась.'),
        finding('reputation', 'Независимая репутация', 'not_connected', 'Поисковый API пока не подключён. Внешние отзывы и жалобы не проверены.'),
        finding('registry', 'Подтверждение организации', 'not_connected', 'Реестр компаний пока не подключён. Реквизиты на сайте не подтверждают личность владельца.'),
    ])
    caution = sum(c['status'] == 'caution' for c in checks)
    observed = sum(c['status'] == 'observed' for c in checks)
    return dict(url=url, host=host, title=title, checked_at=dt.datetime.now(dt.timezone.utc).isoformat(), duration_seconds=round(time.monotonic() - started, 1),
                verdict='caution' if caution else 'insufficient',
                headline='Есть поводы для дополнительной проверки' if caution else 'Недостаточно данных для вывода о надёжности',
                summary='Не переводите предоплату, опираясь только на этот отчёт. Технические сведения и заявления магазина не подтверждают выполнение заказов.',
                checks=checks, observed=observed, caution=caution,
                pages=[{'url': p.url, 'title': p.title[:160]} for p in pages],
                next_steps=['Сверьте ИНН, название и платёжные реквизиты с официальным реестром.', 'Поищите независимые отзывы по домену, телефону и реквизитам.', 'Предпочитайте оплату с защитой покупателя; избегайте переводов незнакомому физлицу.'],
                analysis_mode='rules', limitations='Прототип: проверка доступных страниц и RDAP. ИИ, поиск отзывов и базы угроз не подключены. Отсутствие находок не означает безопасность.')


class Handler(BaseHTTPRequestHandler):
    server_version = 'StoreLens/0.1'

    def log_message(self, fmt, *args):
        # Do not log submitted URLs, query strings or report content.
        pass

    def send_bytes(self, code, payload, mime):
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def json(self, code, data):
        self.send_bytes(code, json.dumps(data, ensure_ascii=False).encode(), 'application/json; charset=utf-8')

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/api/health':
            return self.json(200, {'status': 'ok', 'version': '0.1', 'analysis_mode': 'rules'})
        files = {'/': ('index.html', 'text/html'), '/style.css': ('style.css', 'text/css'), '/app.js': ('app.js', 'text/javascript')}
        if path not in files:
            return self.json(404, {'error': 'Страница не найдена.'})
        name, mime = files[path]
        self.send_bytes(200, (ROOT / 'static' / name).read_bytes(), mime + '; charset=utf-8')

    def do_POST(self):
        if self.path != '/api/check':
            return self.json(404, {'error': 'Неизвестный метод.'})
        origin = self.headers.get('Origin')
        if origin and (urllib.parse.urlsplit(origin).netloc != self.headers.get('Host') or self.headers.get('Sec-Fetch-Site') == 'cross-site'):
            return self.json(403, {'error': 'Запрос с другого сайта запрещён.'})
        if self.headers.get_content_type() != 'application/json':
            return self.json(415, {'error': 'Ожидается application/json.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                return self.json(413, {'error': 'Некорректный размер запроса.'})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or not isinstance(body.get('url'), str):
                raise ValueError()
            url = normalize_url(body['url'])
        except (ValueError, UnicodeError):
            return self.json(400, {'error': 'Укажите корректную публичную ссылку на магазин.'})
        if not SLOTS.acquire(blocking=False):
            return self.json(429, {'error': 'Сейчас выполняется несколько проверок. Повторите чуть позже.'})
        try:
            self.json(200, check_store(url))
        except CheckError as exc:
            self.json(400, {'error': str(exc)})
        except Exception:
            self.json(500, {'error': 'Проверка не завершена из-за внутренней ошибки. Попробуйте другую ссылку.'})
        finally:
            SLOTS.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


def main():
    parser = argparse.ArgumentParser(description='StoreLens — проверка магазина')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    server = Server((args.host, args.port), Handler)
    print(f'StoreLens: http://{args.host}:{args.port} (Ctrl+C для остановки)', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
