"""Anonymous native browser loading through a public-address-only proxy."""
import json
import os
import re
import sys
import time
import urllib.parse

from app import CheckError, MAX_BYTES, normalize_url
from browser_proxy import BrowserProxy


def explain_browser_error(exc):
    """Expose only a whitelisted browser code, never raw URLs or credentials."""
    match = re.search(r'net::(ERR_[A-Z_]+)', str(exc))
    if match:
        code = match[1]
        hints = {
            'ERR_TUNNEL_CONNECTION_FAILED': 'Не удалось установить защищённый туннель к сайту.',
            'ERR_PROXY_CONNECTION_FAILED': 'Браузер не подключился к проверяющему прокси.',
            'ERR_NAME_NOT_RESOLVED': 'Не удалось разрешить доменное имя.',
            'ERR_CONNECTION_TIMED_OUT': 'Истекло время подключения к сайту.',
            'ERR_CONNECTION_RESET': 'Соединение с сайтом было сброшено.',
            'ERR_CERT_AUTHORITY_INVALID': 'Chromium не доверяет сертификату соединения. Проверка TLS сохранена.',
            'ERR_CERT_DATE_INVALID': 'Chromium отклонил сертификат с некорректным сроком действия.',
            'ERR_SSL_PROTOCOL_ERROR': 'Не удалось согласовать защищённое TLS-соединение.',
        }
        return CheckError(f'Chromium: {code}. ' + hints.get(code, 'Страница не загружена; точная причина пока не установлена.'), kind='browser_tls' if 'CERT_' in code or 'SSL_' in code else 'browser_network')
    if type(exc).__name__ == 'TimeoutError':
        return CheckError('Chromium: истекло время ожидания загрузки страницы.', kind='timeout')
    return CheckError('Не удалось запустить или загрузить Chromium. Проверьте браузерный модуль и сетевое соединение.', kind='browser')


def browser_options():
    options = {'headless': True, 'chromium_sandbox': True, 'args': [
        '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--proxy-bypass-list=<-loopback>',
    ]}
    if os.environ.get('STORELENS_BROWSER_EXECUTABLE'):
        options['executable_path'] = os.environ['STORELENS_BROWSER_EXECUTABLE']
    return options


def probe():
    """Actually start the installed browser; an import alone is not readiness."""
    from playwright.sync_api import sync_playwright
    with BrowserProxy() as proxy, sync_playwright() as runtime:
        options = browser_options()
        options['proxy'] = {'server': proxy}
        browser = runtime.chromium.launch(**options)
        try:
            context = browser.new_context(offline=True, service_workers='block')
            page = context.new_page()
            page.set_content('<title>StoreLens ready</title>')
            if page.title() != 'StoreLens ready':
                raise CheckError('Не удалось проверить браузер.')
        finally:
            browser.close()


def render(url: str, *, launch_options=None, connector=None) -> dict:
    from playwright.sync_api import sync_playwright
    initial_url = normalize_url(url)
    initial = urllib.parse.urlsplit(initial_url)
    host = initial.hostname.removeprefix('www.')
    deadline = time.monotonic() + 18
    used = 0
    options = browser_options()
    if launch_options:
        options.update(launch_options)  # Controlled fixtures only, not web input.
    with BrowserProxy(connector=connector) as proxy, sync_playwright() as runtime:
        options['proxy'] = {'server': proxy}
        browser = runtime.chromium.launch(**options)
        try:
            context = browser.new_context(service_workers='block', accept_downloads=False)
            context.set_default_timeout(5000)

            def route_request(route):
                nonlocal used
                used += 1
                try:
                    if used > 30 or time.monotonic() >= deadline:
                        return route.abort()
                    request = route.request
                    if request.method != 'GET' or request.resource_type in ('image', 'media', 'font'):
                        return route.abort()
                    target = normalize_url(request.url)
                    parsed = urllib.parse.urlsplit(target)
                    if request.is_navigation_request() and request.frame == page.main_frame:
                        if parsed.hostname.removeprefix('www.') != host:
                            return route.abort()
                        if initial.scheme == 'https' and parsed.scheme != 'https':
                            return route.abort()
                    return route.continue_()
                except Exception:
                    return route.abort()

            context.route('**/*', route_request)
            context.add_init_script("""for (const key of ['WebSocket','WebTransport','RTCPeerConnection','webkitRTCPeerConnection','Worker','SharedWorker']) { Object.defineProperty(globalThis,key,{value:undefined,configurable:false}); }""")
            page = context.new_page()
            page.route_web_socket('**/*', lambda ws: ws.close())
            try:
                response = page.goto(initial_url, wait_until='domcontentloaded', timeout=18000)
            except Exception as exc:
                raise explain_browser_error(exc) from None
            if not response or response.status >= 400:
                status = response.status if response else None
                raise CheckError(f'Браузер тоже получил отказ HTTP {status}.' if status else 'Браузер не получил страницу.', kind='http', status=status)
            page.wait_for_timeout(1200)
            html = page.content()
            if len(html.encode()) > MAX_BYTES:
                raise CheckError('Отрисованный документ слишком велик.')
            return {'html': html, 'url': normalize_url(page.url)}
        finally:
            browser.close()


def main():
    try:
        payload = json.loads(sys.stdin.read(8192))
        if payload.get('action') == 'probe':
            probe()
            result = {}
        else:
            result = render(payload['url'])
        print(json.dumps({'ok': True, **result}, ensure_ascii=False))
    except ImportError:
        print(json.dumps({'ok': False, 'error': 'Playwright не установлен в активном Python. Запустите bash ./start-mac.command из папки проекта.', 'kind': 'not_configured'}))
    except CheckError as exc:
        print(json.dumps({'ok': False, 'error': str(exc), 'kind': exc.kind, 'status': exc.status}))
    except Exception as exc:
        error = explain_browser_error(exc)
        print(json.dumps({'ok': False, 'error': str(error), 'kind': error.kind}))


if __name__ == '__main__':
    main()
