"""Optional JavaScript rendering. All HTTP traffic goes through app.fetch.

No attempt is made to pass authentication, CAPTCHA or HTTP access denials.
The main process only invokes this worker after a successful HTML response.
"""
import json
import os
import sys
import time
import urllib.parse

from app import CheckError, MAX_BYTES, Resource, fetch, normalize_url


def render(initial: Resource, *, launch_options=None) -> str:
    from playwright.sync_api import sync_playwright

    deadline = time.monotonic() + 18
    used = 0
    options = {'headless': True, 'chromium_sandbox': True, 'args': ['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']}
    if os.environ.get('STORELENS_BROWSER_EXECUTABLE'):
        options['executable_path'] = os.environ['STORELENS_BROWSER_EXECUTABLE']
    if launch_options:
        options.update(launch_options)  # Controlled test harness only; not user input.
    initial_url = normalize_url(initial.url)
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(**options)
        try:
            context = browser.new_context(service_workers='block', accept_downloads=False)
            context.set_default_timeout(5000)

            def route_request(route):
                nonlocal used
                used += 1
                try:
                    if used > 30 or time.monotonic() >= deadline:
                        raise CheckError('Лимит браузерных запросов.')
                    request = route.request
                    if request.method != 'GET' or request.resource_type in ('image', 'media', 'font'):
                        return route.abort()
                    url = normalize_url(request.url)
                    if request.is_navigation_request() and request.frame == page.main_frame and url != initial_url:
                        return route.abort()
                    if used == 1 and url == initial_url:
                        result = initial
                    else:
                        result = fetch(url, expected='any', timeout=min(3, max(.1, deadline - time.monotonic())))
                    # Do not silently change an origin by fulfilling a redirect
                    # response at the old URL. Such resources remain unavailable.
                    if result.url != url:
                        return route.abort()
                    return route.fulfill(status=200, content_type=result.mime, body=result.body if result.body is not None else result.text.encode())
                except Exception:
                    return route.abort()

            context.route('**/*', route_request)
            context.add_init_script("""for (const key of ['WebSocket','WebTransport','RTCPeerConnection','webkitRTCPeerConnection','Worker','SharedWorker']) { Object.defineProperty(globalThis,key,{value:undefined,configurable:false}); }""")
            page = context.new_page()
            page.route_web_socket('**/*', lambda ws: ws.close())
            page.goto(initial_url, wait_until='domcontentloaded', timeout=18000)
            page.wait_for_timeout(1200)
            html = page.content()
            if len(html.encode()) > MAX_BYTES:
                raise CheckError('Отрисованный документ слишком велик.')
            return html
        finally:
            browser.close()


def main():
    try:
        payload = json.loads(sys.stdin.read(MAX_BYTES * 2))
        html = render(Resource(normalize_url(payload['url']), payload['html'], []))
        print(json.dumps({'ok': True, 'html': html}, ensure_ascii=False))
    except ImportError:
        print(json.dumps({'ok': False, 'error': 'Playwright не установлен. Выполните установку браузерного модуля по README.'}))
    except Exception:
        print(json.dumps({'ok': False, 'error': 'Браузерная загрузка недоступна. Проверьте установку Chromium и поддержку sandbox; ограничения доступа сайта не обходятся.'}))


if __name__ == '__main__':
    main()
