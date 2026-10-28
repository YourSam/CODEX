import datetime as dt
import io
import json
import ssl
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import app


class DiagnosticTests(unittest.TestCase):
    def test_http_401_keeps_status_and_does_not_claim_fraud(self):
        error = urllib.error.HTTPError('https://shop.example/', 401, 'Denied', {}, io.BytesIO())
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(app.CheckError) as caught:
                app.fetch('https://shop.example/')
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(caught.exception.kind, 'http')
        self.assertIn('не доказывает', str(caught.exception))

    def test_api_key_never_follows_a_redirect(self):
        error = urllib.error.HTTPError('https://api.example/', 302, 'Found', {'Location': 'https://other.example/'}, io.BytesIO())
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(app.CheckError) as caught:
                app.fetch('https://api.example/', headers={'X-Subscription-Token': 'test-only'})
        self.assertEqual(caught.exception.kind, 'api_redirect')
        self.assertEqual(opener.return_value.open.call_count, 1)

    def test_tls_failure_has_actionable_diagnosis(self):
        error = urllib.error.URLError(ssl.SSLCertVerificationError('untrusted'))
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(app.CheckError) as caught:
                app.fetch('https://shop.example/')
        self.assertEqual(caught.exception.kind, 'tls')
        self.assertIn('Install Certificates.command', str(caught.exception))


class WhoisTests(unittest.TestCase):
    def test_ru_authoritative_fallback_and_query_binding(self):
        connection = MagicMock()
        connection.recv.side_effect = [b'domain: DNS-SHOP.RU\r\ncreated: 2004-01-01T00:00:00Z\r\n', b'']
        with patch('urllib.request.getproxies', return_value={}), patch('app.public_addresses', return_value=['93.184.216.34']) as dns, patch('socket.create_connection') as create:
            create.return_value.__enter__.return_value = connection
            date, domain = app.whois_created('www.dns-shop.ru')
        self.assertEqual(date.year, 2004)
        self.assertEqual(domain, 'dns-shop.ru')
        dns.assert_called_once_with('whois.tcinet.ru', 43)
        connection.sendall.assert_called_once_with(b'dns-shop.ru\r\n')

    def test_does_not_bypass_http_proxy_for_whois(self):
        with patch('urllib.request.getproxies', return_value={'https': 'http://proxy:8080'}), patch('socket.create_connection') as create:
            with self.assertRaises(app.CheckError):
                app.whois_created('dns-shop.ru')
        create.assert_not_called()

    def test_no_arbitrary_server_or_ambiguous_subdomain(self):
        for domain in ['example.com', 'a.b.ru', 'evil.ru\r\nother.ru']:
            with self.subTest(domain=domain), self.assertRaises(app.CheckError):
                app.whois_created(domain)

    def test_rdap_failure_uses_verified_whois_date(self):
        with patch('app.fetch', side_effect=app.CheckError('no RDAP')), patch('app.whois_created', return_value=(dt.datetime(2004, 1, 1, tzinfo=dt.timezone.utc), 'dns-shop.ru')):
            result = app.domain_check('dns-shop.ru')
        self.assertEqual(result['status'], 'observed')
        self.assertIn('WHOIS', result['evidence'][0])
        self.assertIn('2004', result['summary'])


class IndependentSourcesTests(unittest.TestCase):
    def test_archive_returns_dated_external_source(self):
        payload = [['timestamp', 'original'], ['20150102030405', 'https://shop.example/']]
        with patch('app.fetch', return_value=app.Resource('https://web.archive.org/', json.dumps(payload), [])):
            result = app.archive_check('shop.example')
        self.assertEqual(result['status'], 'observed')
        self.assertIn('02.01.2015', result['summary'])
        self.assertIn('20150102030405', result['sources'][1])

    def test_archive_other_domain_is_not_evidence(self):
        payload = [['timestamp', 'original'], ['20150102030405', 'https://other.example/']]
        with patch('app.fetch', return_value=app.Resource('https://web.archive.org/', json.dumps(payload), [])):
            self.assertEqual(app.archive_check('shop.example')['status'], 'unknown')

    def test_no_search_key_does_not_make_a_request(self):
        with patch.dict('os.environ', {}, clear=True), patch('app.fetch') as fetch:
            self.assertEqual(app.search_mentions('shop.example')['status'], 'not_connected')
        fetch.assert_not_called()

    def test_search_collects_external_snippets_without_reputation_points(self):
        data = {'web': {'results': [
            {'url': 'https://shop.example/own', 'title': 'Our own reviews'},
            {'url': 'javascript:alert(1)', 'title': 'Invalid'},
            {'url': 'https://reviews.example/shop', 'title': 'Review', 'description': '<b>Unverified</b> report'},
        ]}}
        with patch.dict('os.environ', {'STORELENS_SEARCH_KEY': 'test-only'}), patch('app.fetch', return_value=app.Resource('https://api.search.brave.com/', json.dumps(data), [])) as fetch:
            result = app.search_mentions('shop.example')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['sources'], ['https://reviews.example/shop'])
        self.assertNotIn('<b>', result['evidence'][0])
        self.assertEqual(fetch.call_args.kwargs['headers'], {'X-Subscription-Token': 'test-only'})
        self.assertNotIn('test-only', json.dumps(result))
        checks = [app.finding('contacts', 'Контакты', 'observed', ''), result]
        self.assertEqual(app.score_evidence(checks, 1)['value'], 5)

    def test_401_does_not_cancel_domain_archive_or_search(self):
        with patch.dict('os.environ', {'STORELENS_BROWSER': '0'}), patch('app.fetch', side_effect=app.CheckError('HTTP 401', kind='http', status=401)), \
             patch('app.domain_check', return_value=app.finding('domain', 'Домен', 'observed', 'Домен зарегистрирован в 2004', ['https://rdap.org/'])), \
             patch('app.archive_check', return_value=app.finding('archive', 'Архив', 'observed', 'Снимок 2015 года', ['https://web.archive.org/'])), \
             patch('app.search_mentions', return_value=app.finding('mentions', 'Упоминания', 'observed', 'Найдена ссылка', ['https://reviews.example/'])), \
             patch('app.browser_render') as browser:
            report = app.check_store('dns-shop.ru')
        browser.assert_not_called()
        self.assertEqual(report['collection']['http_status'], 401)
        self.assertEqual(report['collection']['external_results'], 3)
        self.assertIsNone(report['score']['value'])
        self.assertIn('частичный отчёт', report['headline'])
        self.assertIn('HTTP 401', report['summary'])
        self.assertIn('archive', [f['check_id'] for f in report['assessment']['facts']])

    def test_js_shell_can_use_rendered_content(self):
        initial = app.Resource('https://shop.example/', '<div id="app"></div><script src="/main.js"></script>', [])
        rendered = app.Resource(initial.url, '<main>shop@example.com Оплата картой. Возврат товара 14 дней.</main>' + '<p>Информация о магазине.</p>' * 30, [])
        with patch('app.fetch', return_value=initial), patch('app.browser_render', return_value=rendered) as browser, \
             patch('app.domain_check', return_value=app.finding('domain', 'Домен', 'unknown', '')), \
             patch('app.archive_check', return_value=app.finding('archive', 'Архив', 'unknown', '')), \
             patch('app.search_mentions', return_value=app.finding('mentions', 'Поиск', 'not_connected', '')):
            report = app.check_store(initial.url)
        browser.assert_called_once()
        self.assertGreater(report['score']['value'], 0)
        self.assertIn('browser', [c['id'] for c in report['checks'] if c['status'] == 'observed'])

    def test_captcha_is_not_sent_to_browser_or_scored_as_merchant_data(self):
        with patch('app.fetch', return_value=app.Resource('https://shop.example/', '<p>Verify you are human. CAPTCHA support@example.com</p>', [])), \
             patch('app.browser_render') as browser, \
             patch('app.domain_check', return_value=app.finding('domain', 'Домен', 'unknown', '')), \
             patch('app.archive_check', return_value=app.finding('archive', 'Архив', 'unknown', '')), \
             patch('app.search_mentions', return_value=app.finding('mentions', 'Поиск', 'not_connected', '')):
            report = app.check_store('shop.example')
        browser.assert_not_called()
        self.assertIsNone(report['score']['value'])


if __name__ == '__main__':
    unittest.main()
