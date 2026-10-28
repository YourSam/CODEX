import datetime as dt
import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import app


class InputSecurityTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(app.normalize_url(' Example.COM/catalog#top '), 'https://example.com/catalog')
        self.assertIn('xn--', app.normalize_url('магазин.рф'))

    def test_reject_unsafe_inputs(self):
        for url in ['file:///etc/passwd', 'http://127.0.0.1', 'http://[::1]', 'http://localhost', 'https://a.local', 'https://user:pass@example.com', 'https://example.com:22', 'https://example.com\\@evil.com', 'https://example.com\n', 'https://example.com./', 'http://2130706433', '//example.com', '']:
            # Whitespace outside a URL is intentionally trimmed.
            if url.endswith('\n'):
                url = 'https://exa\nmple.com'
            with self.subTest(url=url), self.assertRaises(app.CheckError):
                app.normalize_url(url)

    def test_reject_mixed_private_dns(self):
        rows = [(2, 1, 6, '', ('93.184.216.34', 443)), (2, 1, 6, '', ('169.254.169.254', 443))]
        with patch('socket.getaddrinfo', return_value=rows), self.assertRaises(app.CheckError):
            app.public_addresses('example.com', 443)

    def test_redirect_to_private_ip_is_not_followed(self):
        error = urllib.error.HTTPError('https://example.com/', 302, 'Found', {'Location': 'http://127.0.0.1/secrets'}, io.BytesIO())
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(app.CheckError):
                app.fetch('https://example.com/')
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_redirect_rechecks_dns(self):
        error = urllib.error.HTTPError('https://example.com/', 302, 'Found', {'Location': 'https://other.example/'}, io.BytesIO())
        with patch('app.public_addresses', side_effect=[['93.184.216.34'], app.CheckError('private')]) as dns, patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(app.CheckError):
                app.fetch('https://example.com/')
            self.assertEqual(dns.call_count, 2)
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_https_downgrade_blocked(self):
        error = urllib.error.HTTPError('https://example.com/', 302, 'Found', {'Location': 'http://example.com/'}, io.BytesIO())
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaisesRegex(app.CheckError, 'HTTPS'):
                app.fetch('https://example.com/')

    def test_direct_connection_uses_validated_ip(self):
        with patch('app.public_addresses', return_value=['93.184.216.34']), patch('socket.create_connection') as connect:
            app.PinnedHTTP('example.com', timeout=7).connect()
            connect.assert_called_once_with(('93.184.216.34', 80), 7)


class AnalysisTests(unittest.TestCase):
    def test_script_content_not_used_as_evidence(self):
        page = app.Page(app.Resource('https://shop.example/', '<script>ИНН 1234567890</script><p>Возврат в течение 14 дней</p>', []))
        checks = {c['id']: c for c in app.analyze_pages([page])}
        self.assertEqual(checks['company']['status'], 'unknown')
        self.assertEqual(checks['returns']['status'], 'observed')

    def test_navigation_is_not_payment_or_returns_policy(self):
        html = '<nav>Методы оплаты картой Возврат товара</nav><a href="/pay">Оплата картой</a><footer>Возврат товара 14 дней</footer>'
        page = app.Page(app.Resource('https://shop.example/', html, []))
        checks = {c['id']: c for c in app.analyze_pages([page])}
        self.assertEqual(checks['payment']['status'], 'unknown')
        self.assertEqual(checks['returns']['status'], 'unknown')

    def test_payment_label_alone_is_not_policy(self):
        page = app.Page(app.Resource('https://shop.example/', '<p>Методы оплаты</p>', []))
        checks = {c['id']: c for c in app.analyze_pages([page])}
        self.assertEqual(checks['payment']['status'], 'unknown')

    def test_actual_policy_text_is_found(self):
        page = app.Page(app.Resource('https://shop.example/', '<main><p>Оплата банковской картой при получении.</p><p>Возврат товара в течение 14 дней.</p></main>', []))
        checks = {c['id']: c for c in app.analyze_pages([page])}
        self.assertEqual(checks['payment']['status'], 'observed')
        self.assertEqual(checks['returns']['status'], 'observed')

    def test_contacts_deduplicated_across_pages_but_sources_retained(self):
        pages = [app.Page(app.Resource('https://shop.example/' + str(i), '<p>+7 800 551-84-74 shop@example.com</p>', [])) for i in range(3)]
        pages.append(app.Page(app.Resource('https://shop.example/4', '<p>8 (800) 551 84 74</p>', [])))
        contacts = app.analyze_pages(pages)[0]
        self.assertEqual(len(contacts['evidence']), 2)
        self.assertEqual(len(contacts['sources']), 4)

    def test_related_links_stay_on_same_host(self):
        page = app.Page(app.Resource('https://shop.example/', '<a href="/contacts">Контакты</a><a href="https://evil.example/return">Возврат</a><a href="javascript:alert(1)">Оплата</a>', []))
        self.assertEqual(app.related_pages(page), ['https://shop.example/contacts'])

    def test_unavailable_site_is_not_fraud_or_safe(self):
        with patch('app.fetch', side_effect=app.CheckError('blocked')):
            report = app.check_store('shop.example')
        self.assertEqual(report['verdict'], 'insufficient')
        self.assertEqual(report['observed'], 0)
        self.assertEqual(report['pages'], [])
        self.assertIn('не завершена', report['assessment']['headline'])
        self.assertIn('Повторите', report['assessment']['recommendation'])
        self.assertTrue(any(c['id'] == 'reputation' and c['status'] == 'not_connected' for c in report['checks']))

    def test_instagram_does_not_score_platform_age(self):
        with patch('app.fetch') as fetch:
            report = app.check_store('https://instagram.com/shop_name/')
        fetch.assert_not_called()
        self.assertEqual(report['verdict'], 'insufficient')
        self.assertNotIn('domain', [c['id'] for c in report['checks']])
        self.assertIn('сайт из описания', report['assessment']['recommendation'])

    def test_full_pipeline_preserves_evidence_and_limits_verdict(self):
        def fixture(url, **kwargs):
            if url.startswith('https://rdap.org/'):
                return app.Resource(url, json.dumps({'events': [{'eventAction': 'registration', 'eventDate': '2010-01-01T00:00:00Z'}]}), [])
            if url.endswith('/contacts'):
                return app.Resource(url, '<p>ИНН 1234567890. shop@example.com</p>', [])
            return app.Resource(url, '<title>Test Store</title><p>Оплата картой. Возврат 14 дней.</p><a href="/contacts">Контакты</a>', [])
        with patch('app.fetch', side_effect=fixture):
            report = app.check_store('shop.example')
        self.assertEqual(len(report['pages']), 2)
        checks = {c['id']: c for c in report['checks']}
        self.assertIn('shop@example.com', checks['contacts']['evidence'])
        self.assertEqual(checks['contacts']['sources'], ['https://shop.example/contacts'])
        self.assertEqual(report['verdict'], 'insufficient')
        self.assertEqual(report['analysis_mode'], 'rules')
        assessment = report['assessment']
        self.assertIn('контакты', assessment['explanation'])
        self.assertIn('С предоплатой', assessment['recommendation'])
        self.assertIn('registry', [g['check_id'] for g in assessment['gaps']])
        self.assertNotIn('contacts', [g['check_id'] for g in assessment['gaps']])
        self.assertIn('contacts', [f['check_id'] for f in assessment['facts']])

    def test_assessment_links_signals_to_their_evidence(self):
        checks = [app.finding('domain', 'История домена', 'caution', 'Домен младше 180 дней.', ['https://rdap.org/domain/shop.example'])]
        assessment = app.make_assessment(checks, 1)
        self.assertEqual(assessment['signals'], [{'check_id': 'domain', 'text': 'Домен младше 180 дней.'}])
        self.assertNotIn('domain', [g['check_id'] for g in assessment['gaps']])
        self.assertNotIn('мошенник', assessment['headline'])

    def test_young_domain_is_caution_not_fraud(self):
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        resource = app.Resource('https://rdap.org/domain/shop.example', json.dumps({'events': [{'eventAction': 'registration', 'eventDate': now}]}), [])
        with patch('app.fetch', return_value=resource):
            check = app.domain_check('shop.example')
        self.assertEqual(check['status'], 'caution')
        self.assertIn('не доказательство', check['summary'])


class EvidenceScoreTests(unittest.TestCase):
    def test_contact_only_site_has_a_number_without_implying_safety(self):
        checks = [app.finding('contacts', 'Контакты', 'observed', 'Контакты указаны')]
        score = app.score_evidence(checks, 1)
        self.assertIsInstance(score['value'], int)
        self.assertGreater(score['value'], 0)
        self.assertLess(score['value'], 50)
        self.assertIn('не вероятность', score['description'])
        self.assertEqual(score['value'], sum(row['points'] for row in score['breakdown']))

    def test_unavailable_site_or_unsupported_profile_has_no_rating(self):
        checks = [app.finding('domain', 'Домен', 'observed', 'Старый домен')]
        self.assertIsNone(app.score_evidence(checks, 0)['value'])
        checks += [app.finding('contacts', 'Контакты', 'observed', 'Контакты')]
        self.assertIsNone(app.score_evidence(checks + [app.finding('instagram', 'Instagram', 'unknown', '')], 1)['value'])

    def test_https_alone_does_not_generate_a_merchant_rating(self):
        checks = [app.finding('connection', 'Соединение', 'observed', 'HTTPS')]
        self.assertIsNone(app.score_evidence(checks, 1)['value'])

    def test_missing_checks_never_rescale_remaining_facts_to_100(self):
        checks = [app.finding('contacts', 'Контакты', 'observed', '')]
        initial = app.score_evidence(checks, 1)
        checks += [app.finding('reputation', 'Репутация', 'not_connected', '')]
        self.assertEqual(app.score_evidence(checks, 1)['value'], initial['value'])
        self.assertEqual(initial['maximum'], 100)

    def test_all_self_reported_facts_cannot_generate_high_confidence(self):
        keys = ['connection', 'contacts', 'company', 'returns', 'payment', 'domain']
        checks = [app.finding(key, key, 'observed', '') for key in keys]
        score = app.score_evidence(checks, 1)
        self.assertLessEqual(score['value'], 40)
        self.assertEqual(sum(row['maximum'] for row in score['breakdown']), 100)
        self.assertIn('6 из 9', score['coverage'])
        # A placeholder is not an implemented independent verification.
        checks += [app.finding(key, key, 'observed', '') for key in ['registry', 'reputation', 'threats']]
        self.assertEqual(app.score_evidence(checks, 1)['value'], score['value'])

    def test_young_domain_and_failed_source_do_not_earn_positive_points(self):
        checks = [app.finding('contacts', 'Контакты', 'observed', ''), app.finding('domain', 'Домен', 'caution', '')]
        score = app.score_evidence(checks, 1)
        self.assertEqual(next(row for row in score['breakdown'] if row['check_id'] == 'domain')['points'], 0)
        self.assertIn('2 из 9', score['coverage'])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.Server(('127.0.0.1', 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, body=None, headers=None):
        request = urllib.request.Request(self.base + path, data=body, headers=headers or {})
        # Loopback is used only for the local server, never for user-supplied URLs.
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5)

    def test_home_and_health(self):
        with self.request('/') as response:
            self.assertIn(b'StoreLens', response.read())
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        with self.request('/api/health') as response:
            health = json.load(response)
            self.assertEqual(health['status'], 'ok')
            self.assertEqual(health['version'], app.VERSION)

    def test_api_rejects_private_url(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request('/api/check', b'{"url":"http://127.0.0.1"}', {'Content-Type': 'application/json'})
        self.assertEqual(ctx.exception.code, 400)

    def test_api_rejects_cross_origin(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request('/api/check', b'{"url":"example.com"}', {'Content-Type': 'application/json', 'Origin': 'https://evil.example'})
        self.assertEqual(ctx.exception.code, 403)

    def test_unknown_api_is_not_homepage(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request('/api/missing')
        self.assertEqual(ctx.exception.code, 404)

    def test_api_returns_real_analysis_shape_on_source_failure(self):
        with patch('app.fetch', side_effect=app.CheckError('network denied')):
            with self.request('/api/check', b'{"url":"shop.example"}', {'Content-Type': 'application/json'}) as response:
                data = json.load(response)
        self.assertEqual(data['verdict'], 'insufficient')
        self.assertIsNone(data['score']['value'])
        self.assertEqual(data['version'], app.VERSION)
        self.assertGreater(len(data['checks']), 0)


if __name__ == '__main__':
    unittest.main()
