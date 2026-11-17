"""Offline tests for the 2026 modernization (Django 5.2, LLM providers, CVE lookup).

Run with:  python manage.py test tests.test_modernization
"""
import logging
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from dashboard.models import AnthropicAPIKey, OllamaSettings, OpenAiAPIKey, Project
from reNgine import cve_lookup
from reNgine.llm import (LLMAttackSuggestionGenerator, LLMClient, LLMError,
                         LLMVulnerabilityReportGenerator, get_llm_selection)

logger = logging.getLogger('test')

VULN_REPORT = """
### Vulnerability Description
Reflected XSS in search parameter.

### Impact
Session hijacking.

### Remediation
Encode output.

### References
- https://owasp.org/www-community/attacks/xss/
"""


class LLMSelectionTests(TestCase):

	def test_default_selection(self):
		provider, model = get_llm_selection()
		self.assertEqual(provider, 'openai')
		self.assertTrue(model)

	def test_legacy_rows_without_provider(self):
		OllamaSettings.objects.create(id=1, selected_model='llama3', use_ollama=True, provider='')
		self.assertEqual(get_llm_selection(), ('ollama', 'llama3'))


class LLMProviderTests(TestCase):

	def test_openai_requires_key(self):
		client = LLMClient(provider='openai', model='gpt-5.4-mini')
		with mock.patch('reNgine.llm.OPENAI_BASE_URL', None):
			with self.assertRaises(LLMError):
				client.complete('sys', 'user')

	def test_openai_call(self):
		OpenAiAPIKey.objects.create(key='sk-test')
		fake = mock.MagicMock()
		fake.chat.completions.create.return_value = SimpleNamespace(
			choices=[SimpleNamespace(message=SimpleNamespace(content='hello'))])
		with mock.patch('openai.OpenAI', return_value=fake) as ctor:
			out = LLMClient(provider='openai', model='gpt-5.4-mini').complete('\tsys', 'user')
		self.assertEqual(out, 'hello')
		self.assertEqual(ctor.call_args.kwargs['api_key'], 'sk-test')
		kwargs = fake.chat.completions.create.call_args.kwargs
		self.assertEqual(kwargs['model'], 'gpt-5.4-mini')
		self.assertEqual(kwargs['messages'][0], {'role': 'system', 'content': 'sys'})

	def test_anthropic_requires_key(self):
		with self.assertRaises(LLMError):
			LLMClient(provider='anthropic', model='claude-sonnet-5-5').complete('s', 'u')

	def test_anthropic_call(self):
		AnthropicAPIKey.objects.create(key='sk-ant-test')
		fake = mock.MagicMock()
		fake.messages.create.return_value = SimpleNamespace(content=[
			SimpleNamespace(type='thinking', thinking='...'),
			SimpleNamespace(type='text', text='claude says hi'),
		])
		with mock.patch('anthropic.Anthropic', return_value=fake):
			out = LLMClient(provider='anthropic', model='claude-sonnet-5-5').complete('sys', 'user')
		self.assertEqual(out, 'claude says hi')
		kwargs = fake.messages.create.call_args.kwargs
		self.assertEqual(kwargs['system'], 'sys')
		self.assertEqual(kwargs['model'], 'claude-sonnet-5-5')
		self.assertIn('max_tokens', kwargs)

	def test_ollama_call(self):
		fake = mock.MagicMock()
		fake.chat.return_value = SimpleNamespace(message=SimpleNamespace(content='local reply'))
		with mock.patch('ollama.Client', return_value=fake):
			out = LLMClient(provider='ollama', model='llama3.1').complete('sys', 'user')
		self.assertEqual(out, 'local reply')

	def test_sdk_exception_is_wrapped(self):
		AnthropicAPIKey.objects.create(key='k')
		fake = mock.MagicMock()
		fake.messages.create.side_effect = RuntimeError('boom')
		with mock.patch('anthropic.Anthropic', return_value=fake):
			with self.assertRaisesRegex(LLMError, 'boom'):
				LLMClient(provider='anthropic', model='claude-haiku-5-5').complete('s', 'u')


class LLMGeneratorTests(TestCase):

	def setUp(self):
		OllamaSettings.objects.create(id=1, selected_model='claude-sonnet-5-5', provider='anthropic', use_ollama=False)

	def test_vulnerability_report_parsed(self):
		with mock.patch.object(LLMClient, 'complete', return_value=VULN_REPORT):
			res = LLMVulnerabilityReportGenerator(logger).get_vulnerability_description('XSS on /search')
		self.assertTrue(res['status'])
		self.assertIn('XSS', res['description'])
		self.assertIn('Encode', res['remediation'])

	def test_error_is_returned_not_raised(self):
		with mock.patch.object(LLMClient, 'complete', side_effect=LLMError('no key')):
			res = LLMAttackSuggestionGenerator(logger).get_attack_suggestion('x')
		self.assertFalse(res['status'])
		self.assertEqual(res['error'], 'no key')


NVD_SAMPLE = {
	'vulnerabilities': [{'cve': {
		'id': 'CVE-2021-44228',
		'descriptions': [{'lang': 'es', 'value': 'nope'}, {'lang': 'en', 'value': 'Apache Log4j2 JNDI RCE'}],
		'metrics': {'cvssMetricV31': [
			{'type': 'Secondary', 'cvssData': {'baseScore': 9.0}},
			{'type': 'Primary', 'cvssData': {'baseScore': 10.0}},
		]},
		'weaknesses': [{'description': [{'lang': 'en', 'value': 'CWE-917'}]}],
		'references': [{'url': 'https://logging.apache.org/log4j/2.x/security.html'}],
	}}]
}

CVE5_SAMPLE = {
	'cveMetadata': {'cveId': 'CVE-2024-3094'},
	'containers': {'cna': {
		'descriptions': [{'lang': 'en', 'value': 'xz backdoor'}],
		'metrics': [{'cvssV3_1': {'baseScore': 10.0}}],
		'problemTypes': [{'descriptions': [{'cweId': 'CWE-506'}]}],
		'references': [{'url': 'https://example.com'}],
	}},
}


class CVELookupTests(TestCase):

	def test_parse_nvd(self):
		info = cve_lookup._parse_nvd(NVD_SAMPLE)
		self.assertEqual(info['id'], 'CVE-2021-44228')
		self.assertEqual(info['summary'], 'Apache Log4j2 JNDI RCE')
		self.assertEqual(info['cvss'], 10.0)
		self.assertEqual(info['cwe'], 'CWE-917')

	def test_parse_cve5(self):
		info = cve_lookup._parse_cve5(CVE5_SAMPLE)
		self.assertEqual(info['cvss'], 10.0)
		self.assertEqual(info['cwe'], 'CWE-506')

	def test_parse_empty(self):
		self.assertIsNone(cve_lookup._parse_nvd({'vulnerabilities': []}))
		self.assertIsNone(cve_lookup._parse_cve5({}))

	def test_severity_bands(self):
		f = cve_lookup.cvss_to_severity
		self.assertEqual([f(None), f(-1), f(0), f(3.9), f(4), f(7), f(9.8)],
						 ['unknown', 'unknown', 'info', 'low', 'medium', 'high', 'critical'])

	def test_cve_to_vuln(self):
		from reNgine.tasks import cve_to_vuln
		with mock.patch('reNgine.tasks.lookup_cve', return_value=cve_lookup._parse_nvd(NVD_SAMPLE)):
			vuln = cve_to_vuln('CVE-2021-44228', vuln_type='nmap-vulners-nse')
		self.assertEqual(vuln['severity'], 4)
		self.assertEqual(vuln['cwe_ids'], ['CWE-917'])
		self.assertEqual(vuln['type'], 'nmap-vulners-nse')

	def test_lookup_falls_back_to_circl(self):
		nvd = mock.Mock(ok=False, status_code=503)
		circl = mock.Mock(ok=True, content=b'x')
		circl.json.return_value = CVE5_SAMPLE
		with mock.patch('reNgine.cve_lookup.requests.get', side_effect=[nvd, circl]):
			info = cve_lookup.lookup_cve('cve-2024-3094')
		self.assertEqual(info['id'], 'CVE-2024-3094')


class PortServiceTests(TestCase):

	def test_nmap_services_lookup(self):
		import tempfile
		from reNgine import common_func
		content = (
			'# comment\n'
			'http\t80/tcp\t0.484143\t# World Wide Web HTTP\n'
			'http\t80/udp\t0.035767\t# World Wide Web HTTP\n'
			'unknown\t81/tcp\t0.01\n'
			'ms-wbt-server\t3389/tcp\t0.083904\t# Microsoft Remote Display Protocol\n'
		)
		with tempfile.NamedTemporaryFile('w', delete=False) as f:
			f.write(content)
		common_func._load_nmap_services.cache_clear()
		try:
			with mock.patch.object(common_func, 'NMAP_SERVICES_FILE', f.name):
				self.assertEqual(common_func.get_port_service_description(3389)['service_name'], 'ms-wbt-server')
				self.assertEqual(common_func.get_port_service_description('80')['description'], 'World Wide Web HTTP')
				self.assertEqual(common_func.get_port_service_description('abc'), {'service_name': '', 'description': ''})
		finally:
			common_func._load_nmap_services.cache_clear()


class WebUITests(TestCase):

	def setUp(self):
		self.user = User.objects.create_superuser('admin', 'a@example.com', 'pw')
		self.project = Project.objects.create(name='Default', slug='default', insert_date='2026-01-01T00:00:00Z')
		self.client.force_login(self.user)

	def test_logout_requires_post(self):
		self.assertEqual(self.client.get('/logout/').status_code, 405)
		resp = self.client.post('/logout/')
		self.assertIn(resp.status_code, (200, 302))

	def test_llm_toolkit_renders_without_ollama(self):
		with mock.patch('reNgine.llm.list_ollama_models', return_value=[]):
			resp = self.client.get('/scanEngine/default/llm_toolkit')
		self.assertEqual(resp.status_code, 200)
		self.assertContains(resp, 'claude-sonnet-5-5')
		self.assertContains(resp, 'is not reachable')

	def test_api_vault_saves_anthropic_key(self):
		resp = self.client.post('/scanEngine/default/api_vault', {'key_anthropic': 'sk-ant-xyz'})
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(AnthropicAPIKey.objects.get().key, 'sk-ant-xyz')

	def test_select_model_api(self):
		resp = self.client.put('/api/tool/ollama/?model=claude-opus-5-5&provider=anthropic')
		self.assertTrue(resp.json()['status'])
		s = OllamaSettings.objects.get()
		self.assertEqual((s.provider, s.use_ollama), ('anthropic', False))

	def test_select_model_api_infers_provider(self):
		self.client.put('/api/tool/ollama/?model=llama3.1:8b')
		self.assertEqual(OllamaSettings.objects.get().provider, 'ollama')
		self.client.put('/api/tool/ollama/?model=gpt-5.5')
		self.assertEqual(OllamaSettings.objects.get().provider, 'openai')

	def test_swagger_schema(self):
		resp = self.client.get('/swagger.json')
		self.assertEqual(resp.status_code, 200)


class ValidatorsCompatTests(TestCase):

	def test_legacy_semantics(self):
		from reNgine import validators_compat as v
		self.assertTrue(v.ipv4('10.0.0.1'))
		self.assertFalse(v.ipv4('10.0.0.0/24'))
		self.assertTrue(v.ipv4_cidr('10.0.0.0/24'))
		self.assertFalse(v.ipv4_cidr('10.0.0.1'))
		self.assertTrue(v.ipv6('::1'))
		self.assertTrue(v.ipv6_cidr('2001:db8::/32'))
		self.assertTrue(v.domain('my_host.example.com'))
		self.assertTrue(v.domain('_dmarc.example.com'))
		self.assertFalse(v.domain('not a domain'))
		self.assertTrue(v.url('http://localhost:8000/x'))
		self.assertTrue(v.url('https://a.example.com/?q=1'))
		self.assertFalse(v.url('example.com'))


class LLMVulnerabilityTaskTests(TestCase):

	def _vuln(self):
		from django.utils import timezone
		from startScan.models import ScanHistory, Subdomain, Vulnerability
		from targetApp.models import Domain
		project = Project.objects.create(name='P', slug='p', insert_date=timezone.now())
		domain = Domain.objects.create(name='example.com', project=project, insert_date=timezone.now())
		from scanEngine.models import EngineType
		engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		sub = Subdomain.objects.create(name='www.example.com', scan_history=scan, target_domain=domain)
		return Vulnerability.objects.create(
			name='Reflected XSS', severity=3, scan_history=scan, target_domain=domain, subdomain=sub,
			http_url='https://www.example.com/search?q=1', description='original', discovered_date=timezone.now())

	def test_success_updates_vulnerability(self):
		from reNgine.tasks import llm_vulnerability_description
		vuln = self._vuln()
		with mock.patch.object(LLMClient, 'complete', return_value=VULN_REPORT):
			res = llm_vulnerability_description(vuln.id)
		self.assertTrue(res['status'])
		vuln.refresh_from_db()
		self.assertTrue(vuln.is_gpt_used)
		self.assertIn('Encode', vuln.remediation)

	def test_failure_leaves_vulnerability_untouched(self):
		from startScan.models import GPTVulnerabilityReport
		from reNgine.tasks import llm_vulnerability_description
		vuln = self._vuln()
		with mock.patch.object(LLMClient, 'complete', side_effect=LLMError('rate limited')):
			res = llm_vulnerability_description(vuln.id)
		self.assertFalse(res['status'])
		vuln.refresh_from_db()
		self.assertEqual(vuln.description, 'original')
		self.assertFalse(vuln.is_gpt_used)
		self.assertFalse(GPTVulnerabilityReport.objects.exists())


class CommandBuilderTests(TestCase):

	def test_no_glued_header_flags(self):
		"""Custom headers used to be appended without a separating space."""
		import inspect
		import reNgine.tasks as t
		src = inspect.getsource(t)
		self.assertNotIn('cmd += formatted_headers', src)
		self.assertNotIn("' -fr' if follow_redirect", src)
