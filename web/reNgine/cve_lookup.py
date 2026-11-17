"""CVE metadata lookup.

Replaces the `pycvesearch` dependency (which imports the removed
`pkg_resources` module and targets the legacy cve.circl.lu response format).

Lookup order:
  1. NVD CVE API 2.0 (set NVD_API_KEY in .env for higher rate limits)
  2. CIRCL Vulnerability-Lookup, which serves CVE JSON 5.x records

Both are normalised to the same dict:
  {id, summary, cvss, cwe, references}
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CIRCL_API_URL = 'https://cve.circl.lu/api/cve/'
TIMEOUT = 15


def _first_english(descriptions):
	for d in descriptions or []:
		if d.get('lang', 'en').startswith('en') and d.get('value'):
			return d['value']
	return ''


def _parse_nvd(data):
	vulns = data.get('vulnerabilities') or []
	if not vulns:
		return None
	cve = vulns[0].get('cve', {})
	cvss = None
	metrics = cve.get('metrics', {})
	for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
		entries = metrics.get(key) or []
		if entries:
			# Prefer the NVD "Primary" score when available
			primary = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
			cvss = primary.get('cvssData', {}).get('baseScore')
			if cvss is not None:
				break
	cwe = ''
	for w in cve.get('weaknesses', []):
		for d in w.get('description', []):
			val = d.get('value', '')
			if val.startswith('CWE-'):
				cwe = val
				break
		if cwe:
			break
	return {
		'id': cve.get('id'),
		'summary': _first_english(cve.get('descriptions')),
		'cvss': cvss,
		'cwe': cwe,
		'references': [r['url'] for r in cve.get('references', []) if r.get('url')],
	}


def _parse_cve5(data):
	meta = data.get('cveMetadata') or {}
	if not meta.get('cveId'):
		return None
	cna = (data.get('containers') or {}).get('cna', {})
	adp = (data.get('containers') or {}).get('adp', [])
	cvss = None
	for container in [cna, *adp]:
		for m in container.get('metrics', []):
			for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
				if key in m and m[key].get('baseScore') is not None:
					cvss = m[key]['baseScore']
					break
			if cvss is not None:
				break
		if cvss is not None:
			break
	cwe = ''
	for pt in cna.get('problemTypes', []):
		for d in pt.get('descriptions', []):
			if d.get('cweId'):
				cwe = d['cweId']
				break
		if cwe:
			break
	return {
		'id': meta['cveId'],
		'summary': _first_english(cna.get('descriptions')),
		'cvss': cvss,
		'cwe': cwe,
		'references': [r['url'] for r in cna.get('references', []) if r.get('url')],
	}


def lookup_cve(cve_id):
	"""Return normalised CVE info dict, or None if not found."""
	cve_id = cve_id.strip().upper()
	headers = {'User-Agent': 'reNgine'}
	nvd_key = os.environ.get('NVD_API_KEY')
	if nvd_key:
		headers['apiKey'] = nvd_key
	try:
		resp = requests.get(NVD_API_URL, params={'cveId': cve_id}, headers=headers, timeout=TIMEOUT)
		if resp.ok:
			info = _parse_nvd(resp.json())
			if info:
				return info
		else:
			logger.warning(f'NVD lookup for {cve_id} returned HTTP {resp.status_code}')
	except (requests.RequestException, ValueError) as e:
		logger.warning(f'NVD lookup for {cve_id} failed: {e}')

	try:
		resp = requests.get(CIRCL_API_URL + cve_id, headers={'User-Agent': 'reNgine'}, timeout=TIMEOUT)
		if resp.ok and resp.content:
			return _parse_cve5(resp.json())
	except (requests.RequestException, ValueError) as e:
		logger.warning(f'CIRCL lookup for {cve_id} failed: {e}')
	return None


def cvss_to_severity(cvss):
	"""Map a CVSS base score to reNgine severity names (CVSS v3 bands)."""
	if cvss is None or cvss < 0:
		return 'unknown'
	if cvss == 0:
		return 'info'
	if cvss < 4:
		return 'low'
	if cvss < 7:
		return 'medium'
	if cvss < 9:
		return 'high'
	return 'critical'
