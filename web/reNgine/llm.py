"""LLM integration for reNgine.

Supports three providers behind one interface:
  * openai     - OpenAI API (SDK v1+), or any OpenAI-compatible endpoint via OPENAI_BASE_URL
  * anthropic  - Anthropic Claude Messages API
  * ollama     - local models served by Ollama (OLLAMA_INSTANCE)

The selected provider/model is stored in dashboard.OllamaSettings.
"""
import re

from dashboard.models import OllamaSettings
from reNgine.common_func import get_anthropic_key, get_open_ai_key, parse_llm_vulnerability_report
from reNgine.definitions import (
	ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT,
	DEFAULT_LLM_MODEL,
	DEFAULT_LLM_PROVIDER,
	LLM_MAX_OUTPUT_TOKENS,
	LLM_PROVIDER_ANTHROPIC,
	LLM_PROVIDER_OLLAMA,
	LLM_PROVIDER_OPENAI,
	LLM_REQUEST_TIMEOUT,
	OLLAMA_INSTANCE,
	OPENAI_BASE_URL,
	VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE,
)


class LLMError(Exception):
	pass


def get_llm_selection():
	"""Return (provider, model) currently selected in the LLM Toolkit."""
	settings = OllamaSettings.objects.first()
	if not settings or not settings.selected_model:
		return DEFAULT_LLM_PROVIDER, DEFAULT_LLM_MODEL
	provider = getattr(settings, 'provider', None)
	if not provider:
		provider = LLM_PROVIDER_OLLAMA if settings.use_ollama else LLM_PROVIDER_OPENAI
	return provider, settings.selected_model


def _key_value(key_obj):
	return key_obj.key if key_obj else None


class LLMClient:
	"""Thin provider-agnostic chat completion wrapper."""

	def __init__(self, provider=None, model=None, logger=None):
		sel_provider, sel_model = get_llm_selection()
		self.provider = provider or sel_provider
		self.model = model or sel_model
		self.logger = logger

	def _log(self, msg):
		if self.logger:
			self.logger.info(msg)

	def complete(self, system_prompt, user_prompt):
		"""Return the model's text reply. Raises LLMError on failure."""
		system_prompt = re.sub(r'\t', '', system_prompt)
		self._log(f'LLM request via {self.provider} ({self.model})')
		try:
			if self.provider == LLM_PROVIDER_OLLAMA:
				return self._ollama(system_prompt, user_prompt)
			if self.provider == LLM_PROVIDER_ANTHROPIC:
				return self._anthropic(system_prompt, user_prompt)
			return self._openai(system_prompt, user_prompt)
		except LLMError:
			raise
		except Exception as e:
			raise LLMError(f'{self.provider} request failed: {e}') from e

	def _openai(self, system_prompt, user_prompt):
		from openai import OpenAI
		api_key = _key_value(get_open_ai_key())
		if not api_key and not OPENAI_BASE_URL:
			raise LLMError('OpenAI API Key not set. Add it in Settings > API Vault.')
		client = OpenAI(
			api_key=api_key or 'not-needed',
			base_url=OPENAI_BASE_URL,
			timeout=LLM_REQUEST_TIMEOUT,
		)
		resp = client.chat.completions.create(
			model=self.model,
			messages=[
				{'role': 'system', 'content': system_prompt},
				{'role': 'user', 'content': user_prompt},
			],
		)
		content = resp.choices[0].message.content if resp.choices else None
		if not content:
			raise LLMError('OpenAI returned an empty response')
		return content

	def _anthropic(self, system_prompt, user_prompt):
		import anthropic
		api_key = _key_value(get_anthropic_key())
		if not api_key:
			raise LLMError('Anthropic API Key not set. Add it in Settings > API Vault.')
		client = anthropic.Anthropic(api_key=api_key, timeout=LLM_REQUEST_TIMEOUT)
		resp = client.messages.create(
			model=self.model,
			max_tokens=LLM_MAX_OUTPUT_TOKENS,
			system=system_prompt,
			messages=[{'role': 'user', 'content': user_prompt}],
		)
		text = ''.join(
			block.text for block in resp.content if getattr(block, 'type', '') == 'text'
		)
		if not text:
			raise LLMError('Anthropic returned an empty response')
		return text

	def _ollama(self, system_prompt, user_prompt):
		import ollama
		client = ollama.Client(host=OLLAMA_INSTANCE, timeout=LLM_REQUEST_TIMEOUT)
		resp = client.chat(
			model=self.model,
			messages=[
				{'role': 'system', 'content': system_prompt},
				{'role': 'user', 'content': user_prompt},
			],
		)
		content = resp.message.content if resp and resp.message else None
		if not content:
			raise LLMError('Ollama returned an empty response')
		return content


class LLMVulnerabilityReportGenerator:

	def __init__(self, logger):
		self.logger = logger
		self.client = LLMClient(logger=logger)
		# kept for backwards compatibility with callers/templates
		self.model_name = self.client.model
		self.use_ollama = self.client.provider == LLM_PROVIDER_OLLAMA

	def get_vulnerability_description(self, description):
		"""Generate a vulnerability description using the selected LLM.

		Returns:
			dict: {status, description, impact, remediation, references} or {status: False, error}
		"""
		self.logger.info(f'Generating Vulnerability Description for: {description}')
		try:
			content = self.client.complete(VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, description)
		except LLMError as e:
			return {'status': False, 'error': str(e)}

		response = parse_llm_vulnerability_report(content)
		if not response:
			return {'status': False, 'error': 'Failed to parse LLM response'}

		return {
			'status': True,
			'description': response.get('description', ''),
			'impact': response.get('impact', ''),
			'remediation': response.get('remediation', ''),
			'references': response.get('references', []),
		}


class LLMAttackSuggestionGenerator:

	def __init__(self, logger):
		self.logger = logger
		self.client = LLMClient(logger=logger)
		self.model_name = self.client.model
		self.use_ollama = self.client.provider == LLM_PROVIDER_OLLAMA

	def get_attack_suggestion(self, user_input):
		try:
			content = self.client.complete(ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, user_input)
		except LLMError as e:
			return {'status': False, 'error': str(e), 'input': user_input}
		return {'status': True, 'description': content, 'input': user_input}


# ---------------------------------------------------------------------------
# Model discovery for the LLM Toolkit page
# ---------------------------------------------------------------------------

def list_ollama_models():
	"""Return locally installed Ollama models, or [] if Ollama is unreachable."""
	import ollama
	from datetime import datetime
	try:
		resp = ollama.Client(host=OLLAMA_INSTANCE, timeout=5).list()
	except Exception:
		return []
	models = []
	for m in resp.models or []:
		details = m.details
		modified = m.modified_at
		if isinstance(modified, str):
			try:
				modified = datetime.fromisoformat(modified)
			except ValueError:
				modified = None
		models.append({
			'name': m.model,
			'model': m.model,
			'modified_at': modified,
			'is_local': True,
			'provider': LLM_PROVIDER_OLLAMA,
			'details': {
				'family': getattr(details, 'family', '') or '',
				'parameter_size': getattr(details, 'parameter_size', '') or '',
			},
		})
	return models


def list_openai_models():
	"""Live chat-capable model list from the OpenAI API (empty on failure)."""
	api_key = _key_value(get_open_ai_key())
	if not api_key and not OPENAI_BASE_URL:
		return []
	try:
		from openai import OpenAI
		client = OpenAI(api_key=api_key or 'not-needed', base_url=OPENAI_BASE_URL, timeout=10)
		ids = sorted((m.id for m in client.models.list()), reverse=True)
	except Exception:
		return []
	if not OPENAI_BASE_URL:
		# api.openai.com also lists embeddings, audio, image models etc.
		skip = ('embedding', 'whisper', 'tts', 'dall-e', 'audio', 'realtime', 'image', 'moderation', 'transcribe', 'search')
		ids = [i for i in ids if (i.startswith('gpt-') or re.match(r'^o\d', i)) and not any(s in i for s in skip)]
	family = 'OpenAI-compatible' if OPENAI_BASE_URL else 'GPT'
	return [{
		'name': i, 'model': i, 'modified_at': '', 'provider': LLM_PROVIDER_OPENAI,
		'details': {'family': family, 'parameter_size': 'N/A'},
	} for i in ids]


def list_anthropic_models():
	"""Live model list from the Anthropic API (empty on failure)."""
	api_key = _key_value(get_anthropic_key())
	if not api_key:
		return []
	try:
		import anthropic
		client = anthropic.Anthropic(api_key=api_key, timeout=10)
		models = list(client.models.list(limit=100))
	except Exception:
		return []
	return [{
		'name': m.id, 'model': m.id, 'modified_at': getattr(m, 'created_at', '') or '',
		'provider': LLM_PROVIDER_ANTHROPIC,
		'display_name': getattr(m, 'display_name', m.id),
		'details': {'family': 'Claude', 'parameter_size': 'N/A'},
	} for m in models]
