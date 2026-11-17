from django.db import migrations, models


def set_provider_from_use_ollama(apps, schema_editor):
	OllamaSettings = apps.get_model('dashboard', 'OllamaSettings')
	for s in OllamaSettings.objects.all():
		s.provider = 'ollama' if s.use_ollama else 'openai'
		s.save(update_fields=['provider'])


class Migration(migrations.Migration):

	dependencies = [
		('dashboard', '0002_chaosapikey_hackeroneapikey_inappnotification_userpreferences'),
	]

	operations = [
		migrations.CreateModel(
			name='AnthropicAPIKey',
			fields=[
				('id', models.AutoField(primary_key=True, serialize=False)),
				('key', models.CharField(max_length=500)),
			],
		),
		migrations.AddField(
			model_name='ollamasettings',
			name='provider',
			field=models.CharField(
				choices=[('openai', 'OpenAI / OpenAI-compatible'), ('anthropic', 'Anthropic Claude'), ('ollama', 'Ollama (local)')],
				default='ollama', max_length=20),
		),
		migrations.RunPython(set_provider_from_use_ollama, migrations.RunPython.noop),
	]
