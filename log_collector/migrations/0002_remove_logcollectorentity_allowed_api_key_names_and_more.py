"""Preserve the original collector schema transition and migration name."""

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_collector', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='logcollectorentity',
            name='allowed_api_key_names',
        ),
        migrations.CreateModel(
            name='LogCollectorApiToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120)),
                ('key_prefix', models.CharField(db_index=True, max_length=16, unique=True)),
                ('key_hash', models.CharField(editable=False, max_length=64, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('allowed_ip_address', models.CharField(blank=True, help_text='Optional caller IP or CIDR range.', max_length=255)),
                ('allowed_origin_domain', models.CharField(blank=True, help_text='Optional Origin or Referer domain allowed to use this token.', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('last_used_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('last_used_origin_domain', models.CharField(blank=True, max_length=255)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_log_collector_api_tokens', to=settings.AUTH_USER_MODEL)),
                ('entity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='api_tokens', to='log_collector.logcollectorentity')),
            ],
            options={
                'ordering': ('-created_at', '-id'),
            },
        ),
        migrations.CreateModel(
            name='LogCollectorApiTokenUsage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token_name', models.CharField(blank=True, max_length=120)),
                ('token_prefix', models.CharField(blank=True, db_index=True, max_length=16)),
                ('path', models.CharField(max_length=500)),
                ('method', models.CharField(blank=True, max_length=12)),
                ('status_code', models.PositiveIntegerField(blank=True, null=True)),
                ('outcome', models.CharField(db_index=True, default='allowed', max_length=32)),
                ('denial_reason', models.CharField(blank=True, db_index=True, max_length=64)),
                ('ip_address', models.GenericIPAddressField(blank=True, db_index=True, null=True)),
                ('request_host', models.CharField(blank=True, max_length=255)),
                ('origin_domain', models.CharField(blank=True, db_index=True, max_length=255)),
                ('user_agent', models.CharField(blank=True, max_length=512)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('entity', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='api_token_usage', to='log_collector.logcollectorentity')),
                ('token', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='usage_logs', to='log_collector.logcollectorapitoken')),
            ],
            options={
                'ordering': ('-created_at', '-id'),
            },
        ),
    ]
