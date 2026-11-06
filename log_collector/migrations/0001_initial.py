"""Historical collector schema retained for existing and new installations."""

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LogCollectorEntity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('slug', models.SlugField(max_length=120, unique=True)),
                ('entity_type', models.CharField(choices=[('hosting', 'Hosting app'), ('integration', 'Integrated system')], max_length=20)),
                ('is_active', models.BooleanField(default=True)),
                ('api_base_url', models.URLField(blank=True)),
                ('remote_entity_slug', models.SlugField(default='hosting-app', max_length=120)),
                ('remote_api_key', models.CharField(blank=True, max_length=255)),
                ('access_logs_enabled', models.BooleanField(default=True)),
                ('geolocation_enabled', models.BooleanField(default=True)),
                ('user_sessions_enabled', models.BooleanField(default=True)),
                ('enable_api_endpoint', models.BooleanField(default=True)),
                ('allowed_api_key_names', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ('name',),
            },
        ),
        migrations.CreateModel(
            name='LogCollectorAuditEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('api_key_name', models.CharField(blank=True, max_length=255)),
                ('event_type', models.CharField(choices=[('page_view', 'Page view'), ('tab_load', 'Tab load'), ('api_request', 'API request'), ('sync', 'On-demand sync'), ('denied', 'Denied access')], max_length=32)),
                ('path', models.CharField(max_length=500)),
                ('method', models.CharField(blank=True, max_length=12)),
                ('outcome', models.CharField(default='success', max_length=32)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('entity', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='audit_events', to='log_collector.logcollectorentity')),
            ],
            options={
                'ordering': ('-created_at', '-id'),
            },
        ),
        migrations.CreateModel(
            name='LogCollectorSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nginx_access_log_paths', models.JSONField(blank=True, default=list)),
                ('sync_cooldown_seconds', models.PositiveIntegerField(default=5)),
                ('max_lines_per_sync', models.PositiveIntegerField(default=5000)),
                ('retention_days', models.PositiveIntegerField(default=90)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('entity', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='collector_settings', to='log_collector.logcollectorentity')),
            ],
        ),
        migrations.CreateModel(
            name='LogCollectorFileCursor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_path', models.CharField(max_length=500)),
                ('offset', models.BigIntegerField(default=0)),
                ('observed_size', models.BigIntegerField(default=0)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('entity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='log_collector.logcollectorentity')),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('entity', 'source_path'), name='unique_entity_log_cursor')],
            },
        ),
        migrations.CreateModel(
            name='LogCollectorIntegratedDomain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120)),
                ('domain', models.CharField(max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('notes', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('entity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='integrated_domains', to='log_collector.logcollectorentity')),
            ],
            options={
                'ordering': ('domain',),
                'constraints': [models.UniqueConstraint(fields=('entity', 'domain'), name='unique_entity_domain')],
            },
        ),
        migrations.CreateModel(
            name='NginxAccessLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(db_index=True)),
                ('ip_address', models.GenericIPAddressField(db_index=True)),
                ('method', models.CharField(max_length=16)),
                ('path', models.CharField(db_index=True, max_length=2048)),
                ('query_string', models.TextField(blank=True)),
                ('protocol', models.CharField(blank=True, max_length=32)),
                ('status_code', models.PositiveSmallIntegerField(db_index=True)),
                ('bytes_sent', models.BigIntegerField(blank=True, null=True)),
                ('referrer', models.TextField(blank=True)),
                ('user_agent', models.TextField(blank=True)),
                ('source_path', models.CharField(max_length=500)),
                ('raw_line_hash', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('entity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access_logs', to='log_collector.logcollectorentity')),
            ],
            options={
                'ordering': ('-timestamp', '-id'),
                'constraints': [models.UniqueConstraint(fields=('entity', 'source_path', 'raw_line_hash'), name='unique_entity_log_line')],
            },
        ),
    ]
