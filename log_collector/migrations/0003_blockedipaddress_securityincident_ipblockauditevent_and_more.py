"""Preserve security incident and blocking schema for existing databases."""

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_collector', '0002_remove_logcollectorentity_allowed_api_key_names_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BlockedIPAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField()),
                ('origin', models.CharField(choices=[('manual', 'Manual'), ('automatic', 'Automatic')], max_length=16)),
                ('reason', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('desired_active', models.BooleanField(default=True)),
                ('django_state', models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active', max_length=16)),
                ('nginx_state', models.CharField(choices=[('not_configured', 'Not configured'), ('pending', 'Pending'), ('applied', 'Applied'), ('failed', 'Failed'), ('removed', 'Removed'), ('remove_failed', 'Removal failed')], default='not_configured', max_length=16)),
                ('last_error', models.TextField(blank=True)),
                ('blocked_request_count', models.PositiveBigIntegerField(default=0)),
                ('last_blocked_at', models.DateTimeField(blank=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_ip_blocks', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created_at', '-id'),
            },
        ),
        migrations.CreateModel(
            name='SecurityIncident',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category', models.CharField(choices=[('unauthorized', 'Unauthorized'), ('malicious', 'Malicious')], max_length=16)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], max_length=16)),
                ('confidence_score', models.FloatField()),
                ('source_ip', models.GenericIPAddressField()),
                ('rule_code', models.CharField(max_length=64)),
                ('target_family', models.CharField(max_length=255)),
                ('fingerprint', models.CharField(max_length=64)),
                ('first_seen_at', models.DateTimeField()),
                ('last_seen_at', models.DateTimeField()),
                ('request_count', models.PositiveBigIntegerField(default=0)),
                ('latest_evidence', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('entity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='security_incidents', to='log_collector.logcollectorentity')),
            ],
            options={
                'ordering': ('-last_seen_at', '-id'),
            },
        ),
        migrations.CreateModel(
            name='IPBlockAuditEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[('requested', 'Requested'), ('applied', 'Applied'), ('failed', 'Failed'), ('expired', 'Expired'), ('unblocked', 'Unblocked')], max_length=32)),
                ('previous_django_state', models.CharField(blank=True, choices=[('active', 'Active'), ('inactive', 'Inactive')], max_length=16)),
                ('new_django_state', models.CharField(blank=True, choices=[('active', 'Active'), ('inactive', 'Inactive')], max_length=16)),
                ('previous_nginx_state', models.CharField(blank=True, choices=[('not_configured', 'Not configured'), ('pending', 'Pending'), ('applied', 'Applied'), ('failed', 'Failed'), ('removed', 'Removed'), ('remove_failed', 'Removal failed')], max_length=16)),
                ('new_nginx_state', models.CharField(blank=True, choices=[('not_configured', 'Not configured'), ('pending', 'Pending'), ('applied', 'Applied'), ('failed', 'Failed'), ('removed', 'Removed'), ('remove_failed', 'Removal failed')], max_length=16)),
                ('reason', models.TextField(blank=True)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ip_block_audit_events', to=settings.AUTH_USER_MODEL)),
                ('block', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='audit_events', to='log_collector.blockedipaddress')),
                ('incident', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='block_audit_events', to='log_collector.securityincident')),
            ],
            options={
                'ordering': ('-timestamp', '-id'),
            },
        ),
        migrations.AddField(
            model_name='blockedipaddress',
            name='incident',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ip_blocks', to='log_collector.securityincident'),
        ),
        migrations.CreateModel(
            name='SecurityIncidentEvidence',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('observed_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('reason', models.TextField(blank=True)),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('access_log', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='security_evidence', to='log_collector.nginxaccesslog')),
                ('incident', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='evidence', to='log_collector.securityincident')),
                ('token_usage', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='security_evidence', to='log_collector.logcollectorapitokenusage')),
            ],
            options={
                'ordering': ('observed_at', 'id'),
            },
        ),
        migrations.CreateModel(
            name='SecurityIncidentSMSAlert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('dispatching', 'Dispatching'), ('sent', 'Sent'), ('partial', 'Partially sent'), ('failed', 'Failed'), ('no_recipients', 'No recipients')], default='pending', max_length=20)),
                ('dispatch_queued_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('incident', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='sms_alert', to='log_collector.securityincident')),
            ],
        ),
        migrations.CreateModel(
            name='SecurityIncidentSMSDelivery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(max_length=20)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('sending', 'Sending'), ('sent', 'Sent'), ('failed', 'Failed')], default='pending', max_length=16)),
                ('last_error', models.TextField(blank=True)),
                ('sent_at', models.DateTimeField(blank=True, null=True)),
                ('alert', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='deliveries', to='log_collector.securityincidentsmsalert')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddIndex(
            model_name='securityincident',
            index=models.Index(fields=['entity', 'category', '-last_seen_at'], name='sec_inc_entity_cat_seen_idx'),
        ),
        migrations.AddIndex(
            model_name='securityincident',
            index=models.Index(fields=['entity', 'severity', '-last_seen_at'], name='sec_inc_entity_sev_seen_idx'),
        ),
        migrations.AddIndex(
            model_name='securityincident',
            index=models.Index(fields=['source_ip', '-last_seen_at'], name='sec_inc_ip_seen_idx'),
        ),
        migrations.AddIndex(
            model_name='securityincident',
            index=models.Index(fields=['fingerprint', '-last_seen_at'], name='sec_inc_fingerprint_seen_idx'),
        ),
        migrations.AddIndex(
            model_name='blockedipaddress',
            index=models.Index(fields=['desired_active', 'expires_at'], name='ip_block_active_expiry_idx'),
        ),
        migrations.AddIndex(
            model_name='blockedipaddress',
            index=models.Index(fields=['ip_address', 'desired_active'], name='ip_block_ip_active_idx'),
        ),
        migrations.AddConstraint(
            model_name='blockedipaddress',
            constraint=models.UniqueConstraint(condition=models.Q(('desired_active', True)), fields=('ip_address',), name='unique_active_blocked_ip_address'),
        ),
        migrations.AddConstraint(
            model_name='securityincidentevidence',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('access_log__isnull', False), ('token_usage__isnull', True)), models.Q(('access_log__isnull', True), ('token_usage__isnull', False)), _connector='OR'), name='security_evidence_exactly_one_source'),
        ),
        migrations.AddConstraint(
            model_name='securityincidentevidence',
            constraint=models.UniqueConstraint(condition=models.Q(('access_log__isnull', False)), fields=('access_log',), name='unique_security_evidence_access_log'),
        ),
        migrations.AddConstraint(
            model_name='securityincidentevidence',
            constraint=models.UniqueConstraint(condition=models.Q(('token_usage__isnull', False)), fields=('token_usage',), name='unique_security_evidence_token_usage'),
        ),
        migrations.AddConstraint(
            model_name='securityincidentsmsdelivery',
            constraint=models.UniqueConstraint(fields=('alert', 'user'), name='unique_security_sms_alert_user'),
        ),
    ]
