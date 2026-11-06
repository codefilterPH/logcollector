"""Add administrator-controlled collector appearance settings."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("log_collector", "0003_blockedipaddress_securityincident_ipblockauditevent_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="logcollectorsettings",
            name="display_name",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="logcollectorsettings",
            name="theme",
            field=models.CharField(
                choices=[
                    ("light", "Light"),
                    ("dark", "Dark"),
                    ("green", "Green Log"),
                    ("command-center", "Command Center"),
                ],
                default="light",
                max_length=20,
            ),
        ),
    ]
