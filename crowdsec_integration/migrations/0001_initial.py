"""Initial CrowdSec connection schema for standalone installations."""

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="CrowdSecConnection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("entity_id", models.PositiveBigIntegerField(db_index=True, unique=True)),
                ("api_url", models.URLField(max_length=500)),
                ("machine_id", models.CharField(max_length=255)),
                ("encrypted_password", models.TextField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("-updated_at",)},
        ),
    ]
