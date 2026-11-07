from django.db import migrations


def create_access_groups(apps, schema_editor):
    group_model = apps.get_model("auth", "Group")
    groups = group_model.objects.using(schema_editor.connection.alias)
    for name in ("DATA_CENTER", "CYBERSECURITY"):
        groups.get_or_create(name=name)


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("log_collector", "0004_app_appearance"),
    ]

    operations = [
        migrations.RunPython(create_access_groups, migrations.RunPython.noop),
    ]
