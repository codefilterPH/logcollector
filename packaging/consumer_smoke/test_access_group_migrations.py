from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class AccessGroupMigrationTests(TransactionTestCase):
    def test_fresh_migrate_creates_both_access_groups(self):
        names = set(
            Group.objects.filter(name__in=("DATA_CENTER", "CYBERSECURITY"))
            .values_list("name", flat=True)
        )
        self.assertEqual(names, {"DATA_CENTER", "CYBERSECURITY"})

    def test_migrate_preserves_an_existing_group_and_its_memberships(self):
        executor = MigrationExecutor(connection)
        target = [
            node
            for node in executor.loader.graph.leaf_nodes()
            if node[0] != "log_collector"
        ]
        target.append(("log_collector", "0004_app_appearance"))
        executor.migrate(target)
        user = get_user_model().objects.create_user(username="existing-member")
        group, _ = Group.objects.get_or_create(name="DATA_CENTER")
        user.groups.add(group)
        original_group_id = group.pk

        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())

        group.refresh_from_db()
        user.refresh_from_db()
        self.assertEqual(group.pk, original_group_id)
        self.assertTrue(user.groups.filter(pk=group.pk).exists())
