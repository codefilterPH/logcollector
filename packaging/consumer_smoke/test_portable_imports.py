"""The published Django apps must import without the host project."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PortableImportTests(unittest.TestCase):
    def test_django_app_imports_without_host_modules(self):
        with tempfile.TemporaryDirectory(prefix="logcollector-consumer-") as directory:
            consumer_root = Path(directory)
            for package in ("log_collector", "crowdsec_integration"):
                shutil.copytree(
                    PROJECT_ROOT / package,
                    consumer_root / package,
                    ignore=shutil.ignore_patterns("__pycache__", "tests"),
                )
            script = """
from django.conf import settings
settings.configure(
    SECRET_KEY='consumer-smoke-key',
    INSTALLED_APPS=[
        'django.contrib.auth', 'django.contrib.contenttypes',
        'django.contrib.sessions', 'rest_framework', 'channels',
        'crowdsec_integration', 'log_collector',
    ],
    DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    ROOT_URLCONF='log_collector.urls',
)
import django
django.setup()
import log_collector.urls
import log_collector.tasks
import log_collector.routing
print('portable imports ok')
"""
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(consumer_root)
            process = subprocess.run(
                [sys.executable, "-c", script],
                cwd=consumer_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("portable imports ok", process.stdout)


if __name__ == "__main__":
    unittest.main()
