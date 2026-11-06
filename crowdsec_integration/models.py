from django.db import models


class CrowdSecConnection(models.Model):
    """CrowdSec LAPI credentials for the local Log Collector entity."""

    entity_id = models.PositiveBigIntegerField(unique=True, db_index=True)
    api_url = models.URLField(max_length=500)
    machine_id = models.CharField(max_length=255)
    encrypted_password = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-updated_at",)
