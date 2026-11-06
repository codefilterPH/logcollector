"""The deliberately small, credential-free security stream wire contract."""


def security_group_name(entity_id):
    # Database IDs, never user-provided slugs, form Channels-safe group keys.
    if type(entity_id) is not int or entity_id < 1:
        raise ValueError("A persisted entity ID is required")
    return f"log_collector_security_{entity_id}"


def sanitize_security_event(entity_id, event_type, payload):
    if event_type not in ("incident.created", "incident.updated", "block.state_changed"):
        return None
    security_group_name(entity_id)
    event = {"type": event_type, "entity_id": entity_id}
    fields = {"incident_id": lambda value: value is None or type(value) is int and value > 0}
    if event_type.startswith("incident."):
        fields.update({
            "category": lambda value: value in ("malicious", "unauthorized"),
            "severity": lambda value: value in ("low", "medium", "high", "critical"),
            "request_count": lambda value: type(value) is int and value >= 0,
        })
    else:
        fields.update({
            "block_id": lambda value: type(value) is int and value > 0,
            "desired_active": lambda value: type(value) is bool,
            "django_state": lambda value: value in ("active", "inactive"),
            "nginx_state": lambda value: value in (
                "not_configured", "pending", "applied", "failed", "removed", "remove_failed"),
        })
    for field, valid in fields.items():
        value = payload.get(field)
        if field in payload and valid(value):
            event[field] = value
    return event
