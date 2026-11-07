"""Shared authorization helpers for LOG Collector's dashboard access."""

DASHBOARD_ACCESS_GROUPS = ("DATA_CENTER", "CYBERSECURITY")


def has_dashboard_access(user):
    return (
        getattr(user, "is_authenticated", False)
        and user.groups.filter(name__in=DASHBOARD_ACCESS_GROUPS).exists()
    )
