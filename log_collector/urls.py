from django.urls import path

from log_collector import views


app_name = "log_collector"

urlpatterns = [
    path("", views.log_collector_home, name="home"),
    path("entities/", views.entity_selection, name="entity_selection"),
    path("entities/add/", views.entity_create, name="entity_create"),
    path("entities/<slug:slug>/", views.entity_dashboard, name="entity_dashboard"),
    path(
        "entities/<slug:slug>/security-report/",
        views.security_report,
        name="security_report",
    ),
    path("entities/<slug:slug>/manage/", views.entity_manage, name="entity_manage"),
    path("entities/<slug:slug>/delete/", views.entity_delete, name="entity_delete"),
    path("entities/<slug:slug>/domains/<int:domain_id>/delete/", views.domain_delete, name="domain_delete"),
    path("api/entities/", views.EntityCollectionApi.as_view(), name="api_entities"),
    path("api/entities/<slug:slug>/", views.EntityDetailApi.as_view(), name="api_entity_detail"),
    path("api/entities/<slug:slug>/metrics/", views.EntityMetricsApi.as_view(), name="api_metrics"),
    path(
        "api/entities/<slug:slug>/security-summary/",
        views.SecuritySummaryApi.as_view(),
        name="api_security_summary",
    ),
    path("api/entities/<slug:slug>/access-logs/", views.AccessLogsApi.as_view(), name="api_access_logs"),
    path(
        "api/entities/<slug:slug>/security-incidents/",
        views.SecurityIncidentsApi.as_view(),
        name="api_security_incidents",
    ),
    path(
        "api/entities/<slug:slug>/security-incidents/<int:incident_id>/evidence/",
        views.SecurityIncidentEvidenceApi.as_view(),
        name="api_security_incident_evidence",
    ),
    path(
        "api/entities/<slug:slug>/security-blocks/",
        views.SecurityBlockApi.as_view(),
        name="api_security_blocks",
    ),
path(
"api/entities/<slug:slug>/security-white-flags/",
views.SecurityWhiteFlagApi.as_view(),
name="api_security_white_flags",
),
    path(
        "api/entities/<slug:slug>/security-blocks/<int:block_id>/unblock/",
        views.SecurityUnblockApi.as_view(),
        name="api_security_unblock",
    ),
    path("api/entities/<slug:slug>/geolocation/", views.GeolocationApi.as_view(), name="api_geolocation"),
    path("api/entities/<slug:slug>/user-sessions/", views.UserSessionsApi.as_view(), name="api_user_sessions"),
    path("api/entities/<slug:slug>/crowdsec/connection/", views.CrowdSecConnectionApi.as_view(), name="api_crowdsec_connection"),
    path("api/entities/<slug:slug>/crowdsec/alerts/", views.CrowdSecAlertsApi.as_view(), name="api_crowdsec_alerts"),
    path("api/entities/<slug:slug>/crowdsec/decisions/", views.CrowdSecDecisionsApi.as_view(), name="api_crowdsec_decisions"),
path(
    "api/entities/<slug:slug>/user-sessions/<int:session_id>/contain/",
    views.UserSessionContainApi.as_view(),
    name="api_user_session_contain",
),
    path("api/entities/<slug:slug>/endpoints/", views.EndpointsApi.as_view(), name="api_endpoints"),
    path("api/entities/<slug:slug>/audit-events/", views.AuditEventsApi.as_view(), name="api_audit_events"),
]
