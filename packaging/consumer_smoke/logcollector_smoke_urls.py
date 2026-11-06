from django.urls import include, path

urlpatterns = [path("log-collector/", include("log_collector.urls"))]
