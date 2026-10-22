from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path


def healthz(request):
    from pipeline.health import health_report

    report = health_report()
    return JsonResponse(report, status=200 if report["ok"] else 503)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("healthz", healthz),
    path("api/v1/", include("devices.urls")),
    path("api/v1/", include("submissions.urls")),
    path("api/v1/", include("remediation.urls")),
    path("api/v1/auth/", include("dashboard.auth_urls")),
    path("api/v1/dash/", include("dashboard.api_urls")),
    path("", include("dashboard.urls")),
]
