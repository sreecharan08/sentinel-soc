from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("login/", auth_views.LoginView.as_view(template_name="login.html", redirect_authenticated_user=True),
         name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", views.overview, name="overview"),
    path("submissions/", views.submissions, name="submissions"),
    path("submissions/<uuid:sid>/", views.submission_detail, name="submission"),
    path("devices/", views.devices, name="devices"),
    path("remediation/", views.remediation, name="remediation"),
    path("rules/", views.rules, name="rules"),
    path("rules/<uuid:rid>/", views.rule_detail, name="rule"),
    path("settings/", views.settings_page, name="settings"),
    path("demo/", views.demo, name="demo"),
    path("dev/pipeline/", views.pipeline_console, name="pipeline"),
]
