from django.urls import path

from . import views

urlpatterns = [
    path("remediations/<uuid:rid>/result", views.DeviceRemediationResultView.as_view(), name="remediation-result"),
]
