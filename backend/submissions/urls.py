from django.urls import path

from . import views

urlpatterns = [
    path("submissions", views.SubmissionCreateView.as_view(), name="submission-create"),
    path("submissions/<uuid:sid>/apk", views.SubmissionUploadView.as_view(), name="submission-upload"),
    path("submissions/<uuid:sid>", views.DeviceSubmissionView.as_view(), name="submission-device-detail"),
]
