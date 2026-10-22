from django.urls import path

from realtime.consumers import DashboardConsumer, DeviceConsumer, SubmissionConsumer

websocket_urlpatterns = [
    path("ws/dashboard/", DashboardConsumer.as_asgi()),
    path("ws/device/", DeviceConsumer.as_asgi()),
    path("ws/submissions/<uuid:sid>/", SubmissionConsumer.as_asgi()),
]
