from django.urls import path

from . import views

urlpatterns = [
    path("devices/register", views.RegisterView.as_view(), name="device-register"),
    path("devices/me/heartbeat", views.HeartbeatView.as_view(), name="device-heartbeat"),
    path("devices/me/commands", views.CommandsView.as_view(), name="device-commands"),
    path("devices/me/commands/<int:command_id>/ack", views.AckCommandView.as_view(), name="device-command-ack"),
]
