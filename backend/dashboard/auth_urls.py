from django.urls import path

from . import auth_api

urlpatterns = [
    path("token/", auth_api.LoginView.as_view()),
    path("refresh/", auth_api.RefreshView.as_view()),
    path("me/", auth_api.MeView.as_view()),
]
