import os

from django.conf import settings
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sentinel.settings")
django_asgi = get_asgi_application()  # must run before importing routing
if settings.DEBUG:
    # Daphne does not serve static files on its own; without this the dashboard JS/CSS 404 and pages never render.
    django_asgi = ASGIStaticFilesHandler(django_asgi)

from channels.auth import AuthMiddlewareStack  # noqa: E402
from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from channels.security.websocket import AllowedHostsOriginValidator  # noqa: E402

from realtime.auth import JWTQueryAuthMiddleware  # noqa: E402
from sentinel.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter({
    "http": django_asgi,
    "websocket": AllowedHostsOriginValidator(AuthMiddlewareStack(JWTQueryAuthMiddleware(URLRouter(websocket_urlpatterns)))),
})
