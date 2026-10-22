"""Django settings for the Sentinel SOC backend (Stages 2, 3, 5, 6, 7).

Shared keys (CONTRACTS section 11) are read from the environment with the contract defaults.
"""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY", "dev-only-insecure-key-change-me-0000000")
DEBUG = _env_bool("SENTINEL_DEBUG", True)
ALLOWED_HOSTS = os.environ.get("SENTINEL_ALLOWED_HOSTS", "*").split(",")

# ---- Shared configuration keys (CONTRACTS section 11) -----------------------------------------
SENTINEL = {
    "PAIRING_TTL_MIN": _env_int("SENTINEL_PAIRING_TTL_MIN", 10),
    "MAX_APK_MB": _env_int("MAX_APK_MB", 100),
    "ANALYSIS_VERSION": _env_int("ANALYSIS_VERSION", 4),  # 4: + vendor allowlist, IPs only from URLs, launcher aliases, media ignored
    "DYNAMIC_ENABLED": _env_bool("DYNAMIC_ENABLED", False),
    "MAX_VERIFICATION_LOOPS": _env_int("MAX_VERIFICATION_LOOPS", 2),
    "REASONER_BACKEND": os.environ.get("REASONER_BACKEND", "rules"),
    "REASONER_TIMEOUT_S": _env_int("REASONER_TIMEOUT_S", 60),
    "AUTO_REMEDIATION_ENABLED": _env_bool("AUTO_REMEDIATION_ENABLED", False),
    "AUTO_REMEDIATION_MIN_CONFIDENCE": _env_float("AUTO_REMEDIATION_MIN_CONFIDENCE", 0.85),
    "REMEDIATION_TTL_HOURS": _env_int("REMEDIATION_TTL_HOURS", 24),
    "REMEDIATION_RATE_LIMIT_PER_DEVICE_HOUR": _env_int("REMEDIATION_RATE_LIMIT_PER_DEVICE_HOUR", 3),
    "DEVICE_POLL_SECONDS": _env_int("DEVICE_POLL_SECONDS", 5),
    "DEV_FAULTS": _env_bool("SENTINEL_DEV_FAULTS", False),
    "DATA_DIR": Path(os.environ.get("SENTINEL_DATA_DIR", BASE_DIR / "data")),
}
SENTINEL["MEDIA_SAMPLES"] = SENTINEL["DATA_DIR"] / "samples"
SENTINEL["WORK_DIR"] = SENTINEL["DATA_DIR"] / "work"
SENTINEL["RULES_DIR"] = SENTINEL["DATA_DIR"] / "rules"
SENTINEL["REPUTATION_DIR"] = BASE_DIR / "analysis" / "data" / "reputation"

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "channels",
    "devices",
    "submissions",
    "pipeline",
    "analysis",
    "reasoning",
    "remediation",
    "rules",
    "realtime",
    "dashboard",
    "evalkit",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",   # before CommonMiddleware; lets the Next.js dev server call /api/v1
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "dashboard.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "sentinel.urls"
ASGI_APPLICATION = "sentinel.asgi.application"
WSGI_APPLICATION = "sentinel.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "dashboard.context.role",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("SENTINEL_DB_PATH", str(BASE_DIR / "data" / "db.sqlite3")),
    }
}

AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "dashboard" / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # the dashboard JS reads csrftoken and sends X-CSRFToken

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",   # Next.js dashboard (Authorization: Bearer)
        "rest_framework.authentication.SessionAuthentication",         # legacy Django-rendered dashboard + admin
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "sentinel.pagination.SentinelPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "sentinel.errors.exception_handler",
    "DEFAULT_THROTTLE_RATES": {"pairing": "5/min", "device": "240/min", "login": "10/min"},
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}

# ---- Next.js dashboard: CORS + JWT (see API.md) ------------------------------------------------
CORS_ALLOWED_ORIGINS = [o for o in os.environ.get(
    "SENTINEL_WEB_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o]
CORS_ALLOW_CREDENTIALS = False   # bearer tokens, not cookies
CORS_EXPOSE_HEADERS = ["Content-Disposition"]
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=_env_int("SENTINEL_ACCESS_TOKEN_MIN", 15)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=_env_int("SENTINEL_REFRESH_TOKEN_DAYS", 7)),
    "ROTATE_REFRESH_TOKENS": False,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# ---- Realtime (Channels) and Celery ------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "")
if REDIS_URL:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            # redis-py >= 8 applies a 5s socket read timeout, equal to channels_redis' 5s blocking pop, so every
            # idle WebSocket died with "Timeout reading from redis". Keep the socket timeout above the pop timeout.
            "CONFIG": {"hosts": [{"address": REDIS_URL, "socket_timeout": 30}]},
        }
    }
else:
    CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}

CELERY_BROKER_URL = REDIS_URL or "memory://"
CELERY_RESULT_BACKEND = None
CELERY_TASK_ALWAYS_EAGER = _env_bool("SENTINEL_EAGER", False)
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ROUTES = {
    "analysis.tasks.*": {"queue": "analysis"},
    "pipeline.tasks.run_reasoning": {"queue": "reasoning"},
    "pipeline.tasks.*": {"queue": "default"},
}
CELERY_BEAT_SCHEDULE = {
    "expire-remediations": {"task": "remediation.tasks.expire_remediations", "schedule": 600.0},
    "requeue-stale": {"task": "pipeline.tasks.requeue_stale", "schedule": 120.0},
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": os.environ.get("SENTINEL_LOG_LEVEL", "INFO")},
}
