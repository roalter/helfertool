"""
Django settings for Helfertool.
"""

import os
import re
import sys

from django.utils.translation import gettext_lazy as _

from datetime import timedelta
from pathlib import Path

from .utils import build_path, get_version, pg_trgm_installed


def _enabled(var, default_result="0"):
    return os.environ.get(var, default_result).lower() in ["1", "on", "yes", "true", "enabled"]


def _has(var):
    if var not in os.environ:
        return False
    return os.environ.get(var) != ""


def _get(var, default_value=None):
    result = os.environ.get(var, default_value)
    if result == "":
        result = None
    return result


def _get_int(var, default_value=0):
    return int(_get(var, str(default_value)))


def _get_float(var, default_value=0.0):
    return float(_get(var, str(default_value)))
    

# import josepy, otherwise the oidc module does not work properly...
import josepy

BASE_DIR = Path(__file__).resolve().parent.parent

# versioning
HELFERTOOL_VERSION = get_version(BASE_DIR / "version.txt")
HELFERTOOL_CONTAINER_VERSION = None  # will be set in settings_container.py

# directories for static and media files (overwritten in settings_container.py)
STATIC_ROOT = _get("STATIC_ROOT", BASE_DIR / ".." / "static")
MEDIA_ROOT = _get("MEDIA_ROOT", BASE_DIR / ".." / "media")
BADGES_ROOT = _get("BADGES_ROOT", BASE_DIR / ".." / "badges")

# directory for temporary files like badges, file uploads (overwritten in settings_container.py)
TMP_ROOT = _get("TEMP_ROOT", "/tmp")

STATIC_URL = "/static/"
MEDIA_URL = "/media/"

# file permissions for newly uploaded files and directories
FILE_UPLOAD_PERMISSIONS = 0o640
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o750
FILE_UPLOAD_TEMP_DIR = TMP_ROOT

# internationalization
LANGUAGE_CODE = _get("LANGUAGE_DEFAULT", "de")

TIME_ZONE = _get("LANGUAGE_TIMEZONE", "Europe/Berlin")

LANGUAGE_SINGLELANGUAGE = _enabled("LANGUAGE_SINGLE")

if LANGUAGE_SINGLELANGUAGE:
    if LANGUAGE_CODE == "de":
        LANGUAGES = (("de", _("German")),)
    elif LANGUAGE_CODE == "en":
        LANGUAGES = (("en", _("English")),)
    else:
        print("Invalid language: {}".format(LANGUAGE_CODE))
        sys.exit(1)
else:
    LANGUAGES = (
        ("de", _("German")),
        ("en", _("English")),
    )

USE_I18N = True
USE_TZ = True

DEFAULT_COUNTRY = _get("LANGUAGE_DEFAULT_COUNTRY", "de")


# database
def generate_database(connection_string: str):
    _c = re.compile(
        r"^(?P<engine>[\w.-]+)://(|(?P<user>[\w.-]+)(|:(?P<secret>.+))@)"
        r"(?P<host>[\w.-]+)(|:(?P<port>\d+))/(?P<database>.+)$"
    )
    result = _c.match(connection_string)
    if not result:
        raise SyntaxError(f"Connection string {connection_string} is invalid.")

    def get(field, default=None):
        value = result.group(field)
        return default if value is None else value

    engine = get("engine", "sqlite3")
    if engine.startswith("sqlite"):
        base = get("host").replace("BASE_DIR", str(BASE_DIR))
        name = base + "/" + get("database")
    else:
        name = get("database")

    return dict(
        ENGINE="django.db.backends." + engine,
        NAME=name,
        USER=get("user"),
        PASSWORD=get("secret"),
        HOST=get("host"),
        PORT=get("port", "5432"),
    )


DATABASES = dict(default=generate_database(_get("DATABASE_URI", "sqlite3://BASE_DIR/database.sqlite3")))
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# rabbitmq

CELERY_BROKER_URL = _get("CELERY_BROKER_URI", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = _get("CELERY_BACKEND_URI", "redis://localhost:6379/0")
CELERY_RESULT_EXTENDED = True
CELERY_BROKER_POOL_LIMIT = None
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# caches
CACHES = {
    # default cache - not used on purpose currently
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
    # select2 needs its own cache
    "select2": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "select2_cache",
    },
    # cache for locks (used by celery tasks to prevent parallel execution)
    "locks": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "locks_cache",
    },
}

# mail
if _has("MAIL_OUTGOING_SERVER"):
    # send
    EMAIL_HOST = _get("MAIL_OUTGOING_SERVER")
    EMAIL_PORT = _get_int("MAIL_OUTGOING_PORT", 25)
    EMAIL_HOST_USER = _get("MAIL_OUTGOING_USERNAME", None)
    EMAIL_HOST_PASSWORD = _get("MAIL_OUTGOING_PASSWORD", None)
    EMAIL_USE_SSL = _enabled("MAIL_OUTGOING_USE_SSL")
    EMAIL_USE_TLS = _enabled("MAIL_OUTGOING_USE_TLS")

    if EMAIL_USE_SSL and EMAIL_USE_TLS:
        print("Mail settings for sending invalid: TLS and STARTTLS are mutually exclusive")
        sys.exit(1)

    # receive
    RECEIVE_EMAIL_HOST = _get("MAIL_INCOMING_SERVER")
    RECEIVE_EMAIL_PORT = _get_int("MAIL_INCOMING_PORT", 143)
    RECEIVE_EMAIL_HOST_USER = _get("MAIL_INCOMING_USERNAME")
    RECEIVE_EMAIL_HOST_PASSWORD = _get("MAIL_INCOMING_PASSWORD")
    RECEIVE_EMAIL_USE_SSL = _enabled("MAIL_INCOMING_USE_SSL")
    RECEIVE_EMAIL_USE_TLS = _enabled("MAIL_INCOMING_USE_TLS")

    RECEIVE_EMAIL_FOLDER = _get("MAIL_INCOMING_FOLDER", "INBOX")
    RECEIVE_INTERVAL = _get_int("MAIL_INCOMING_CHECK_INTERVAL", 300)

    if RECEIVE_EMAIL_USE_SSL and RECEIVE_EMAIL_USE_TLS:
        print("Mail settings for receiving invalid: TLS and STARTTLS are mutually exclusive")
        sys.exit(1)
else:
    # old config format
    EMAIL_HOST = None
    EMAIL_PORT = 25
    EMAIL_HOST_USER = None
    EMAIL_HOST_PASSWORD = None
    EMAIL_USE_TLS = False
    RECEIVE_EMAIL_HOST = None

# sender of all mails (because of SPF, DKIM, DMARC)
# the display name defaults to the mail address
EMAIL_SENDER_ADDRESS = _get("MAIL_SENDER_ADDRESS", "helfertool@localhost")
EMAIL_SENDER_NAME = _get("MAIL_SENDER_NAME", EMAIL_SENDER_ADDRESS)

SERVER_EMAIL = EMAIL_SENDER_ADDRESS  # for error messages

# forward mails that were not handled automatically to this address
# the display name defaults to the mail address
FORWARD_UNHANDLED_ADDRESS = _get("MAIL_FORWARD_UNHANDLED_ADDRESS", None)
FORWARD_UNHANDLED_NAME = _get("MAIL_FORWARD_UNHANDLED_NAME", None)

# newsletter: number of mails sent during one connection and time between
MAIL_BATCH_SIZE = _get_int("MAIL_BATCH_SIZE", 200)
MAIL_BATCH_GAP = _get_int("MAIL_BATCH_GAP", 5)

# authentication
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/manage/account/check/"
LOGOUT_REDIRECT_URL = "/"

LOCAL_USER_CHAR = _get("AUTH_LOCAL_USER_CHAR", None)

# django auth backends
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesBackend",
]

# LDAP
if _has("AUTH_LDAP_SERVER_URI"):
    import django_auth_ldap.config
    import ldap

    # server address and authentication
    AUTH_LDAP_SERVER_URI = _get("AUTH_LDAP_SERVER_URI")
    AUTH_LDAP_BIND_DN = _get("AUTH_LDAP_BIND_DN", None)
    AUTH_LDAP_BIND_PASSWORD = _get("AUTH_LDAP_BIND_PASSWORD", None)

    # user search
    user_search_base = _get("AUTH_LDAP_SEARCH_BASE", None)
    user_search_filter = _get("AUTH_LDAP_SEARCH_FILTER", None)

    if user_search_base is not None and user_search_filter is not None:
        AUTH_LDAP_USER_SEARCH = django_auth_ldap.config.LDAPSearch(
            user_search_base,
            ldap.SCOPE_SUBTREE,  # pylint: disable=E1101
            user_search_filter,
        )

    AUTH_LDAP_USER_DN_TEMPLATE = _get("AUTH_LDAP_USER_DN_TEMPLATE", None)

    # user schema
    AUTH_LDAP_USER_ATTR_MAP = {
        "first_name": _get("AUTH_LDAP_MAP_FIRSTNAME", "givenName"),
        "last_name": _get("AUTH_LDAP_MAP_LASTNAME", "sn"),
        "email": _get("AUTH_LDAP_MAP_EMAIL", "mail")
    }

    # group schema
    group_type_name = _get("AUTH_LDAP_GROUP_TYPE", "GroupOfNamesType")
    AUTH_LDAP_GROUP_TYPE = getattr(django_auth_ldap.config, group_type_name)()

    AUTH_LDAP_GROUP_SEARCH = django_auth_ldap.config.LDAPSearch(
        _get("AUTH_LDAP_GROUP_BASE_DN", None),
        ldap.SCOPE_SUBTREE,  # pylint: disable=E1101
        "(objectClass={})".format(_get("AUTH_LDAP_GROUP_OBJECT", "groupOfNames")),
    )
    AUTH_LDAP_MIRROR_GROUPS = False

    # permissions based on groups
    AUTH_LDAP_USER_FLAGS_BY_GROUP = {}

    ldap_group_login = _get("AUTH_LDAP_LOGIN_BY_GROUPS", None)
    if ldap_group_login:
        AUTH_LDAP_USER_FLAGS_BY_GROUP["is_active"] = ldap_group_login

    ldap_group_admin = _get("AUTH_LDAP_LOGIN_BY_ADMINS", None)
    if ldap_group_admin:
        AUTH_LDAP_USER_FLAGS_BY_GROUP["is_staff"] = ldap_group_admin
        AUTH_LDAP_USER_FLAGS_BY_GROUP["is_superuser"] = ldap_group_admin

    AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")

# OpenID Connect
OIDC_CUSTOM_PROVIDER_NAME = None  # used to check if enabled or not
OIDC_CUSTOM_LOGOUT_ENDPOINT = None
OIDC_CUSTOM_LOGOUT_REDIRECT_PARAMTER = None
oidc_config = False
oidc_renew_check_interval = 0

if _has("AUTH_OIDC_PROVIDER"):
    # name for identity provider displayed on login page (custom paremeter, not from lib)
    OIDC_CUSTOM_PROVIDER_NAME = _get("AUTH_OIDC_PROVIDER", "OpenID Connect")

    # provider
    OIDC_RP_SIGN_ALGO = "RS256"
    OIDC_OP_JWKS_ENDPOINT = _get("AUTH_OIDC_JWKS_URL", None)

    OIDC_RP_CLIENT_ID = _get("AUTH_OIDC_CLIENT_ID", None)
    OIDC_RP_CLIENT_SECRET = _get("AUTH_OIDC_CLIENT_SECRET", None)

    OIDC_OP_AUTHORIZATION_ENDPOINT = _get("AUTH_OIDC_AUTHORIZATION_ENDPOINT", None)
    OIDC_OP_TOKEN_ENDPOINT = _get("AUTH_OIDC_TOKEN_ENDPOINT", None)
    OIDC_OP_USER_ENDPOINT = _get("AUTH_OIDC_USER_ENDPOINT", None)

    OIDC_RP_SCOPES = _get("AUTH_OIDC_SCOPES", "openid email profile")

    oidc_renew_check_interval = _get_int("AUTH_OIDC_RENEW_INTERVAL", 0)
    if oidc_renew_check_interval > 0:
        OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS = oidc_renew_check_interval * 60

    # username is mail address
    OIDC_USERNAME_ALGO = "helfertool.oidc.generate_username"

    # login and logout
    LOGIN_REDIRECT_URL_FAILURE = "/oidc/failed"
    ALLOW_LOGOUT_GET_METHOD = True

    oidc_logout = _get("AUTH_OIDC_LOGOUT", None)
    if oidc_logout:
        OIDC_CUSTOM_LOGOUT_ENDPOINT = _get("AUTH_OIDC_LOGOUT_ENDPOINT", None)
        OIDC_CUSTOM_LOGOUT_REDIRECT_PARAMTER = _get("AUTH_OIDC_LOGOUT_REDIRECT_PARAMETER", None)

        OIDC_OP_LOGOUT_URL_METHOD = "helfertool.oidc.custom_oidc_logout"

    # claims for is_active and is_admin
    OIDC_CUSTOM_CLAIM_LOGIN = _get("AUTH_OIDC_CLAIMS_USER")
    OIDC_CUSTOM_CLAIM_ADMIN = _get("AUTH_OIDC_CLAIMS_ADMIN")

    AUTHENTICATION_BACKENDS.append("helfertool.oidc.CustomOIDCAuthenticationBackend")
    oidc_config = True

AUTHENTICATION_BACKENDS.append("django.contrib.auth.backends.ModelBackend")

# password policy
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": _get_int("SECURITY_PASSWORD_LENGTH", 12),
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# axes: user lockout based on username, not IP or user agent
AXES_LOCKOUT_PARAMETERS = ["username"]
AXES_LOCK_OUT_AT_FAILURE = True

AXES_FAILURE_LIMIT = _get_int("SECURITY_AXES_LOCKOUT_LIMT", 5)
AXES_COOLOFF_TIME = lambda request: timedelta(minutes=_get_int("SECURITY_AXES_LOCKOUT_TIME", 10))

AXES_LOCKOUT_TEMPLATE = "helfertool/login_banned.html"
AXES_DISABLE_ACCESS_LOG = True
if OIDC_CUSTOM_PROVIDER_NAME is not None:
    AXES_WHITELIST_CALLABLE = "helfertool.oidc.axes_whitelist"

# security
DEBUG = _enabled("DEBUG")
SECRET_KEY = _get("SECRET_KEY", "CHANGEME")
ALLOWED_HOSTS = _get("DJANGO_ALLOWED_HOSTS", "localhost 0.0.0.0").split()
CSRF_TRUSTED_ORIGINS = [f"https://{x}" for x in ALLOWED_HOSTS]

CAPTCHAS_NEWSLETTER = _enabled("SECURITY_CAPTCHAS_NEWSLETTER")
CAPTCHAS_REGISTRATION = _enabled("SECURITY_CAPTCHAS_REGISTRATION")

# use X-Forwarded-Proto header to determine if https is used (overwritten in settings_container.py)
if _enabled("SECURITY_PROXY_FORWARD"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# password hashers: use scrypt instead of PBKDF2
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.ScryptPasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# cookies
LANGUAGE_COOKIE_NAME = "lang"
LANGUAGE_COOKIE_HTTPONLY = True
LANGUAGE_COOKIE_SAMESITE = "Lax"
LANGUAGE_COOKIE_AGE = 31449600

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
# OIDC with foreign TLDs is blocked by SAMESITE=Strict, so make this configurable

if _enabled("AUTH_OIDC_THIRDPARTY_DOMAIN"):
    SESSION_COOKIE_SAMESITE = "Lax"
else:
    SESSION_COOKIE_SAMESITE = "Strict"

if not DEBUG:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    LANGUAGE_COOKIE_SECURE = True

# logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "require_debug_true": {
            "()": "django.utils.log.RequireDebugTrue",
        },
    },
    "formatters": {
        # formatters for console and syslog. database logging does not use a formatter
        "helfertool_console": {
            "()": "toollog.formatters.TextFormatter",
            "format": "[%(asctime)s] %(levelname)s %(message)s (%(extras)s)",
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
        "helfertool_syslog": {
            "()": "toollog.formatters.TextFormatter",
            "format": "helfertool %(levelname)s %(message)s (%(extras)s)",
        },
    },
    "handlers": {
        # console output in debug mode (-> development)
        "helfertool_console": {
            "class": "logging.StreamHandler",
            "filters": ["require_debug_true"],
            "formatter": "helfertool_console",
            "level": "INFO",
        },
        # store in database (only event-related entries)
        "helfertool_database": {
            "class": "toollog.handlers.DatabaseHandler",
            "level": "INFO",
        }
        # syslog handlers are added dynamically below
    },
    "loggers": {
        "helfertool": {
            "handlers": ["helfertool_console"],
            "level": "INFO",
        },
    },
}

# Helfertool features
FEATURES_NEWSLETTER = _enabled("FEATURE_NEWSLETTER", "1")
FEATURES_BADGES = _enabled("FEATURE_BADGES", "1")
FEATURES_GIFTS = _enabled("FEATURE_GIFTS", "1")
FEATURES_PREREQUISITES = _enabled("FEATURE_PREREQUISITES", "1")
FEATURES_INVENTORY = _enabled("FEATURE_INVENTORY", "1")
FEATURES_CORONA = _enabled("FEATURE_CORONA", "1")

# Display Options
# Maximum years of events to be displayed by default on the main page
EVENTS_LAST_YEARS = _get_int("CUSTOM_EVENTS_HISTORY", "2")
if EVENTS_LAST_YEARS < 0:
    print("events_show_years must be positive or 0")
    sys.exit(1)

# announcement on every page
ANNOUNCEMENT_TEXT = _get("CUSTOM_ANNOUNCEMENT_TEXT", None)

# title for all pages
PAGE_TITLE = _get("CUSTOM_TITLE", "Helfertool")

# external URLs
PRIVACY_URL = _get("CUSTOM_PRIVACY_URL", "/help/privacy/")
IMPRINT_URL = _get("CUSTOM_IMPRINT_URL", "/help/imprint/")
DOCS_URL = _get("CUSTOM_DOCS_URL", "https://docs.helfertool.org")
WEBSITE_URL = "https://www.helfertool.org"

# mail address for "About this software" page and support requests
CONTACT_MAIL = _get("CUSTOM_CONTACT_ADDRESS", "helfertool@localhost")

# similarity search for postgresql
SEARCH_SIMILARITY_DISABLED = not _enabled("SEARCH_SIMILARITY")
SEARCH_SIMILARITY = 0.3

if not SEARCH_SIMILARITY_DISABLED:
    # it only works on postgresql when pg_trgm is there, so check this. otherwise, disable
    if "postgresql" in DATABASES["default"]["ENGINE"]:
        if not pg_trgm_installed():
            SEARCH_SIMILARITY_DISABLED = True
    else:
        SEARCH_SIMILARITY_DISABLED = True
    if not SEARCH_SIMILARITY_DISABLED:
        SEARCH_SIMILARITY = _get_float("SEARCH_SIMILARITY", 0.3)

# badges
BADGE_PDFLATEX = _get("BADGE_PDFLATEX", "/usr/bin/pdflatex")
BADGE_PHOTO_MAX_SIZE = _get_int("BADGE_PHOTO_MAX_SIZE", 1000)
BADGE_SPECIAL_MAX = _get_int("BADGE_SPECIAL_MAX_SIZE", 50)

BADGE_PDF_TIMEOUT = 60 * _get_int("BADGE_PDF_TIMEOUT", 30)
BADGE_RM_DELAY = 60 * _get_int("BADGE_RM_DELAY", 60)

BADGE_DEFAULT_TEMPLATE = BADGES_ROOT

# copy generated latex code for badges to this file, disable with None
if DEBUG:
    BADGE_TEMPLATE_DEBUG_FILE = build_path("badge_debugging.tex", BASE_DIR)
else:
    BADGE_TEMPLATE_DEBUG_FILE = None

BADGE_LANGUAGE_CODE = _get("BADGE_LANGUAGE_CODE", "de")

# newsletter
NEWS_SUBSCRIBE_DEADLINE = _get_int("NEWSLETTER_DEADLINE", 3)

# internal group names
GROUP_ADDUSER = "registration_adduser"
GROUP_ADDEVENT = "registration_addevent"
GROUP_SENDNEWS = "registration_sendnews"

# Bootstrap config
BOOTSTRAP5 = {
    "required_css_class": "required-form",
}

# HTML sanitization for text fields
BLEACH_ALLOWED_TAGS = ["h2", "h3", "p", "b", "i", "u", "em", "strong", "a", "br", "ul", "ol", "li"]
BLEACH_ALLOWED_ATTRIBUTES = [
    "href",
]
BLEACH_ALLOWED_STYLES = []
BLEACH_STRIP_TAGS = True

# editor for text fields
CKEDITOR_CONFIGS = {
    "default": {
        "toolbar": "Custom",
        "toolbar_Custom": [
            ["Bold", "Italic", "Underline"],
            [
                "NumberedList",
                "BulletedList",
                "-",
            ],
            ["Link", "Unlink"],
            ["Source"],
        ],
        # we want to have a responsive ckeditor:
        # 1. set width for editor itself here
        # 2. set width also vor div.django-ckeditor-widget via custom CSS
        "width": "100%",
    }
}

# django-select2 config
SELECT2_CACHE_BACKEND = "select2"

# django-icons config
DJANGO_ICONS = {
    "DEFAULTS": {
        "renderer": "fontawesome4",
    },
    "RENDERERS": {
        "fontawesome4": "FontAwesome4Renderer",
    },
}

# django-simple-captcha
CAPTCHA_FONT_SIZE = 30
CAPTCHA_IMAGE_SIZE = (120, 50)
CAPTCHA_LETTER_ROTATION = (-30, 30)
CAPTCHA_FOREGROUND_COLOR = "#1ea082"

# application definition
INSTALLED_APPS = (
    "helfertool",  # we override some default translations here, so put it first
    "modeltranslation",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "mozilla_django_oidc",
    "django_celery_beat",
    "axes",
    "django_bootstrap5",
    "django_icons",
    "django_select2",
    "django_countries",
    "captcha",
    "ckeditor",
    "compressor",
    #"django_celery_results",
    "registration.apps.RegistrationConfig",
    "statistic.apps.StatisticConfig",
    "badges.apps.BadgesConfig",
    "news.apps.NewsConfig",
    "gifts.apps.GiftsConfig",
    "inventory.apps.InventoryConfig",
    "mail.apps.MailConfig",
    "help.apps.HelpConfig",
    "account.apps.AccountConfig",
    "toolsettings.apps.ToolsettingsConfig",
    "prerequisites.apps.PrerequisitesConfig",
    "toollog.apps.ToollogConfig",
    "corona.apps.CoronaConfig",
)

# middleware
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

if oidc_config and oidc_renew_check_interval > 0:
    MIDDLEWARE.append("mozilla_django_oidc.middleware.SessionRefresh")

MIDDLEWARE.append("axes.middleware.AxesMiddleware")  # axes should be the last one

# templates and css/js compression
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR / "helfertool" / "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.media",
            ],
        },
    },
]

COMPRESS_ENABLED = True  # compress also in debug mode
COMPRESS_OFFLINE = not DEBUG  # offline compression for prod deployments (overwritten in settings_container.py)
COMPRESS_OUTPUT_DIR = "compressed"
COMPRESS_FILTERS = {
    "css": [
        "compressor.filters.css_default.CssAbsoluteFilter",
        "compressor.filters.cssmin.CSSCompressorFilter",
    ],
    "js": [
        "compressor.filters.jsmin.JSMinFilter",
    ],
}

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    "compressor.finders.CompressorFinder",
)

COMPRESS_PRECOMPILERS = (("text/x-scss", "django_libsass.SassCompiler"),)

# urls and wsgi things
ROOT_URLCONF = "helfertool.urls"

WSGI_APPLICATION = "helfertool.wsgi.application"
