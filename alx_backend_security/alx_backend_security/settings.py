from pathlib import Path
from decouple import config
import os
from celery.schedules import crontab

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='', cast=lambda v: [s.strip() for s in v.split(',') if s.strip()])

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'ip_tracking',
    'rest_framework',
    'django_celery_results',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Added for static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django_ip_geolocation.middleware.IpGeolocationMiddleware',
    'ip_tracking.middleware.IPTrackingMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'alx_backend_security.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'alx_backend_security.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# WhiteNoise configuration for static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Geolocation configuration
IP_GEOLOCATION_SETTINGS = {
    'BACKEND': 'django_ip_geolocation.backends.IPDataCo',
    'BACKEND_API_KEY': config('IPDATA_API_KEY'),
    'ENABLE_REQUEST_HOOK': True,
    'ENABLE_RESPONSE_HOOK': False,
    'ENABLE_COOKIE': False, 
}

# Rate limiting configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Cache configuration - Updated for deployment
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'cache_table',
    }
}
# when i configure redis

# CELERY_BROKER_URL = 'redis://localhost:6379/0' 
# CELERY_RESULT_BACKEND = 'redis://localhost:6379/0' 

# Celery configuration - Using filesystem as broker instead of Redis
CELERY_BROKER_URL = f'filesystem://{BASE_DIR / "celery_broker"}'
CELERY_RESULT_BACKEND = f'file://{BASE_DIR / "celery_results"}'

# Filesystem broker transport options
CELERY_BROKER_TRANSPORT_OPTIONS = {
    'data_folder_in': BASE_DIR / 'celery_broker' / 'data_in',
    'data_folder_out': BASE_DIR / 'celery_broker' / 'data_out',
    'data_folder_processed': BASE_DIR / 'celery_broker' / 'processed',
}

# Ensure directories exist for file-based Celery
os.makedirs(BASE_DIR / 'celery_broker' / 'data_in', exist_ok=True)
os.makedirs(BASE_DIR / 'celery_broker' / 'data_out', exist_ok=True)
os.makedirs(BASE_DIR / 'celery_broker' / 'processed', exist_ok=True)
os.makedirs(BASE_DIR / 'celery_results', exist_ok=True)

# Celery task configuration
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

CELERY_BEAT_SCHEDULE = {
    'detect-anomalous-ips': {
        'task': 'ip_tracking.tasks.detect_anomalous_ips',
        'schedule': crontab(minute=0),  # Run every hour at minute 0
    },
    'cleanup-old-records': {
        'task': 'ip_tracking.tasks.cleanup_old_suspicious_records',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2:00 AM
    },
    'generate-security-report': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': crontab(hour=6, minute=0),  # Run daily at 6:00 AM
    },
}

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'celery_tasks.log',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'ip_tracking.tasks': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Security settings for production
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True