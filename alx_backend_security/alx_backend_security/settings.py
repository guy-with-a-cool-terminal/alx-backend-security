from pathlib import Path
from decouple import config
import os
from celery.schedules import crontab

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-)(*(zp0q6e(2b!*#=9w^x4h9jj(jv57-9p)23=xvuu@vi0lxhi'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


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
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

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

# Cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Celery broker configuration

CELERY_BROKER_URL = 'redis://localhost:6379/0' 
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'  


# Ensure directories exist
os.makedirs(BASE_DIR / 'celery_broker', exist_ok=True)
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

# Logging configuration for Celery tasks
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'celery_tasks.log',
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