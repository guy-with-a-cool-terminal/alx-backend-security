# Celery Configuration
import os
from celery.schedules import crontab

# Celery broker configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Using Redis as message broker
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'  # Store task results in Redis

# Alternative: Using database as broker (simpler setup, no Redis required)
# CELERY_BROKER_URL = 'db+sqlite:///celerydb.sqlite'
# CELERY_RESULT_BACKEND = 'db+sqlite:///celerydb.sqlite'

# Celery task configuration
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# Celery Beat scheduler configuration (for periodic tasks)
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