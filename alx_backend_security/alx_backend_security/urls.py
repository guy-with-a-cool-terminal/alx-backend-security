from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('ip_tracking/', include('ip_tracking.urls')),
]
