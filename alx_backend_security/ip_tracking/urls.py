# ip_tracking/urls.py
from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    # Authentication
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Admin interface
    path('admin/', views.admin_panel_view, name='admin_panel'),
    
    # API endpoints
    path('api/ip-info/', views.api_ip_info, name='api_ip_info'),
    path('api/report-suspicious/', views.api_report_suspicious, name='api_report_suspicious'),
    
    # System
    path('health/', views.health_check, name='health_check'),
]