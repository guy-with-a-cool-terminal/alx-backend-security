from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('sensitive-data/', views.sensitive_data_view, name='sensitive_data'),
    path('admin-action/', views.admin_action_view, name='admin_action'),
    path('ip-info/', views.ip_info_view, name='ip_info'),
    path('health/', views.health_check, name='health_check'),
]