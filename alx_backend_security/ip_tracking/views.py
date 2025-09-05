from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.contrib import messages
from django.urls import reverse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import json
from .models import RequestLog, BlockedIP


def ratelimit_handler(request, exception):
    """
    Custom handler for when rate limit is exceeded.
    Returns appropriate response based on request type.
    """
    if request.content_type == 'application/json':
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
        }, status=429)
    else:
        messages.error(request, 'Too many requests. Please try again later.')
        return redirect('ip_tracking:dashboard')


def custom_ratelimit_by_auth(group, request):
    """
    Dynamic rate limiting based on authentication status.
    - Authenticated users: 10 requests/minute
    - Anonymous users: 5 requests/minute
    """
    return '10/m' if request.user.is_authenticated else '5/m'


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    User login view with rate limiting protection.
    Rate limit: 5 login attempts per minute per IP.
    """
    if request.method == 'GET':
        # Render login form
        context = {
            'title': 'Login',
            'rate_limit_info': '5 attempts per minute'
        }
        return render(request, 'ip_tracking/login.html', context)
    
    elif request.method == 'POST':
        try:
            # Handle both form data and JSON
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                username = data.get('username')
                password = data.get('password')
            else:
                username = request.POST.get('username')
                password = request.POST.get('password')
            
            if not username or not password:
                error_msg = 'Username and password are required'
                if request.content_type == 'application/json':
                    return JsonResponse({'error': error_msg}, status=400)
                messages.error(request, error_msg)
                return render(request, 'ip_tracking/login.html')
            
            # TODO: Implement actual authentication logic
            # For now, just return success response structure
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                success_msg = f'Welcome back, {user.username}!'
                
                if request.content_type == 'application/json':
                    return JsonResponse({
                        'success': True,
                        'message': success_msg,
                        'redirect_url': reverse('ip_tracking:dashboard')
                    })
                messages.success(request, success_msg)
                return redirect('ip_tracking:dashboard')
            else:
                error_msg = 'Invalid username or password'
                if request.content_type == 'application/json':
                    return JsonResponse({'error': error_msg}, status=401)
                messages.error(request, error_msg)
                return render(request, 'ip_tracking/login.html')
                
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Ratelimited:
            return ratelimit_handler(request, None)


@ratelimit(key='ip', rate=custom_ratelimit_by_auth, method='GET', block=True)
def dashboard_view(request):
    """
    Main dashboard view with dynamic rate limiting.
    Shows IP tracking analytics and system overview.
    """
    try:
        client_ip = getattr(request, 'client_ip', request.META.get('REMOTE_ADDR'))
        
        # TODO: Implement dashboard analytics
        context = {
            'title': 'IP Tracking Dashboard',
            'user': request.user,
            'client_ip': client_ip,
            'rate_limit': '10/min' if request.user.is_authenticated else '5/min',
            # Placeholder data - implement actual analytics later
            'stats': {
                'total_requests': 0,
                'unique_ips': 0,
                'blocked_ips': 0,
                'countries': 0,
            },
            'recent_requests': [],  # TODO: Get from RequestLog
            'top_countries': [],    # TODO: Analytics implementation
        }
        
        return render(request, 'ip_tracking/dashboard.html', context)
        
    except Ratelimited:
        return ratelimit_handler(request, None)


@login_required
@ratelimit(key='ip', rate='3/m', method=['GET', 'POST'], block=True)
def admin_panel_view(request):
    """
    Admin panel for managing IP blocks and system settings.
    Very strict rate limiting: 3 requests per minute.
    """
    if not request.user.is_staff:
        messages.error(request, 'Administrator access required')
        return redirect('ip_tracking:dashboard')
    
    try:
        if request.method == 'POST':
            # TODO: Handle admin actions (block/unblock IPs, etc.)
            action = request.POST.get('action')
            ip_address = request.POST.get('ip_address')
            
            if action == 'block_ip' and ip_address:
                # TODO: Implement IP blocking logic
                messages.success(request, f'IP {ip_address} has been blocked')
            elif action == 'unblock_ip' and ip_address:
                # TODO: Implement IP unblocking logic
                messages.success(request, f'IP {ip_address} has been unblocked')
            
            return redirect('ip_tracking:admin_panel')
        
        # TODO: Get actual data from models
        context = {
            'title': 'Admin Panel',
            'blocked_ips': [],      # TODO: BlockedIP.objects.all()
            'suspicious_ips': [],   # TODO: From anomaly detection
            'system_health': {      # TODO: Real system metrics
                'service_status': 'healthy',
                'cache_status': 'active',
                'db_status': 'connected',
            }
        }
        
        return render(request, 'ip_tracking/admin_panel.html', context)
        
    except Ratelimited:
        return ratelimit_handler(request, None)


@api_view(['GET'])
@ratelimit(key='ip', rate='20/m', method='GET', block=True)
def api_ip_info(request):
    """
    Public API endpoint for IP information.
    Rate limit: 20 requests per minute.
    
    Returns IP address information including geolocation data,
    request statistics, and rate limiting information.
    """
    try:
        client_ip = getattr(request, 'client_ip', request.META.get('REMOTE_ADDR'))
        
        # TODO: Get actual geolocation and request data
        response_data = {
            'ip_address': client_ip,
            'timestamp': None,  # TODO: timezone.now().isoformat()
            'geolocation': {
                'country': 'Unknown',  # TODO: From RequestLog
                'city': 'Unknown',     # TODO: From RequestLog
            },
            'request_count': 0,    # TODO: RequestLog count for this IP
            'is_blocked': False,   # TODO: Check BlockedIP model
            'rate_limit': {
                'limit': 20,
                'window': '1 minute',
                'remaining': None  # TODO: Calculate from cache
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Ratelimited:
        return Response({
            'error': 'Rate limit exceeded',
            'retry_after': 60
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)


@api_view(['POST'])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@csrf_exempt
def api_report_suspicious(request):
    """
    API endpoint for reporting suspicious activity.
    Rate limit: 10 reports per minute.
    
    Expected JSON payload:
    {
        "ip_address": "192.168.1.1",
        "reason": "Multiple failed login attempts",
        "evidence": {"attempts": 5, "timespan": "5 minutes"}
    }
    """
    try:
        data = request.data if hasattr(request, 'data') else json.loads(request.body)
        suspicious_ip = data.get('ip_address')
        reason = data.get('reason')
        evidence = data.get('evidence', {})
        
        if not suspicious_ip or not reason:
            return Response({
                'error': 'ip_address and reason are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # TODO: Implement suspicious activity reporting
        # This would integrate with the anomaly detection system
        
        return Response({
            'success': True,
            'message': 'Suspicious activity report received',
            'report_id': None,  # TODO: Generate unique report ID
        }, status=status.HTTP_201_CREATED)
        
    except json.JSONDecodeError:
        return Response({
            'error': 'Invalid JSON data'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Ratelimited:
        return Response({
            'error': 'Rate limit exceeded',
            'retry_after': 60
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)


def logout_view(request):
    """
    User logout view. No rate limiting needed for logout.
    """
    if request.user.is_authenticated:
        username = request.user.username
        logout(request)
        messages.success(request, f'Goodbye {username}!')
    
    return redirect('ip_tracking:login')


@api_view(['GET'])
def health_check(request):
    """
    Health check endpoint for load balancers and monitoring.
    No rate limiting to avoid interfering with health checks.
    
    Returns system health status including database, cache,
    and external service connectivity.
    """
    # TODO: Add actual health checks
    return Response({
        'status': 'healthy',
        'timestamp': None,  # TODO: timezone.now().isoformat()
        'services': {
            'database': 'ok',       # TODO: Check DB connection
            'cache': 'ok',          # TODO: Check cache connection
            'geolocation': 'ok',    # TODO: Check geolocation service
        }
    }, status=status.HTTP_200_OK)