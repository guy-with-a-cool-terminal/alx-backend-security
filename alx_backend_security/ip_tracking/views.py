from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.core.exceptions import PermissionDenied
import json
from .models import RequestLog, BlockedIP


def ratelimit_handler(request, exception):
    """
    Custom handler for when rate limit is exceeded.
    This function is called when a user hits the rate limit.
    """
    return JsonResponse({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'status': 429
    }, status=429)


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """
    Rate limit: 5 requests per minute for any IP address
    This prevents brute force attacks on the login endpoint.
    
    Usage: POST /ip_tracking/login/
    Body: {"username": "user", "password": "pass"}
    """
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Missing credentials',
                'message': 'Both username and password are required'
            }, status=400)
        
        # Attempt authentication
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Login successful
            login(request, user)
            return JsonResponse({
                'success': True,
                'message': f'Welcome {user.username}!',
                'user_id': user.id,
                'is_authenticated': True
            })
        else:
            # Login failed
            return JsonResponse({
                'error': 'Invalid credentials',
                'message': 'Username or password is incorrect'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON',
            'message': 'Request body must be valid JSON'
        }, status=400)
    except Ratelimited:
        # This shouldn't be reached due to block=True, but good to have
        return ratelimit_handler(request, None)
    except Exception as e:
        return JsonResponse({
            'error': 'Server error',
            'message': 'An unexpected error occurred'
        }, status=500)


def custom_ratelimit_by_auth(group, request):
    """
    Custom rate limiting function that applies different limits based on authentication.
    
    - Authenticated users: 10 requests/minute
    - Anonymous users: 5 requests/minute
    
    This function returns the appropriate rate limit string.
    """
    if request.user.is_authenticated:
        return '10/m'  # 10 requests per minute for authenticated users
    return '5/m'      # 5 requests per minute for anonymous users


@ratelimit(key='ip', rate=custom_ratelimit_by_auth, method='GET', block=True)
def sensitive_data_view(request):
    """
    A sensitive view that demonstrates dynamic rate limiting.
    
    Rate limits:
    - Authenticated users: 10 requests/minute
    - Anonymous users: 5 requests/minute
    
    Usage: GET /ip_tracking/sensitive-data/
    """
    try:
        # Get client IP from our middleware
        client_ip = getattr(request, 'client_ip', 'Unknown')
        
        # Get recent request logs for this IP
        recent_logs = RequestLog.objects.filter(
            ip_address=client_ip
        ).order_by('-timestamp')[:10]
        
        # Build response data
        response_data = {
            'message': 'Access granted to sensitive data',
            'your_ip': client_ip,
            'is_authenticated': request.user.is_authenticated,
            'rate_limit': '10/min' if request.user.is_authenticated else '5/min',
            'recent_requests': []
        }
        
        # Add recent request data
        for log in recent_logs:
            response_data['recent_requests'].append({
                'path': log.path,
                'timestamp': log.timestamp.isoformat(),
                'country': log.country,
                'city': log.city
            })
        
        if request.user.is_authenticated:
            response_data['username'] = request.user.username
            response_data['user_id'] = request.user.id
        
        return JsonResponse(response_data)
        
    except Ratelimited:
        return ratelimit_handler(request, None)
    except Exception as e:
        return JsonResponse({
            'error': 'Server error',
            'message': 'An unexpected error occurred'
        }, status=500)


@ratelimit(key='ip', rate='3/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["POST"])
def admin_action_view(request):
    """
    Simulates an admin action with very strict rate limiting.
    
    Rate limit: 3 requests per minute for any IP
    This represents a highly sensitive admin operation.
    
    Usage: POST /ip_tracking/admin-action/
    """
    try:
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required',
                'message': 'You must be logged in to perform admin actions'
            }, status=401)
        
        # Parse request data
        data = json.loads(request.body) if request.body else {}
        action = data.get('action', 'unknown')
        
        # Simulate admin action
        return JsonResponse({
            'success': True,
            'message': f'Admin action "{action}" completed successfully',
            'performed_by': request.user.username,
            'ip_address': getattr(request, 'client_ip', 'Unknown'),
            'rate_limit': '3/min'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON',
            'message': 'Request body must be valid JSON'
        }, status=400)
    except Ratelimited:
        return ratelimit_handler(request, None)
    except Exception as e:
        return JsonResponse({
            'error': 'Server error',
            'message': 'An unexpected error occurred'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def logout_view(request):
    """
    Simple logout view (no rate limiting needed for logout).
    
    Usage: POST /ip_tracking/logout/
    """
    if request.user.is_authenticated:
        username = request.user.username
        logout(request)
        return JsonResponse({
            'success': True,
            'message': f'Goodbye {username}! You have been logged out.'
        })
    else:
        return JsonResponse({
            'error': 'Not logged in',
            'message': 'You were not logged in'
        }, status=400)


@ratelimit(key='ip', rate='20/m', method='GET', block=True)
def ip_info_view(request):
    """
    Public view to show IP information with moderate rate limiting.
    
    Rate limit: 20 requests per minute
    This is a less sensitive endpoint but still needs protection.
    
    Usage: GET /ip_tracking/ip-info/
    """
    try:
        client_ip = getattr(request, 'client_ip', 'Unknown')
        
        # Check if IP is blocked
        is_blocked = BlockedIP.objects.filter(ip_address=client_ip).exists()
        
        # Get request count for this IP
        request_count = RequestLog.objects.filter(ip_address=client_ip).count()
        
        # Get the most recent log entry for geolocation data
        recent_log = RequestLog.objects.filter(
            ip_address=client_ip
        ).order_by('-timestamp').first()
        
        response_data = {
            'ip_address': client_ip,
            'is_blocked': is_blocked,
            'total_requests': request_count,
            'rate_limit': '20/min',
            'geolocation': {
                'country': recent_log.country if recent_log else 'Unknown',
                'city': recent_log.city if recent_log else 'Unknown'
            }
        }
        
        return JsonResponse(response_data)
        
    except Ratelimited:
        return ratelimit_handler(request, None)
    except Exception as e:
        return JsonResponse({
            'error': 'Server error',
            'message': 'An unexpected error occurred'
        }, status=500)


# Health check view (no rate limiting)
def health_check(request):
    """
    Simple health check endpoint with no rate limiting.
    Used for monitoring and load balancer health checks.
    
    Usage: GET /ip_tracking/health/
    """
    return JsonResponse({
        'status': 'healthy',
        'message': 'IP Tracking service is running'
    })