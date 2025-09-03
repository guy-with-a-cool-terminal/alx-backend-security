# ip_tracking/middleware.py

from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware that runs for every HTTP request to:
    1. Extract the real client IP address
    2. Check if IP is blocked and reject request if so
    3. Log all request details to database
    
    Middleware executes in order defined in settings.py MIDDLEWARE list.
    This should run early to catch and block requests before expensive processing.
    """
    
    def get_client_ip(self, request):
        """
        Extract real client IP address handling proxy/load balancer scenarios.
        
        Order of preference based on reliability:
        1. X-Forwarded-For header (most common proxy header)
        2. X-Real-IP header (nginx sets this)
        3. HTTP_X_FORWARDED_FOR (Django's processed version)
        4. REMOTE_ADDR (direct connection IP - could be proxy)
        """
        
        # X-Forwarded-For format: "client_ip, proxy1_ip, proxy2_ip"
        # We want the first IP (client), not the last (our load balancer)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Split by comma and take first IP (the real client)
            ip = x_forwarded_for.split(',')[0].strip()
            if ip:
                return ip
        
        # Single IP set by nginx or other reverse proxy
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip.strip()
        
        # Cloudflare's connecting IP header
        cf_connecting_ip = request.META.get('HTTP_CF_CONNECTING_IP')
        if cf_connecting_ip:
            return cf_connecting_ip.strip()
        
        # Fallback to direct connection IP
        # This might be load balancer IP in production
        return request.META.get('REMOTE_ADDR')
    
    def process_request(self, request):
        """
        Called for every incoming request BEFORE view processing.
        
        This is where we:
        1. Get the real client IP
        2. Check if IP is blocked
        3. Log the request details
        
        If this method returns HttpResponse, Django skips the view entirely
        and returns our response (used for blocking).
        """
        
        # Extract real client IP using our helper method
        client_ip = self.get_client_ip(request)
        
        # Store IP in request object so views can access it later
        # This avoids recalculating IP in views
        request.client_ip = client_ip
        
        # Check if this IP is in our blocklist
        # exists() is more efficient than get() when we only need yes/no
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            # Return 403 Forbidden immediately, don't process the request
            # This prevents blocked users from accessing any part of the site
            return HttpResponseForbidden(
                "<h1>Access Denied</h1><p>Your IP address has been blocked.</p>"
            )
        
        # Log this request to database for monitoring and analysis
        try:
            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.get_full_path(),  # Include query parameters like ?page=2
                # timestamp automatically set by model default
            )
        except Exception as e:
            # Don't break the website if logging fails
            # In production, you'd want to log this error somewhere
            # For now, silently continue serving the request
            pass
        
        # Return None means "continue processing normally"
        # Request will proceed to next middleware and eventually the view
        return None
    
    def process_response(self, request, response):
        """
        Called for every outgoing response AFTER view processing.
        
        This runs after the view has processed and created a response.
        We could add security headers, modify response based on IP, etc.
        
        For basic IP tracking, we don't need this method, but it's here
        for future enhancements.
        """
        
        # Could add security headers based on IP analysis:
        # if hasattr(request, 'client_ip') and is_suspicious_ip(request.client_ip):
        #     response['X-Security-Level'] = 'high'
        
        return response