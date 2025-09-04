# ip_tracking/middleware.py

from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware that runs for every HTTP request to:
    1. Extract the real client IP address
    2. Check if IP is blocked and reject request if so
    3. Get geolocation data from django-ip-geolocation middleware
    4. Log all request details to database
    """
    
    def get_client_ip(self, request):
        """Extract real client IP address handling proxy scenarios."""
        
        # X-Forwarded-For format: "client_ip, proxy1_ip, proxy2_ip"
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
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
        return request.META.get('REMOTE_ADDR')
    
    def process_request(self, request):
        """Process every incoming request before view processing."""
        
        # Extract real client IP
        client_ip = self.get_client_ip(request)
        request.client_ip = client_ip
        
        # Check if this IP is blocked
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            return HttpResponseForbidden(
                "<h1>Access Denied</h1><p>Your IP address has been blocked.</p>"
            )
        
        # Get geolocation data from django-ip-geolocation middleware
        country = ''
        country_code = ''
        city = ''
        
        if hasattr(request, 'geolocation') and request.geolocation:
            # Extract all geolocation data
            country = getattr(request.geolocation, 'country', '') or ''
            city = getattr(request.geolocation, 'city', '') or ''
            
            # Handle country format - might be dict with 'name' and 'code' keys
            if hasattr(country, 'get'):
                country_code = country.get('code', '') or ''
                country = country.get('name', '') or ''
        
        # Log this request to database
        try:
            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.get_full_path(),
                country=str(country)[:100],
                country_code=str(country_code)[:2],
                city=str(city)[:100],
            )
        except Exception:
            # Don't break site if logging fails
            pass
        
        return None