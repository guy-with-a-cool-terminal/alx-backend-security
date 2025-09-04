from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware(MiddlewareMixin):
    """
    this middleware does the following:
        1. Extract the real client IP address
        2. Check if IP is blocked and reject request if so
        3. Get geolocation data
        4. Log all request details to database
        
    """
    def get_client_ip(self,request):
        """
        Extract real client IP address handling proxy/load balancer scenarios.
        
        Order of preference based on reliability:
        1. X-Forwarded-For header (most common proxy header)
        2. X-Real-IP header 
        3. HTTP_X_FORWARDED_FOR (Django's processed version)
        4. REMOTE_ADDR (direct connection IP)
        
        """
        # get first IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            if ip:
                return ip
        
        # single IP set by reverse proxies
        x_real_ip = request.META.get('HHTP_X_REAL_IP')
        if x_real_ip:
            return x.real_ip.strip()
        
        # cloudflare connecting IP header
        cf_connecting_ip = request.META.get("HTTP_CF_CONNECTING_IP")
        if cf_connecting_ip:
            return cf_connecting_ip.strip()
        
        # direct connection IP,might be a load balancer
        return request.META.get('REMOTE_ADDR')
    
    def process_request(self,request):
        """ 
        this will be called for every incoming request
        1. Get the real client IP
        2. Check if IP is blocked
        3. Log the request details
        
        If this method returns a HttpResponse, Django skips the view entirely
        and returns our response
        
        """
        client_ip = self.get_client_ip(request)
        # store IP in request object for views to access later,avoid recalculating
        request.client_ip = client_ip
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            # return a 403 immediately
            return HttpResponseForbidden(
                "<h1>Access Denied</h1><p>Touch Grass.</p>"
            )
        
        # get geolocation data
        country = ''
        country_code = ''
        city = ''
        if hasattr(request,'geolocation') and request.geolocation:
            # extract geolocation data
            country = getattr(request.geolocation, 'country', '') or ''
            city = getattr(request.geolocation, 'city', '') or ''
            
            # handle country format docs say it might be a dictionary
            if hasattr(country,'get'):
                country_code = country.get('code', '') or ''
                country = country.get('name', '') or ''
        
        # log request to the database
        try:
            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.get_full_path(),
                country=str(country)[:100],
                country_code=str(country_code)[:2],
                city=str(city)[:100],
            )
        except Exception as e:
            pass
        return None
    
    def process_response(self,request,response):
        """
        Called for every outgoing response after the view is done
        
        """
        return response