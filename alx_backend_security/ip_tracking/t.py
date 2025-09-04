from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from .models import RequestLog, BlockedIP


class IPTrackingMiddleware(MiddlewareMixin):
    """
    This middleware does the following:
    1. Extract the real client IP address
    2. Check if IP is blocked and reject request if so
    3. Get geolocation data (with 24-hour caching to reduce API calls)
    4. Log all request details to database
    """

    def get_client_ip(self, request):
        """
        Extract real client IP address handling proxy/load balancer scenarios.
        Order of preference based on reliability:
        1. X-Forwarded-For header (most common proxy header)
        2. X-Real-IP header
        3. HTTP_X_FORWARDED_FOR (Django's processed version)
        4. REMOTE_ADDR (direct connection IP)
        """
        # Get first IP from X-Forwarded-For header (proxy chain)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            if ip:
                return ip

        # Single IP set by reverse proxies
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip.strip()

        # Cloudflare connecting IP header
        cf_connecting_ip = request.META.get("HTTP_CF_CONNECTING_IP")
        if cf_connecting_ip:
            return cf_connecting_ip.strip()

        # Direct connection IP, might be a load balancer
        return request.META.get('REMOTE_ADDR')

    def get_geolocation_data(self, client_ip, request):
        """
        Get geolocation data for the given IP address.
        Implements 24-hour caching to reduce API calls and improve performance.
        
        Args:
            client_ip (str): The client's IP address
            request: Django request object (contains geolocation data)
            
        Returns:
            dict: Contains country, country_code, and city data
        """
        # Create a unique cache key for this IP address
        cache_key = f"geo_data_{client_ip}"
        
        # Try to get cached geolocation data first
        cached_geo_data = cache.get(cache_key)
        
        if cached_geo_data:
            # Cache hit: Use the cached data instead of making API call
            print(f"Using cached geolocation data for IP: {client_ip}")  # Debug log
            return cached_geo_data
        
        # Cache miss: Get fresh geolocation data from the API
        print(f"Fetching fresh geolocation data for IP: {client_ip}")  # Debug log
        
        # Initialize default values
        country = ''
        country_code = ''
        city = ''
        
        # Check if geolocation data is available from django-ip-geolocation middleware
        if hasattr(request, 'geolocation') and request.geolocation:
            try:
                # Extract geolocation data from the request
                country = getattr(request.geolocation, 'country', '') or ''
                city = getattr(request.geolocation, 'city', '') or ''
                
                # Handle country format - docs say it might be a dictionary
                if hasattr(country, 'get'):
                    # Country is a dictionary with 'code' and 'name' keys
                    country_code = country.get('code', '') or ''
                    country = country.get('name', '') or ''
                
                # Only cache if we got valid data (not empty)
                if country or city:
                    # Prepare the data to be cached
                    geo_data = {
                        'country': str(country)[:100],        # Limit to 100 chars
                        'country_code': str(country_code)[:2], # Limit to 2 chars
                        'city': str(city)[:100]               # Limit to 100 chars
                    }
                    
                    # Store in cache for 24 hours (86400 seconds)
                    # This reduces API calls and improves response time
                    cache.set(cache_key, geo_data, 86400)
                    
                    return geo_data
                
            except Exception as e:
                # If geolocation extraction fails, return empty data
                print(f"Error extracting geolocation data: {e}")  # Debug log
                pass
        
        # Return empty data if no geolocation available
        return {
            'country': '',
            'country_code': '',
            'city': ''
        }

    def process_request(self, request):
        """
        This will be called for every incoming request.
        1. Get the real client IP
        2. Check if IP is blocked
        3. Get geolocation data (with caching)
        4. Log the request details
        
        If this method returns an HttpResponse, Django skips the view entirely
        and returns our response.
        """
        # Step 1: Extract the real client IP address
        client_ip = self.get_client_ip(request)
        
        # Store IP in request object for views to access later, avoid recalculating
        request.client_ip = client_ip

        # Step 2: Check if this IP address is blocked
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            # IP is blocked: return a 403 Forbidden response immediately
            return HttpResponseForbidden(
                "<h1>Access Denied</h1><p>Touch Grass.</p>"
            )

        # Step 3: Get geolocation data with caching
        geo_data = self.get_geolocation_data(client_ip, request)
        
        # Step 4: Log request to the database
        try:
            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.get_full_path(),
                country=geo_data['country'],
                country_code=geo_data['country_code'],
                city=geo_data['city'],
            )
        except Exception as e:
            # Silently handle database errors - don't break the request flow
            print(f"Error logging request: {e}")  # Debug log
            pass

        # Return None to continue normal request processing
        return None

    def process_response(self, request, response):
        """
        Called for every outgoing response after the view is done.
        Currently just passes the response through unchanged.
        """
        return response