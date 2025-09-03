# ip_tracking/models.py

from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    """
    Stores every HTTP request made to our Django application.
    Used for security monitoring, analytics, and debugging.
    """
    # GenericIPAddressField automatically validates IPv4/IPv6 format
    # Stores IP as efficient database format (not just text)
    ip_address = models.GenericIPAddressField(
        help_text="Client IP address (IPv4 or IPv6)"
    )
    
    # DateTimeField with timezone awareness
    # default=timezone.now sets current time if not specified
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the request was made"
    )
    
    # CharField for URL path like '/admin', '/login', '/api/users'
    # max_length=500 handles most realistic URL lengths
    path = models.CharField(
        max_length=500,
        help_text="URL path that was requested"
    )
    
    class Meta:
        # Show newest requests first in admin and queries
        ordering = ['-timestamp']
        
        # Database indexes for fast queries
        # Without indexes, queries scan entire table (slow)
        # With indexes, database jumps to specific records (fast)
        indexes = [
            # Fast lookups like "show all requests from this IP"
            models.Index(fields=['ip_address'], name='idx_request_ip'),
            # Fast lookups like "show requests from last hour"
            models.Index(fields=['timestamp'], name='idx_request_time'),
            # Fast lookups combining both fields for anomaly detection
            models.Index(fields=['ip_address', 'timestamp'], name='idx_ip_time'),
        ]
        
        # Human-readable names in Django admin
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
    
    def __str__(self):
        """String representation shown in Django admin"""
        return f"{self.ip_address} requested {self.path} at {self.timestamp}"

class BlockedIP(models.Model):
    """
    Stores IP addresses that should be blocked from accessing the site.
    Middleware checks this table before processing requests.
    """
    # unique=True prevents duplicate blocked IPs
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="IP address to block"
    )
    
    # auto_now_add=True sets timestamp only when record is created
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this IP was blocked"
    )
    
    # Optional reason for blocking (manual blocks, automated detection, etc.)
    reason = models.CharField(
        max_length=255,
        blank=True,
        help_text="Why this IP was blocked"
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"

class SuspiciousIP(models.Model):
    """
    Stores IPs flagged by anomaly detection system.
    These are not blocked automatically, but flagged for review.
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address showing suspicious behavior"
    )
    
    # Why this IP was flagged (too many requests, admin access, etc.)
    reason = models.CharField(
        max_length=255,
        help_text="Specific suspicious behavior detected"
    )
    
    # When the suspicious activity was detected
    detected_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When suspicious activity was detected"
    )
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
    
    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"