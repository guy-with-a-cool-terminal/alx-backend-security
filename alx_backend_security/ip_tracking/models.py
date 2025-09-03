from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    """ 
    stores every incoming HTTP request 
    
    """
    # GenericIPAddressField stores an IPv4 or IPv6 address, in string format
    ip_address = models.GenericIPAddressField(
        help_text="Client IP address"
    )
    
    # set curent time
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="when the request was made"
    )
    
    # requested url path
    path = models.CharField(
        max_length=500,
        help_text="requested url path"
    )
    
    class Meta:
        # show newest first
        ordering = ['-timestamp']
        
        # database indexes for fast lookups
        indexes = [
            models.Index(fields=['ip_address'],name='idx_request_ip'),
            models.Index(fields=['timestamp'],name='idx_request_time'),
            models.Index(fields=['ip_address','timestamp'],name='idx_ip_time'),
        ]
        # readable names in django admin
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
    
    def __str__(self):
        return f"{self.ip_address} requested {self.path} at {self.timestamp}"

class BlockedIP(models.Model):
    """
    stores IP addresses that should be blocked,middleware 
    middleware checks this table before processing requests
    
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="IP addresses to block"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="when this IP was blocked"
    )
    reason = models.CharField(
        max_length=250,
        blank=True,
        help_text="why this IP was blocked"
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"

class SuspiciousIP(models.Model):
    """ 
    stores flagged IPs for review
    
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address showing suspicious behavior"
    )
    reason = models.CharField(
        max_length=250,
        help_text="Specific suspicious behavior detected"
    )
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
