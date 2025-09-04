from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger(__name__)

@shared_task
def detect_anomalous_ips():
    """
    Hourly Celery task to detect and flag suspicious IP addresses.
    
    Detection criteria:
    1. IPs exceeding 100 requests/hour
    2. IPs accessing sensitive paths (/admin, /login)
    
    This task runs every hour via Celery Beat scheduler.
    """
    logger.info("starting detection..")
    
    # time window
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    total_suspicious_ips = 0
    new_detections = 0
    
    try:
        # detect > 100 requests/hour
        high_volume_ips = detect_high_volume_ips(one_hour_ago)
        new_detections += len(high_volume_ips)
        total_suspicious_ips += len(high_volume_ips)
        
        # sensitive paths detection
        sensitive_path_ips = detect_sensitive_path_access(one_hour_ago)
        new_detections += len(sensitive_path_ips)
        total_suspicious_ips += len(sensitive_path_ips)
        
        logger.info(f"Anomaly detection completed. Found {total_suspicious_ips} suspicious IPs, {new_detections} new detections")
        
        return {
            'status': 'completed',
            'timestamp': timezone.now().isoformat(),
            'total_suspicious_ips': total_suspicious_ips,
            'new_detections': new_detections,
            'detection_types': {
                'high_volume': len(high_volume_ips),
                'sensitive_paths': len(sensitive_path_ips)
            }
        }
    except Exception as e:
        logger.error(f"Anomaly detection task failed: {str(e)}")
        return {
            'status': 'failed',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }
def detect_high_volume_ips(time_threshold):
    """
    Detect IPs that have made more than 100 requests in the last hour.
    
    Args:
        time_threshold (datetime): Start time for the detection window
        
    Returns:
        list: List of suspicious IP addresses detected
    """
    
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=time_threshold)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
        .order_by('-request_count')
    )
    suspicious_ips = []
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Check if we've already flagged this IP recently
        existing_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='High request volume',
            detected_at__gte=timezone.now() - timedelta(hours=6)  # Don't duplicate within 6 hours
        ).exists()
        if not existing_flag:
            # Create new suspicious IP record
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'High request volume: {request_count} requests in 1 hour (threshold: 100)'
            )
            
            suspicious_ips.append(ip_address)
            logger.warning(f"Flagged high-volume IP: {ip_address} ({request_count} requests)")
    
    logger.info(f"High-volume detection complete. Found {len(suspicious_ips)} new suspicious IPs")
    return suspicious_ips

def detect_sensitive_path_access(time_threshold):
    """
    Detect IPs accessing sensitive paths like /admin, /login.
    
    Args:
        time_threshold (datetime): Start time for the detection window
        
    Returns:
        list: List of suspicious IP addresses detected
    """ 
    sensitive_paths = [
        '/admin',
        '/login',
        '/api/admin',
        '/management',
        '/dashboard/admin',
        '/staff',
        '/superuser'
    ]
    
    suspicious_ips = []
    
    for sensitive_path in sensitive_paths:
        # Find IPs that accessed this sensitive path
        accessing_ips = (
            RequestLog.objects
            .filter(
                timestamp__gte=time_threshold,
                path__icontains=sensitive_path
            )
            .values('ip_address')
            .annotate(access_count=Count('id'))
            .order_by('-access_count')
        )
        
        for ip_data in accessing_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            existing_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                reason__contains=f'Sensitive path access: {sensitive_path}',
                detected_at__gte=timezone.now() - timedelta(hours=6) 
            ).exists()
            
            if not existing_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f'Sensitive path access: {sensitive_path} ({access_count} attempts)'
                )
                
                if ip_address not in suspicious_ips:
                    suspicious_ips.append(ip_address)
                
                logger.warning(f"Flagged sensitive path access: {ip_address} -> {sensitive_path} ({access_count} attempts)")
    
    logger.info(f"Sensitive path detection complete. Found {len(suspicious_ips)} new suspicious IPs")
    return suspicious_ips

@shared_task
def cleanup_old_suspicious_records():
    """
    Cleanup task to remove old suspicious IP records.
    Runs daily to prevent database bloat.
    Keeps records for 30 days by default.
    """
    logger.info("Starting cleanup of old suspicious IP records...")
    
    try:
        # Delete records older than 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        deleted_count, _ = SuspiciousIP.objects.filter(
            detected_at__lt=thirty_days_ago
        ).delete()
        
        logger.info(f"Cleanup completed. Removed {deleted_count} old suspicious IP records")
        
        return {
            'status': 'completed',
            'deleted_records': deleted_count,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        return {
            'status': 'failed',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }

@shared_task
def generate_security_report():
    """
    Generate a daily security summary report.
    This task can be extended to send email notifications or save reports.
    """
    logger.info("Generating security report...")
    
    try:
        # Calculate statistics for the last 24 hours
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        
        # Get statistics
        total_requests = RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).count()
        unique_ips = RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).values('ip_address').distinct().count()
        suspicious_detections = SuspiciousIP.objects.filter(detected_at__gte=twenty_four_hours_ago).count()
        
        # Get top countries
        top_countries = (
            RequestLog.objects
            .filter(timestamp__gte=twenty_four_hours_ago, country__isnull=False)
            .exclude(country='')
            .values('country')
            .annotate(request_count=Count('id'))
            .order_by('-request_count')[:5]
        )
        
        # Get most active IPs
        top_ips = (
            RequestLog.objects
            .filter(timestamp__gte=twenty_four_hours_ago)
            .values('ip_address')
            .annotate(request_count=Count('id'))
            .order_by('-request_count')[:10]
        )
        
        report = {
            'report_date': timezone.now().date().isoformat(),
            'period': '24 hours',
            'statistics': {
                'total_requests': total_requests,
                'unique_ips': unique_ips,
                'suspicious_detections': suspicious_detections,
            },
            'top_countries': list(top_countries),
            'top_ips': list(top_ips),
            'generated_at': timezone.now().isoformat()
        }
        return report
        
    except Exception as e:
        logger.error(f"Security report generation failed: {str(e)}")
        return {
            'status': 'failed',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }

@shared_task
def test_anomaly_detection():
    """
    Test task to verify Celery is working correctly.
    """
    logger.info("Running anomaly detection test...")
    
    try:
        # Get current statistics
        total_requests = RequestLog.objects.count()
        suspicious_count = SuspiciousIP.objects.count()
        
        return {
            'status': 'test_successful',
            'timestamp': timezone.now().isoformat(),
            'current_stats': {
                'total_requests': total_requests,
                'suspicious_ips': suspicious_count
            },
            'message': 'Celery anomaly detection is working correctly!'
        }
        
    except Exception as e:
        logger.error(f"Test task failed: {str(e)}")
        return {
            'status': 'test_failed',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }