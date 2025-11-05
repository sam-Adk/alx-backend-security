from datetime import timedelta
from django.utils import timezone
from celery import shared_task
from ip_tracking.models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Flags IPs that:
    - exceed 100 requests/hour
    - access sensitive paths (/admin, /login)
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # 1️⃣ Check for excessive requests (>100/hour)
    recent_requests = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    ip_counts = {}

    for req in recent_requests:
        ip_counts[req.ip_address] = ip_counts.get(req.ip_address, 0) + 1

    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f'High request volume: {count} requests in the past hour.'}
            )

    # 2️⃣ Check for sensitive path access
    sensitive_paths = ['/admin', '/login', '/api/secure', '/settings']
    sensitive_requests = recent_requests.filter(path__in=sensitive_paths)

    for req in sensitive_requests:
        SuspiciousIP.objects.get_or_create(
            ip_address=req.ip_address,
            defaults={'reason': f'Accessed sensitive path: {req.path}'}
        )

    return f"Suspicious IP detection completed at {now}"
