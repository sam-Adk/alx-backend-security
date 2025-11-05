import requests
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    """
    Middleware to:
    - Block requests from blacklisted IPs
    - Log IPs with geolocation (country, city)
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        # Block blacklisted IPs
        if ip and BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Get geolocation (cached 24 hours)
        country, city = self.get_geolocation(ip)

        # Log the request
        if ip:
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                timestamp=timezone.now(),
                country=country,
                city=city,
            )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP (handles proxies)."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def get_geolocation(self, ip):
        """Get country & city for IP, cached for 24 hours."""
        if not ip:
            return None, None

        cache_key = f"geo_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached["country"], cached["city"]

        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if response.status_code == 200:
                data = response.json()
                country = data.get("country")
                city = data.get("city")
            else:
                country, city = None, None
        except requests.RequestException:
            country, city = None, None

        cache.set(cache_key, {"country": country, "city": city}, 86400)  # 24 hours
        return country, city

