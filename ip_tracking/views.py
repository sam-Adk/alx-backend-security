from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit

# Example: Sensitive endpoint (fake login for demonstration)
@csrf_exempt
@ratelimit(key='ip', rate='10/m', method='POST', block=True)  # For authenticated users
@ratelimit(key='ip', rate='5/m', method='POST', block=True)   # For anonymous users
def login_view(request):
    """
    Example login endpoint with rate limiting by IP.
    Authenticated: 10 requests/min
    Anonymous: 5 requests/min
    """
    if getattr(request, 'limited', False):
        # This flag is set by django-ratelimit if rate exceeded and block=False
        return JsonResponse({'error': 'Too many requests'}, status=429)

    if request.method == 'POST':
        # Fake login logic for demonstration
        return JsonResponse({'message': 'Login successful (demo)'})
    
    return JsonResponse({'message': 'Send a POST request to log in.'})
