import re
from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Q
from .audit import AuditLogger


class ThreatDetectionMiddleware:

    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"union.+select",
        r"select.+from",
        r"drop.+table",
        r"insert.+into",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"document\.cookie",
    ]

    def __init__(self, get_response):
        self.get_response = get_response
        self.sql_re = re.compile('|'.join(self.SQL_PATTERNS), re.IGNORECASE)
        self.xss_re = re.compile('|'.join(self.XSS_PATTERNS), re.IGNORECASE)

    def __call__(self, request):
        ip = self._get_ip(request)

        if self._is_blocked(ip):
            AuditLogger.log('UNAUTHORIZED_ACCESS', request=request,
                          description=f"Blocked IP attempted access: {ip}")
            return JsonResponse({'error': 'Access denied'}, status=403)

        data = self._get_data(request)

        if self.sql_re.search(data):
            AuditLogger.log('SQL_INJECTION_ATTEMPT', request=request,
                          description=f"SQL injection pattern dari {ip}",
                          extra_data={'preview': data[:200]})
            return JsonResponse({'error': 'Malicious request detected'}, status=400)

        if self.xss_re.search(data):
            AuditLogger.log('XSS_ATTEMPT', request=request,
                          description=f"XSS pattern dari {ip}")
            return JsonResponse({'error': 'Malicious request detected'}, status=400)

        return self.get_response(request)

    def _is_blocked(self, ip):
        if not ip:
            return False
        try:
            from .models import BlockedIP
            return BlockedIP.objects.filter(
                ip_address=ip, is_active=True
            ).filter(
                Q(blocked_until__isnull=True) | Q(blocked_until__gt=timezone.now())
            ).exists()
        except Exception:
            return False

    def _get_ip(self, request):
        x = request.META.get('HTTP_X_FORWARDED_FOR')
        return x.split(',')[0].strip() if x else request.META.get('REMOTE_ADDR')

    def _get_data(self, request):
        parts = [request.path, request.META.get('QUERY_STRING', '')]
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                parts.append(request.body.decode('utf-8', errors='ignore'))
            except Exception:
                pass
        return ' '.join(parts)


class SecurityAuditMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith('/api/') and response.status_code >= 400:
            AuditLogger.log(
                'UNAUTHORIZED_ACCESS' if response.status_code == 401 else 'SUSPICIOUS_ACTIVITY',
                request=request,
                description=f"HTTP {response.status_code} on {request.path}",
                status_code=response.status_code,
            )
        return response
