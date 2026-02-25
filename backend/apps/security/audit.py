import uuid
import logging
from django.utils import timezone
from .models import AuditLog

logger = logging.getLogger('security')

class AuditLogger:
    """
    Central audit logging utility.
    Digunakan di seluruh aplikasi untuk mencatat event.
    """

    @staticmethod
    def _get_severity(event_type):
        """Automatically assign severity based on event type."""
        critical_events = [
            'BRUTE_FORCE_DETECTED', 'SQL_INJECTION_ATTEMPT',
            'XSS_ATTEMPT', 'ACCOUNT_LOCKED'
        ]
        high_events = [
            'LOGIN_FAILED', 'UNAUTHORIZED_ACCESS',
            'RATE_LIMIT_EXCEEDED', 'PAYMENT_FAILED'
        ]
        medium_events = [
            'PASSWORD_RESET_REQUEST', 'SUSPICIOUS_ACTIVITY',
            'MULTIPLE_FAILED_PAYMENTS'
        ]

        if event_type in critical_events:
            return 'CRITICAL'
        elif event_type in high_events:
            return 'HIGH'
        elif event_type in medium_events:
            return 'MEDIUM'
        else:
            return 'INFO'

    @staticmethod
    def log(event_type, request=None, user=None, description='', extra_data=None, status_code=None):
        """
        Main logging method. Dipanggil dari views, signals, middleware.

        Usage:
            AuditLogger.log('LOGIN_SUCCESS', request=request, user=user)
            AuditLogger.log('BRUTE_FORCE_DETECTED', request=request, 
                          extra_data={'attempts': 5, 'ip': '192.168.1.1'})
        """
        if extra_data is None:
            extra_data = {}

        ip_address = None
        user_agent = ''
        request_method = ''
        request_path = ''

        if request:
            ip_address = AuditLogger._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            request_method = request.method
            request_path = request.path
            if not user and hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user

        severity = AuditLogger._get_severity(event_type)

        log_entry = AuditLog.objects.create(
            event_type=event_type,
            severity=severity,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path,
            request_id=str(uuid.uuid4()),
            description=description,
            extra_data=extra_data,
            status_code=status_code,
        )

        # Also log to Django's logger for external SIEM integration
        log_message = f"[{severity}] {event_type} | IP: {ip_address} | User: {user} | {description}"
        if severity in ['CRITICAL', 'HIGH']:
            logger.warning(log_message)
        else:
            logger.info(log_message)

        return log_entry

    @staticmethod
    def _get_client_ip(request):
        """Extract real IP, handle proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')