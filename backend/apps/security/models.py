from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class AuditLog(models.Model):
    """
    Comprehensive audit log untuk setiap aksi user.
    Ini yang disebut 'structured logging' dalam SOC context.
    """
    EVENT_TYPES = [
        # Authentication events
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('TOKEN_REFRESH', 'Token Refresh'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PASSWORD_RESET_REQUEST', 'Password Reset Request'),
        # Account events
        ('ACCOUNT_CREATED', 'Account Created'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('ACCOUNT_UNLOCKED', 'Account Unlocked'),
        ('PROFILE_UPDATE', 'Profile Update'),
        # Resource events
        ('BOOKING_CREATED', 'Booking Created'),
        ('BOOKING_MODIFIED', 'Booking Modified'),
        ('BOOKING_CANCELLED', 'Booking Cancelled'),
        ('PAYMENT_INITIATED', 'Payment Initiated'),
        ('PAYMENT_SUCCESS', 'Payment Success'),
        ('PAYMENT_FAILED', 'Payment Failed'),
        # Security events
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('BRUTE_FORCE_DETECTED', 'Brute Force Detected'),
        ('RATE_LIMIT_EXCEEDED', 'Rate Limit Exceeded'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
        ('SQL_INJECTION_ATTEMPT', 'SQL Injection Attempt'),
        ('XSS_ATTEMPT', 'XSS Attempt'),
        # Admin events
        ('ADMIN_LOGIN', 'Admin Login'),
        ('DATA_EXPORT', 'Data Export'),
        ('USER_DELETED', 'User Deleted'),
        ('PERMISSION_CHANGE', 'Permission Change'),
    ]

    SEVERITY_LEVELS = [
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    # Core fields
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='INFO')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    # Actor information
    user = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='audit_logs'
    )
    username_attempted = models.CharField(max_length=255, blank=True)  # For failed logins

    # Network information
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    request_id = models.CharField(max_length=36, blank=True)  # UUID for request tracing

    # Event details
    description = models.TextField(blank=True)
    extra_data = models.JSONField(default=dict, blank=True)  # Structured additional data

    # Response info
    status_code = models.IntegerField(null=True, blank=True)

    # For incident correlation
    session_id = models.CharField(max_length=100, blank=True)
    correlation_id = models.CharField(max_length=36, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.event_type} - {self.timestamp}"

    def to_siem_format(self):
        """Export log dalam format yang kompatibel dengan SIEM tools."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.ip_address,
            "user": self.user.email if self.user else self.username_attempted,
            "action": self.request_method,
            "resource": self.request_path,
            "outcome": "success" if self.status_code and self.status_code < 400 else "failure",
            "details": self.extra_data,
            "mitre_technique": self._map_to_mitre(),
        }

    def _map_to_mitre(self):
        """Map event types ke MITRE ATT&CK techniques."""
        mapping = {
            'LOGIN_FAILED': 'T1110 - Brute Force',
            'BRUTE_FORCE_DETECTED': 'T1110.001 - Password Guessing',
            'SQL_INJECTION_ATTEMPT': 'T1190 - Exploit Public-Facing Application',
            'XSS_ATTEMPT': 'T1059.007 - JavaScript',
            'UNAUTHORIZED_ACCESS': 'T1078 - Valid Accounts',
            'RATE_LIMIT_EXCEEDED': 'T1498 - Network Denial of Service',
        }
        return mapping.get(self.event_type, 'N/A')


class ThreatAlert(models.Model):
    """
    Alert yang di-generate oleh threat detection engine.
    Mirip dengan alert di SIEM tools seperti Splunk/QRadar.
    """
    ALERT_TYPES = [
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('CREDENTIAL_STUFFING', 'Credential Stuffing'),
        ('UNUSUAL_LOCATION', 'Unusual Login Location'),
        ('RAPID_BOOKING', 'Rapid Booking Pattern'),
        ('MASS_DATA_ACCESS', 'Mass Data Access'),
        ('AFTER_HOURS_ACCESS', 'After Hours Admin Access'),
        ('MULTIPLE_FAILED_PAYMENTS', 'Multiple Failed Payments'),
        ('ACCOUNT_ENUMERATION', 'Account Enumeration'),
    ]

    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]

    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')

    triggered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    source_ip = models.GenericIPAddressField(null=True, blank=True)
    affected_user = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL
    )

    description = models.TextField()
    evidence = models.JSONField(default=dict)  # Supporting log entries
    recommended_action = models.TextField(blank=True)

    # Correlation with audit logs
    related_logs = models.ManyToManyField(AuditLog, blank=True)

    class Meta:
        ordering = ['-triggered_at']

    def __str__(self):
        return f"[{self.severity}] {self.alert_type} - {self.triggered_at}"


class BlockedIP(models.Model):
    """IP addresses yang diblokir oleh sistem."""
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.TextField()
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_until = models.DateTimeField(null=True, blank=True)  # None = permanent
    is_active = models.BooleanField(default=True)
    auto_blocked = models.BooleanField(default=True)  # True = blocked by system, False = manual

    class Meta:
        ordering = ['-blocked_at']

    def __str__(self):
        return f"Blocked IP: {self.ip_address}"