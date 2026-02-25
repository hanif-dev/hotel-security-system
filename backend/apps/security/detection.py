from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import AuditLog, ThreatAlert, BlockedIP
from .audit import AuditLogger

class ThreatDetectionEngine:
    """
    Engine untuk mendeteksi pola serangan dari audit logs.
    Ini adalah versi sederhana dari SIEM correlation rules.
    """

    @staticmethod
    def check_brute_force(ip_address, user_identifier=None):
        """
        Deteksi brute force: >5 login gagal dalam 10 menit dari IP yang sama.
        MITRE ATT&CK: T1110.001 - Password Guessing
        """
        window = timezone.now() - timedelta(minutes=10)

        query = AuditLog.objects.filter(
            event_type='LOGIN_FAILED',
            ip_address=ip_address,
            timestamp__gte=window
        )

        failed_count = query.count()

        if failed_count >= 5:
            # Check if alert already exists
            existing = ThreatAlert.objects.filter(
                alert_type='BRUTE_FORCE',
                source_ip=ip_address,
                status='OPEN',
                triggered_at__gte=window
            ).exists()

            if not existing:
                alert = ThreatAlert.objects.create(
                    alert_type='BRUTE_FORCE',
                    severity='HIGH',
                    source_ip=ip_address,
                    description=f"Brute force detected: {failed_count} failed login attempts from {ip_address} in 10 minutes",
                    evidence={
                        'failed_attempts': failed_count,
                        'timewindow': '10 minutes',
                        'ip_address': ip_address,
                        'mitre_technique': 'T1110.001',
                    },
                    recommended_action='Block IP, notify admin, reset affected account password'
                )

                # Auto-block IP after detection
                ThreatDetectionEngine._auto_block_ip(
                    ip_address,
                    reason=f"Brute force: {failed_count} failed attempts",
                    duration_minutes=60
                )

                return alert

        return None

    @staticmethod
    def check_rapid_booking(user, request=None):
        """
        Deteksi pola booking mencurigakan: >3 booking dalam 1 jam.
        Kemungkinan fraud atau automated attack.
        """
        window = timezone.now() - timedelta(hours=1)

        from apps.bookings.models import Booking
        booking_count = Booking.objects.filter(
            user=user,
            created_at__gte=window
        ).count()

        if booking_count > 3:
            ThreatAlert.objects.create(
                alert_type='RAPID_BOOKING',
                severity='MEDIUM',
                affected_user=user,
                description=f"Unusual booking pattern: {booking_count} bookings in 1 hour by {user.email}",
                evidence={
                    'booking_count': booking_count,
                    'timewindow': '1 hour',
                    'user_email': user.email,
                },
                recommended_action='Review bookings, verify user identity, check for fraud'
            )

            if request:
                AuditLogger.log(
                    'SUSPICIOUS_ACTIVITY',
                    request=request,
                    user=user,
                    description=f"Rapid booking pattern detected: {booking_count} in 1h"
                )

    @staticmethod
    def check_account_enumeration(ip_address):
        """
        Deteksi account enumeration: >10 request ke endpoint /api/auth/ dari IP yang sama.
        MITRE ATT&CK: T1087 - Account Discovery
        """
        window = timezone.now() - timedelta(minutes=5)

        count = AuditLog.objects.filter(
            ip_address=ip_address,
            request_path__contains='/api/auth/',
            timestamp__gte=window
        ).count()

        if count > 10:
            ThreatAlert.objects.create(
                alert_type='ACCOUNT_ENUMERATION',
                severity='HIGH',
                source_ip=ip_address,
                description=f"Account enumeration detected: {count} auth requests from {ip_address}",
                evidence={
                    'request_count': count,
                    'endpoint': '/api/auth/',
                    'mitre_technique': 'T1087',
                },
                recommended_action='Block IP, investigate for credential stuffing'
            )

    @staticmethod
    def _auto_block_ip(ip_address, reason, duration_minutes=60):
        """Auto-block an IP address."""
        BlockedIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'blocked_until': timezone.now() + timedelta(minutes=duration_minutes),
                'is_active': True,
                'auto_blocked': True,
            }
        )