from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics, permissions
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.utils import timezone
from datetime import timedelta
from .models import AuditLog, ThreatAlert, BlockedIP
from .audit import AuditLogger


class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_staff


class SecurityDashboardView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        return Response({
            "summary": {
                "open_alerts": ThreatAlert.objects.filter(status='OPEN').count(),
                "critical_events_24h": AuditLog.objects.filter(
                    severity='CRITICAL', timestamp__gte=last_24h).count(),
                "failed_logins_24h": AuditLog.objects.filter(
                    event_type='LOGIN_FAILED', timestamp__gte=last_24h).count(),
                "blocked_ips": BlockedIP.objects.filter(is_active=True).count(),
                "total_alerts_24h": ThreatAlert.objects.filter(
                    triggered_at__gte=last_24h).count(),
            },
            "event_timeline": list(
                AuditLog.objects.filter(timestamp__gte=last_24h)
                .annotate(hour=TruncHour('timestamp'))
                .values('hour').annotate(count=Count('id')).order_by('hour')
            ),
            "events_by_type": list(
                AuditLog.objects.filter(timestamp__gte=last_24h)
                .values('event_type').annotate(count=Count('id')).order_by('-count')[:10]
            ),
            "severity_distribution": list(
                AuditLog.objects.filter(timestamp__gte=last_7d)
                .values('severity').annotate(count=Count('id'))
            ),
            "top_suspicious_ips": list(
                AuditLog.objects.filter(
                    timestamp__gte=last_24h,
                    severity__in=['HIGH', 'CRITICAL']
                ).values('ip_address').annotate(count=Count('id')).order_by('-count')[:10]
            ),
            "recent_alerts": list(
                ThreatAlert.objects.filter(status='OPEN').values(
                    'id', 'alert_type', 'severity', 'source_ip',
                    'description', 'triggered_at', 'evidence'
                )[:10]
            ),
        })


class SIEMExportView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        fmt = request.query_params.get('format', 'json')
        limit = int(request.query_params.get('limit', 100))
        logs = AuditLog.objects.order_by('-timestamp')[:limit]

        if fmt == 'cef':
            sev_map = {'INFO': 2, 'LOW': 3, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
            cef_logs = []
            for log in logs:
                cef_logs.append(
                    f"CEF:0|HotelSystem|Security|1.0|{log.event_type}|"
                    f"{log.description}|{sev_map.get(log.severity, 2)}|"
                    f"src={log.ip_address} duser={log.user} request={log.request_path}"
                )
            return Response({'format': 'CEF', 'logs': cef_logs})

        return Response({
            'format': 'JSON-SIEM',
            'total': len(logs),
            'logs': [log.to_siem_format() for log in logs]
        })


class BlockIPView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        ip = request.data.get('ip_address')
        reason = request.data.get('reason', 'Manual block by admin')

        if not ip:
            return Response({'error': 'ip_address required'}, status=400)

        block, created = BlockedIP.objects.update_or_create(
            ip_address=ip,
            defaults={'reason': reason, 'is_active': True, 'auto_blocked': False}
        )

        AuditLogger.log(
            'SUSPICIOUS_ACTIVITY',
            request=request,
            description=f"Admin manually blocked IP: {ip}",
            extra_data={'blocked_ip': ip, 'reason': reason}
        )

        return Response({
            'message': f'IP {ip} has been blocked',
            'created': created
        })
