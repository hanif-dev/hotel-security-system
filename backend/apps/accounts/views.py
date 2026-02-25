from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from apps.security.audit import AuditLogger
from apps.security.detection import ThreatDetectionEngine
from .models import User
from .serializers import UserSerializer, LoginSerializer

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            AuditLogger.log(
                'LOGIN_FAILED',
                request=request,
                description='Invalid request format',
                extra_data={'errors': serializer.errors}
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        ip = self._get_ip(request)

        # 🔐 Check if IP is in cooldown from previous brute force
        from apps.security.models import BlockedIP
        from django.db.models import Q
        if BlockedIP.objects.filter(
            ip_address=ip, is_active=True
        ).filter(
            Q(blocked_until__isnull=True) | Q(blocked_until__gt=timezone.now())
        ).exists():
            return Response(
                {'error': 'Too many failed attempts. Please try again later.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Attempt authentication
        user = authenticate(request, username=email, password=password)

        if user is None:
            # 🔐 Log failed attempt
            AuditLogger.log(
                'LOGIN_FAILED',
                request=request,
                description=f'Failed login for {email}',
                extra_data={
                    'email_attempted': email,
                    'ip': ip
                }
            )

            # 🔐 Check for brute force pattern
            ThreatDetectionEngine.check_brute_force(ip, email)
            ThreatDetectionEngine.check_account_enumeration(ip)

            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # 🔐 Check if account is locked
        if user.is_locked and user.lockout_until and user.lockout_until > timezone.now():
            AuditLogger.log(
                'UNAUTHORIZED_ACCESS',
                request=request,
                user=user,
                description='Attempt to login to locked account'
            )
            return Response(
                {'error': 'Account is temporarily locked. Please try again later.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Successful login
        refresh = RefreshToken.for_user(user)

        # Update user security fields
        user.failed_login_attempts = 0
        user.last_login_ip = ip
        user.save(update_fields=['failed_login_attempts', 'last_login_ip'])

        # 🔐 Log successful login
        AuditLogger.log(
            'LOGIN_SUCCESS',
            request=request,
            user=user,
            description=f'Successful login for {user.email}',
            status_code=200
        )

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data
        })

    def _get_ip(self, request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded.split(',')[0].strip() if x_forwarded else request.META.get('REMOTE_ADDR')


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            AuditLogger.log(
                'ACCOUNT_CREATED',
                request=request,
                user=user,
                description=f'New account created: {user.email}'
            )

            return Response(
                {'message': 'Account created successfully', 'user': UserSerializer(user).data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)