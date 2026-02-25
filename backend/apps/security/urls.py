from django.urls import path
from .views import SecurityDashboardView, SIEMExportView, BlockIPView

urlpatterns = [
    path('dashboard/', SecurityDashboardView.as_view(), name='security-dashboard'),
    path('export/', SIEMExportView.as_view(), name='siem-export'),
    path('block-ip/', BlockIPView.as_view(), name='block-ip'),
]
