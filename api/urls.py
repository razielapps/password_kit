from django.urls import path
from .views import HealthView
from . import views

urlpatterns = [
    path("v1/health/", HealthView.as_view()),
     path('api/rockyou/', views.RockYouView.as_view(), name='rockyou'),
    path('api/password/generate/', views.PasswordGeneratorView.as_view(), name='generate-password'),
    
    # Optional: Add these for more specific endpoints
    path('api/check/password/', views.RockYouView.as_view(), {'method': 'check_password'}, name='check-password'),
    path('api/check/hash/', views.RockYouView.as_view(), {'method': 'check_hash'}, name='check-hash'),
    path('api/rockyou/add/', views.RockYouView.as_view(), {'method': 'add_to_rockyou'}, name='add-rockyou'),
]
