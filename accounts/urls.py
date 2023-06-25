from django.urls import path, include
from rest_framework import routers
from .views import RegisterAPIView, UserAPIView
from rest_framework_simplejwt.views import TokenRefreshView

router = routers.SimpleRouter()

urlpatterns = [
    path('', UserAPIView.as_view(), name='user_api'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('refresh/', TokenRefreshView.as_view()), # jwt 토큰 재발급
]