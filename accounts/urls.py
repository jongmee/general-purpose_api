from django.urls import path, include
from rest_framework import routers
from .views import RegisterAPIView, UserAPIView, google_login, google_callback, GoogleLogin
from rest_framework_simplejwt.views import TokenRefreshView

router = routers.SimpleRouter()

urlpatterns = [
    path('', UserAPIView.as_view(), name='user_api'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('refresh/', TokenRefreshView.as_view()), # jwt 토큰 재발급
    path('allauth/', include('allauth.urls')),
    path('google/login/', google_login, name='google_login'),
    path('google/callback/', google_callback, name='google_callback'),
    path('google/login/finish/', GoogleLogin.as_view(), name='google_login_todjango'),
]