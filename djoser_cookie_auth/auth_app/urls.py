from django.urls import path, include
from auth_app.views import CustomTokenObtainPairView

urlpatterns = [
    path('create/', CustomTokenObtainPairView.as_view())
]
