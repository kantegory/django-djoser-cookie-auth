from django.shortcuts import render
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.response import Response
from rest_framework import status
import datetime


# Create your views here.
class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        response = Response(serializer.validated_data, status=status.HTTP_200_OK)

        response.set_cookie(
            'access',
            serializer.validated_data.get("access"),
            5,
            httponly=True,
            expires=datetime.datetime.now() + datetime.timedelta(minutes=5)
        )

        response.set_cookie(
            'refresh',
            serializer.validated_data.get("refresh"),
            5,
            httponly=True,
            expires=datetime.datetime.now() + datetime.timedelta(days=1)
        )

        return response
