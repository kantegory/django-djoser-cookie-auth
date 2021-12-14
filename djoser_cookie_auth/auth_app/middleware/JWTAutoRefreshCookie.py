from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
import datetime


class JWTAutoRefreshCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        refresh_token = request.COOKIES.get('refresh')
        response = self.get_response(request)

        url = request.path

        disabled_urls = ['login', 'logout']

        is_url_disabled = len(
            list(
                filter(lambda _url: _url in url, disabled_urls)
            )
        ) > 0

        if refresh_token and not is_url_disabled:
            refresh = RefreshToken(refresh_token)

            data = {'access': str(refresh.access_token)}

            if api_settings.ROTATE_REFRESH_TOKENS:

                refresh.set_jti()
                refresh.set_exp()

                data['refresh'] = str(refresh)

            request.COOKIES['access'] = data.get('access')
            request.COOKIES['refresh'] = data.get('refresh', refresh_token)

            response = self.get_response(request) 

            response.set_cookie(
                'access',
                data.get("access"),
                5,
                httponly=True,
                expires=datetime.datetime.now() + datetime.timedelta(minutes=5)
            )

            response.set_cookie(
                'refresh',
                data.get("refresh", refresh_token),
                5,
                httponly=True,
                expires=datetime.datetime.now() + datetime.timedelta(days=1)
            )

        return response
