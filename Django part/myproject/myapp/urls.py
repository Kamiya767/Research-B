

from django.urls import path
from .views import register, user_login, home, login_success, login_log, access_flask_app

urlpatterns = [
    path('', home, name='home'),
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('login_success/', login_success, name='login_success'),
    path('login_log/', login_log, name='login_log'),
    path('flask-app/', access_flask_app, name='access_flask_app'),
]
