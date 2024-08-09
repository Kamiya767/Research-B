from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import UserRegisterForm, UserLoginForm
from .models import LoginLog
import subprocess
import os

def home(request):
    return render(request, 'myapp/home.html')

def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}!')
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'myapp/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                LoginLog.objects.create(user=user, success=True)
                messages.info(request, f'You are now logged in as {username}.')
                start_flask_app()  # Start the Flask application
                return redirect('login_success')
            else:
                LoginLog.objects.create(user=User.objects.filter(username=username).first(), success=False)
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = UserLoginForm()
    return render(request, 'myapp/login.html', {'form': form})

def login_success(request):
    return render(request, 'myapp/login_success.html')

def login_log(request):
    logs = LoginLog.objects.all().order_by('-timestamp')
    return render(request, 'myapp/login_log.html', {'logs': logs})

@login_required
def access_flask_app(request):
    return redirect('http://localhost:5000')

def start_flask_app():
    subprocess.Popen(['python', os.path.join(os.path.dirname(__file__), 'D:/Django part/myproject/run_flask.py')])
