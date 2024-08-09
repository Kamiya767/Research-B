

from django.db import models
from django.contrib.auth.models import User

class LoginLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField()

    def __str__(self):
        return f"{self.user.username} - {'Success' if self.success else 'Failure'} - {self.timestamp}"
