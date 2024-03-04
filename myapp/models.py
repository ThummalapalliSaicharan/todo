from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import datetime



# Create your models here.

class Todo(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(auto_now=True)
    todo_name = models.CharField(max_length=1000)
    status = models.BooleanField(default=False)

    def __str__(self):
        return self.todo_name

class Contactus(models.Model):
    username = models.CharField(max_length=100,blank=False)
    useremail = models.CharField(max_length=100,blank=False)
    subject = models.CharField(max_length=100,blank=False)
    message = models.CharField(max_length=100,blank=False)

    def __str__(self):
        return self.username

class Support(models.Model):
    user=models.CharField(max_length=100,blank=False)
    support=models.CharField(max_length=1000,blank=False)

    def __str__(self):
        return self.user

class OTPModel(models.Model):
    email = models.EmailField(max_length=100)

    def __str__(self):
        return f"reset password for {self.email}"