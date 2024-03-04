from django.contrib import admin
from .models import Todo,Contactus,Support,OTPModel

# Register your models here.

admin.site.register(Todo)
admin.site.register(Contactus)
admin.site.register(Support)
admin.site.register(OTPModel)

