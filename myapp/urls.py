from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
   path('todo/',views.todo,name='todo'),
   path('login',views.loginpage,name='login'),
   path('',views.index,name='index'),
   path('register/',views.register,name='register'),
   path('deletetodo/<str:id>/',views.deletetodo,name='deletetodo'),
   path('updatetodo/<str:id>/',views.updatetodo,name='updatetodo'),
   path('deletetodofromcompletedlist/<str:id>/',views.deletetodofromcompletedlist,name='deletetodofromcompletedlist'),
   path('send_reminder/',views.send_reminder,name="send_reminder"),
   path('logout/',views.logoutpage,name='logout'),
   path('activate/<uidb64>/<token>', views.ActivateAccountView.as_view(), name="activate"),
   path('contactus/',views.contactus,name="contactus"),
   path('services',views.services,name='services'),
   path('changepassword',views.changepassword,name='changepassword'),
   path('support',views.support,name='support'),
   path('completedlist',views.completedlist,name='completedlist'),
   path('forgotpassword',views.forgotpassword,name='forgotpassword'),
   path('password_reset_pageuserpassword=?reset-page',views.password_reset_page,name='password_reset_pageuserpassword=?reset-page')
]