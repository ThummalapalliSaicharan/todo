from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import Todo,Contactus
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.views.generic import View
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import TokenGenerator, generate_token
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
from django.utils.encoding import force_str
from django.core.mail import EmailMessage
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import update_session_auth_hash
from . models import Support
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
from random import randint
from .models import OTPModel



# Create your views here.

@login_required()
@login_required()
def todo(request):
    if request.method == "POST":
        task = request.POST.get("task")
        new_todo = Todo(user=request.user, todo_name=task)
        new_todo.save()

        # Redirect after successful form submission
        return redirect('todo')

    all_todos = Todo.objects.filter(user=request.user)

    is_superuser = request.user.is_superuser

    session_timeout = settings.SESSION_COOKIE_AGE

    return render(request, 'todo.html', {'todos': all_todos, 'is_superuser': is_superuser,"session_timeout": session_timeout,'username' : request.user.username})

def send_reminder_email(receiver_email, todo_name,date):
    subject = "Todo Reminder"
    body = f"Your task '{todo_name}' on '{date}' is still in process. Please complete it!"
    sender_email = settings.EMAIL_HOST_USER

    send_mail(
        subject,
        body,
        sender_email,
        [receiver_email],
        fail_silently=False,
    )
    if sender_email:
        print("yes")
    else:
        print("no")


@login_required()
def send_reminder(request):
    if request.user.is_superuser:
        # Get all tasks that are still in progress
        in_progress_tasks = Todo.objects.filter(status=False)

        for task in in_progress_tasks:
            send_reminder_email(task.user.email, task.todo_name,task.date)

        messages.success(request, "Reminder emails sent successfully!")


    return redirect('todo')



def loginpage(request):
    if request.user.is_authenticated:
        return redirect('todo')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        validate_user = authenticate(username=username, password=password)
        if validate_user is not None:
            login(request, validate_user)
            return redirect('todo')
        else:
            messages.error(request, "invalid credentials")
            return redirect('login')

    return render(request, 'login.html')



def register(request):
    if request.user.is_authenticated:
        return redirect('todo')

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        cpassword = request.POST.get("cpassword")
        special_characters = {'[', ']', '{', '}', '(', ')', '/', '?', '.', ',', ';', ':', '|', '*', '~', '`',
                              '!', '^', '-', '_', '+', '<', '>', '@', '#', '$', '%', '&'}

        # Password constraints validation
        if len(password) < 8:
            messages.warning(request, "Password should be at least 8 characters")
            return redirect('register')
        if not any(char in special_characters for char in password):
            messages.warning(request, "Password should contain at least one special character.")
            return redirect('register')
        elif password != cpassword:
            messages.warning(request, "Passwords do not match.")
            return redirect('register')

        try:
            if User.objects.get(username=username):
                messages.warning(request, "UserName already taken")
                return redirect("register")
        except User.DoesNotExist:
            pass

        try:
            if User.objects.get(email=email):
                messages.warning(request, "Email already exists")
                return redirect("register")
        except User.DoesNotExist:
            pass

        user = User.objects.create_user(username, email, password)
        user.is_active = False
        user.save()

        email_subject = "Activate Your Account"
        message = render_to_string("activate.html", {
            "user": user,
            "domain": "127.0.0.1:8000",
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": generate_token.make_token(user)
        })

        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_message.send()

        messages.warning(request, "A confirmation email has been sent to your email.")
        return redirect('login')

    return render(request, 'register.html')


@login_required()
def deletetodo(request, id):
    deletetask = Todo.objects.get(user=request.user, id=id)
    deletetask.delete()
    return redirect("todo")

@login_required()
def deletetodofromcompletedlist(request, id):
    deletetask = Todo.objects.get(user=request.user, id=id)
    deletetask.delete()
    return redirect("completedlist")


@login_required()
def updatetodo(request, id):
    updatetask = Todo.objects.get(user=request.user, id=id)
    updatetask.status = True
    updatetask.save()
    return redirect("todo")


@login_required()
def logoutpage(request):
    logout(request)
    return redirect('login')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            return redirect("login")

        return render(request, "activatefail.html")




def index(request):

    return  render(request, "index.html")



def contactus(request):
    if request.method == "POST":
        username = request.POST.get("name")
        useremail = request.POST.get("email")
        subject = request.POST.get("subject")
        message = request.POST.get("message")
        contactus = Contactus(username=username, useremail=useremail, subject=subject, message=message)
        contactus.save()
    return render(request, "contactus.html")

def services(request):
    return render(request,"services.html",{'username' : request.user.username})

@login_required()
def changepassword(request):
    if request.method == "POST":
        oldpassword = request.POST.get("oldpassword")
        newpassword = request.POST.get("newpassword")
        cpassword = request.POST.get("cpassword")
        user = request.user
        password_matched = check_password(oldpassword,request.user.password)
        special_characters = {'[', ']', '{', '}', '(', ')', '/', '?', '.', ',', ';', ':', '|', '*', '~', '`',
                              '!', '^', '-', '_', '+', '<', '>', '@', '#', '$', '%', '&'}
        if password_matched:
         if newpassword == cpassword and oldpassword != newpassword:
            if len(newpassword) < 8:
                messages.warning(request, "Password should be at least 8 characters")
                return redirect('changepassword')

            if not any(char in special_characters for char in newpassword):

                messages.warning(request, "Password should contain at least one special character.")
                return redirect('changepassword')

            user.set_password(newpassword)
            user.save()
            # It's a good practice to update the session hash after changing the password
            update_session_auth_hash(request, user)

            messages.warning(request,"Successfully Changed")
            redirect('changepassword')
         else:

           messages.warning(request,"Unsuccessful check your inputs.")
           redirect('changepassword')
        else:
            messages.warning(request, "Old password not matched")
            redirect('changepassword')
    return render(request, "changepassword.html",{'username' : request.user.username})


@login_required()
def support(request):
    if request.method=="POST":
        username=request.user.username
        supporbax=request.POST.get("supportbox")
        supportaskeduser=Support(user=username,support=supporbax)
        supportaskeduser.save()

    return  render(request,"support.html",{'username': request.user.username})

@login_required()
def completedlist(request):
    all_todos = Todo.objects.filter(user=request.user)
    return render(request,"completedlist.html",{'todos': all_todos,})


def forgotpassword(request):
    if request.method == "POST":
        email = request.POST.get("email")
        check = User.objects.filter(email=email).exists()
        # Check if the email exists in the database
        if check:

            OTPModel.objects.create(email=email)

            # Send to the user's email
            email_subject = "Reset Your Account Password"
            message = render_to_string("passwordreset.html", {
                "domain": "127.0.0.1:8000",
            })

            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            email_message.send()

        else:
            messages.warning(request,"User does not exist")
            redirect('forgotpassword')




    return render(request, "forgotpassword.html")


def password_reset_page(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        special_characters = {'[', ']', '{', '}', '(', ')', '/', '?', '.', ',', ';', ':', '|', '*', '~', '`',
                              '!', '^', '-', '_', '+', '<', '>', '@', '#', '$', '%', '&'}

        user = User.objects.filter(username=username).first()

        if user:
            if password == confirm_password:
                if len(password) < 8:
                    messages.warning(request, "Password should be at least 8 characters")
                    return redirect('password_reset_pageuserpassword=?reset-page')

                if not any(char in special_characters for char in password):
                    messages.warning(request, "Password should contain at least one special character.")
                    return redirect('password_reset_pageuserpassword=?reset-page')

                user.set_password(password)
                user.save()
                # It's a good practice to update the session hash after changing the password
                update_session_auth_hash(request, user)

                messages.success(request, "Password changed successfully.")
                return redirect('login')
            else:
                messages.warning(request, "Passwords do not match.")
                return redirect('password_reset_pageuserpassword=?reset-page')
        else:
            messages.warning(request, "User not found.")
            return redirect('password_reset_pageuserpassword=?reset-page')

    return render(request, "password_reset_page.html")