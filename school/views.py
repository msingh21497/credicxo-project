from django.shortcuts import render


def Login(request):
    return render(request,'login.html')


def RegistrationForm(request):
    return render(request,'registration-form.html')

def Dashbord(request):
    return render(request,'dashbord.html')

def AllUser(request):
    return render(request,'all-user.html')

def Teacher(request):
    return render(request,'teacher.html')


def Student(request):
    return render(request,'student.html')