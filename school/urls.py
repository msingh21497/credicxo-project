from django.contrib import admin
from django.urls import path
from school.views import *

urlpatterns = [
    path('', Dashbord,name='dashbord'),
    path('login/', Login,name='login'),
    path('register/', RegistrationForm,name='register'),
    path('all-user/', AllUser,name='all-user'),
    path('teacher/', Teacher,name='teacher'),
    path('student/', Student,name='student'),
]