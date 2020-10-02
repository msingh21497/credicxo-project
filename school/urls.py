from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from school.views import LoginApi
from school.views import *

urlpatterns = [
    path('', Dashbord,name='dashbord'),
    path('login/',LoginPage, name='login'),
    path('api/login/', LoginApi.as_view(),name='api-all-login'),

    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    
    path('register/', RegistrationForm,name='register'),
    
    path('all-user/', AllUserPage,name='all-user'),
    
    path('api/create/user/', CreateUser.as_view(),name='api-create-user'),
    path('api/all-user/detail/<int:pk>/', UserSerializerRetrieveUpdateDelete.as_view(),name='api-all-user-update-delete'),

    path('teacher/', Teacher,name='teacher'),
    path('student/', Student,name='student'),
]