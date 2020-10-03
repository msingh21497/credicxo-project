from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from school.views import LoginApi,StudentList,TeacherList,CreateUser,UserSerializerRetrieveUpdateDelete,ResetPasswordValidateToken,ResetPasswordConfirm,ResetPasswordRequestToken
from .views import *

urlpatterns = [
    path('api/login/', LoginApi.as_view(),name='api-all-login'),

    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),

    path('api/student/dd/list/', StudentList.as_view(), name='student-list'),
	path('api/teacher/dd/list/', TeacherList.as_view(), name='teacher-list'),
	
    path('api/create/user/', CreateUser.as_view(),name='api-create-user'),
    path('api/all-user/detail/<int:pk>/', UserSerializerRetrieveUpdateDelete.as_view(),name='api-all-user-update-delete'),

	############ Reset Password 

	path('validate_token/', ResetPasswordValidateToken.as_view(), name="reset-password-validate"),
    path('reset-password-confirm/', ResetPasswordConfirm.as_view(), name="reset-password-confirm"),
    path('reset-password-request/', ResetPasswordRequestToken.as_view(), name="reset-password-request"),
    #############

]