from django.shortcuts import render
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.http import Http404
from django.conf import settings
from school.serializers import *
from school.constants import *
from school.models import *
from school.utils import *

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User

from django.http import HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext as _
from django.template.response import TemplateResponse
from rest_framework import permissions
from django.conf import settings
import requests, json
from django.db.models import Q, Count, Sum
import datetime, os
from django.dispatch import receiver

from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password, get_password_validators
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from rest_framework import status, exceptions
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response


from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User




def LoginPage(request):
    return render(request,'login.html')


class LoginApi(APIView):
    # permission_classes = (AllowAny,)
    """
	User Login API
	:param request: {'username': 'XYZ_987', 'password': '123456'}
	An internal call to /api/token/ is sent to get access token which is then returned as response
	response: access token of JWT auth with user basic information
	"""
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        try:
            usr = User.objects.get(username__iexact=username)
        except User.DoesNotExist:
            return response({'error':LOGIN_ERROR, 'message':USER_DOES_NOT_EXIST,
            "error_code":USERNAME_ERROR}, status.HTTP_400_BAD_REQUEST)
        serializer = UserLoginSerializer(usr)
        if serializer.is_valid:
            if usr.is_active:
                if usr.check_password(password):
                    data = {'username':username,'password':password,'email':username}
                    response = requests.post(settings.BASE_URL + '/api/token', data=data)
                    access_token = response.json()
                    bearer_token = access_token['access']
                    headers = {"Authorization": "Bearer" + bearer_token}
                    return response({'usr':data,'tokens':access_token},headers=headers)
                return response({'error':LOGIN_ERROR,'message':ENTER_CORRECT_PASSWORD,
                'error_code':PASSWORD_ERROR}, status=HTTP_400_BAD_REQUEST)
        else:
            return response({'message':"error"}, status=HTTP_400_BAD_REQUEST)




def RegistrationForm(request):
    return render(request,'registration-form.html')

def Dashbord(request):
    return render(request,'dashbord.html')


def AllUserPage(request):
    return render(request,'all-user.html')



class CreateUser(APIView):

    def get(self, request):
        try:
            usr = User.objects.all()
        except User.DoesNotExist:
            return Response({'data':NO_RECORD_FOUND})
        serializer = User_Serializer(usr, many=True,)
        return Response({'data':serializer.data,'status' : status.HTTP_200_OK})

    def post(self, request):
        try:
            temp = User.objects.get(email__iexact=request.data.get('email'))
            if temp:
                return Response({"error":EMAIL_ALREADY_TAKEN, "message": "error"},status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            serializer = User_Serializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": SUCCESSFULLY_CREATED}, status.HTTP_201_CREATED)
            return Response({"message": ENTER_VALID_DATA}, status.HTTP_400_BAD_REQUEST)

class UserSerializerRetrieveUpdateDelete(APIView):

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        usr = self.get_object(pk)
        serializer = User_Serializer(usr)
        return Response({'result' :serializer.data, 'status' : status.HTTP_200_OK})

    def put(self, request, pk):
        usr = self.get_object(pk)
        serializer = User_Serializer(usr, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": SUCCESSFULLY_UPDATED}, status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        usr = self.get_object(pk)
        usr.delete()
        return Response({"message": SUCCESSFULLY_CREATED}, status.HTTP_204_NO_CONTENT)



class StudentList(APIView):
	"""
	API to create User and get User list
	GET method is passed to get list of User
	POST method is passed to create a new User
	"""
	# permission_classes = (IsAuthenticated,)
	def get(self, request):
		try:
			user_master_list = models.User.objects.filter(username=request.user.username,role=3,is_deleted=False).all().order_by('-id')
		except models.User.DoesNotExist:
			return Response({'result':'No Record Found'})
		serializer = serializers.UserGetSerializer(user_master_list, many=True)
		return Response({'result':serializer.data})

class TeacherList(APIView):
	"""
	API to create User and get User list
	GET method is passed to get list of User
	POST method is passed to create a new User
	"""
	# permission_classes = (IsAuthenticated,)
	def get(self, request):
		try:
			user_master_list = models.User.objects.filter(role=3,is_deleted=False).all().order_by('-id')
		except models.User.DoesNotExist:
			return Response({'result':'No Record Found'})
		serializer = serializers.UserGetSerializer(user_master_list, many=True)
		return Response({'result':serializer.data})


########## Password Reset 


from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password, get_password_validators
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from rest_framework import status, exceptions
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from school.serializers import EmailSerializer, PasswordTokenSerializer, ResetTokenSerializer
from school.models import ResetPasswordToken, clear_expired, get_password_reset_token_expiry_time, \
    get_password_reset_lookup_field
from school.signals import reset_password_token_created, pre_password_reset, post_password_reset

User = get_user_model()

__all__ = [
    'ResetPasswordValidateToken',
    'ResetPasswordConfirm',
    'ResetPasswordRequestToken',
    # 'reset_password_validate_token',
    # 'reset_password_confirm',
    # 'reset_password_request_token'
]

HTTP_USER_AGENT_HEADER = getattr(settings, 'DJANGO_REST_PASSWORDRESET_HTTP_USER_AGENT_HEADER', 'HTTP_USER_AGENT')
HTTP_IP_ADDRESS_HEADER = getattr(settings, 'DJANGO_REST_PASSWORDRESET_IP_ADDRESS_HEADER', 'REMOTE_ADDR')


class ResetPasswordValidateToken(GenericAPIView):
    """
    An Api View which provides a method to verify that a token is valid
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = ResetTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'status': 'OK'})


class ResetPasswordConfirm(GenericAPIView):
    """
    An Api View which provides a method to reset a password based on a unique token
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = PasswordTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        token = serializer.validated_data['token']

        # find token
        reset_password_token = ResetPasswordToken.objects.filter(key=token).first()

        # change users password (if we got to this code it means that the user is_active)
        if reset_password_token.user.eligible_for_reset():
            pre_password_reset.send(sender=self.__class__, user=reset_password_token.user)
            try:
                # validate the password against existing validators
                validate_password(
                    password,
                    user=reset_password_token.user,
                    password_validators=get_password_validators(settings.AUTH_PASSWORD_VALIDATORS)
                )
            except ValidationError as e:
                # raise a validation error for the serializer
                raise exceptions.ValidationError({
                    'password': e.messages
                })

            reset_password_token.user.set_password(password)
            reset_password_token.user.save()
            post_password_reset.send(sender=self.__class__, user=reset_password_token.user)

        # Delete all password reset tokens for this user
        ResetPasswordToken.objects.filter(user=reset_password_token.user).delete()

        return Response({'status': 'OK'})


class ResetPasswordRequestToken(GenericAPIView):
    """
    An Api View which provides a method to request a password reset token based on an e-mail address

    Sends a signal reset_password_token_created when a reset token was created
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = EmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        # before we continue, delete all existing expired tokens
        password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # datetime.now minus expiry hours
        now_minus_expiry_time = timezone.now() - timedelta(hours=password_reset_token_validation_time)

        # delete all tokens where created_at < now - 24 hours
        clear_expired(now_minus_expiry_time)

        # find a user by email address (case insensitive search)
        users = User.objects.filter(**{'{}__iexact'.format(get_password_reset_lookup_field()): email})

        active_user_found = False

        # iterate over all users and check if there is any user that is active
        # also check whether the password can be changed (is useable), as there could be users that are not allowed
        # to change their password (e.g., LDAP user)
        for user in users:
            if user.eligible_for_reset():
                active_user_found = True

        # No active user found, raise a validation error
        # but not if DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE == True
        if not active_user_found and not getattr(settings, 'DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE', False):
            raise exceptions.ValidationError({
                'email': [_(
                    "We couldn't find an account associated with that email. Please try a different e-mail address.")],
            })

        # last but not least: iterate over all users that are active and can change their password
        # and create a Reset Password Token and send a signal with the created token
        for user in users:
            if user.eligible_for_reset():
                # define the token as none for now
                token = None

                # check if the user already has a token
                if user.password_reset_tokens.all().count() > 0:
                    # yes, already has a token, re-use this token
                    token = user.password_reset_tokens.all()[0]
                else:
                    # no token exists, generate a new token
                    token = ResetPasswordToken.objects.create(
                        user=user,
                        user_agent=request.META.get(HTTP_USER_AGENT_HEADER, ''),
                        ip_address=request.META.get(HTTP_IP_ADDRESS_HEADER, ''),
                    )
                # send a signal that the password token was created
                # let whoever receives this signal handle sending the email for the password reset
                reset_password_token_created.send(sender=self.__class__, instance=self, reset_password_token=token)
        # done
        return Response({'status': 'OK'})



def Teacher(request):
    return render(request,'teacher.html')


def Student(request):
    return render(request,'student.html')