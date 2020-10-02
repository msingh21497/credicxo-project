from django.shortcuts import render
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.http import Http404
from django.conf import settings
from .serializers import *
from .constants import *

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
    # renderer_classes = [TemplateHTMLRenderer]
    # template_name = 'all-user.html'

    # def get(self, request):
    #     usr = User.objects.all()
    #     return Response({'usr': usr})
    # permission_classes = (IsAuthenticated,)

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

def Teacher(request):
    return render(request,'teacher.html')


def Student(request):
    return render(request,'student.html')