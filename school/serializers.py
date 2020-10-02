from rest_framework.serializers import ModelSerializer
from rest_framework import serializers, fields
from django.contrib.auth.models import User


class User_Serializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id','first_name','username','password']
        # fields = '__all__'