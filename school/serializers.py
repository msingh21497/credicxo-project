from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from . import models, utils
from django.conf import settings
from django.db import transaction
from django.db.models import F, Sum
import json, os



class UserLoginSerializer(serializers.ModelSerializer):
	"""
	User Information after User login
	"""
	assigned_roles = serializers.SerializerMethodField()
	menu_list = serializers.SerializerMethodField()

	class Meta(object):
		model = models.User
		# fields = '__all__'
		include = ['assigned_roles', 'menu_list']
		exclude = ['password']

	def get_assigned_roles(self, obj):
		permissions = []
		role_list = models.UserRole.objects.filter(user_id=obj.id).annotate(
			roleid=F('role__id'),
			rolename=F('role__role_name')
		).values('roleid', 'rolename').distinct()
		for roles in role_list:
			permissions.append({'roleid': roles['roleid'],
								'rolename': roles['rolename']
								})
		return permissions

	def get_menu_list(self, obj):
		menu_list = []
		try:
			role = models.UserRole.objects.filter(user_id=obj.id).first()
		except:
			role = None
		if role:
			profile = models.Role.objects.filter(id=role.role_id).first()
			profile_id = profile.profile.id
		else:
			profile_id = 0
		file_name = 'profile_{}.json'.format(0)
		file_path = os.path.join(settings.BASE_DIR, 'fixtures', 'role_menu_profile', file_name)
		with open(file_path, 'r') as outfile:
			data = json.load(outfile)
			menu_list = data
		return menu_list


class UserGetSerializer(serializers.ModelSerializer):
	"""
	Serializer to return information of a particular User
	"""
	role_name = serializers.CharField(source='get_role_display')
	class Meta:
		model = models.User
		fields = ('username','role_name',)


class UserDetailSerializer(serializers.ModelSerializer):
	"""
	Serializer to return information of a particular User
	"""
	assigned_roles = serializers.SerializerMethodField()
	emp_name = serializers.ReadOnlyField(source='emp_ref.get_full_name', read_only=True)
	class Meta(object):
		model = models.User
		fields = ('id', 'emp_ref',  'emp_name', 'username', 'status', 'assigned_roles')

	def get_assigned_roles(self, obj):
		permissions = []
		role_list = models.UserRole.objects.filter(user_id=obj.id).annotate(
			roleid=F('role__id'),
			rolename=F('role__role_name')
		).values('roleid', 'rolename').distinct()
		for roles in role_list:
			permissions.append({'roleid': roles['roleid'],
								'rolename': roles['rolename']
								})
		return permissions


class UserPostSerializer(serializers.ModelSerializer):
	"""
	Serializer to create or update user data
	"""
	password = serializers.CharField(write_only=True)
	# selected_roles = serializers.CharField(allow_blank=True, allow_null=True, max_length=100, required=False)

	class Meta(object):
		model = models.User
		fields = '__all__'# ('emp_ref', 'username', 'status', 'password', 'selected_roles')

	@transaction.atomic
	def create(self, validated_data):
		# selected_roles_data = validated_data.pop('selected_roles')
		password = validated_data.pop('password')
		email = validated_data.pop('email')
		username = validated_data.pop('username')
		role = validated_data.pop('role')
		user_master = models.User.objects.create_user(username=username,email=email,role=role)
		user_master.set_password(password)
		user_master.save()
		return user_master

	@transaction.atomic
	def update(self, instance, validated_data):
		password = ''
		if 'password' in validated_data:
			password = validated_data.pop('password')

		user_master, created = models.User.objects.update_or_create(id=instance.id, defaults=validated_data)
		if password:
			user_master.set_password(password)
			user_master.save()
		return user_master






###### Password Reset 
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404 as _get_object_or_404
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from school.models import get_password_reset_token_expiry_time
from . import models

__all__ = [
    'EmailSerializer',
    'PasswordTokenSerializer',
    'ResetTokenSerializer',
]


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordValidateMixin:
    def validate(self, data):
        token = data.get('token')

        # get token validation time
        password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # find token
        try:
            reset_password_token = _get_object_or_404(models.ResetPasswordToken, key=token)
        except (TypeError, ValueError, ValidationError, Http404,
                models.ResetPasswordToken.DoesNotExist):
            raise Http404(_("The OTP password entered is not valid. Please check and try again."))

        # check expiry date
        expiry_date = reset_password_token.created_at + timedelta(
            hours=password_reset_token_validation_time)

        if timezone.now() > expiry_date:
            # delete expired token
            reset_password_token.delete()
            raise Http404(_("The token has expired"))
        return data


class PasswordTokenSerializer(PasswordValidateMixin, serializers.Serializer):
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'})
    token = serializers.CharField()


class ResetTokenSerializer(PasswordValidateMixin, serializers.Serializer):
    token = serializers.CharField()


