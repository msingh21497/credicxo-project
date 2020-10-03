#-*- coding: utf-8 -*-
from django.contrib.auth.models import UserManager


class CustomUserManager(UserManager):
    """
     This class is necessary to create if using custom user model is desired
    """

    def _create_user(self, username, password,
                     is_staff, is_superuser, **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """

        # email = self.normalize_email(email)
        # extra_fields['username'] = extra_fields['username'] if extra_fields.get('username') else email
        user = self.model(username=username, is_staff=is_staff, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, *args, **kwargs):
        """
        :param args:
        :param kwargs:
        :return: creates a super user
        """
        u = self.create_user(kwargs['username'], password=kwargs['password'])
        u.username = kwargs['username']
        u.is_staff = True
        u.save(using=self._db)
        return u

    def create_user(self, username, password=None, **extra_fields):
        return self._create_user(username, password, False, False, **extra_fields)