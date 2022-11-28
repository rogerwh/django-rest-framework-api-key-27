
from django.conf import settings
from django.http import HttpRequest
from rest_framework import permissions

from .models import AbstractAPIKey, APIKey


class KeyParser:
    keyword = "Api-Key"

    def get(self, request):
        """
        :type request: django.http.HttpRequest
        :return: str or None
        """
        custom_header = getattr(settings, "API_KEY_CUSTOM_HEADER", None)

        if custom_header is not None:
            return self.get_from_header(request, custom_header)

        return self.get_from_authorization(request)

    def get_from_authorization(self, request):
        """
        :type request: django.http.HttpRequest
        :return: str or None
        """
        authorization = request.META.get("HTTP_AUTHORIZATION")

        if not authorization:
            return None

        try:
            _, key = authorization.split("{} ".format(self.keyword))
        except ValueError:
            key = None

        return key

    def get_from_header(self, request, name):
        """
        :type request: django.http.HttpRequest
        :type name: str
        :return: str or None
        """
        return request.META.get(name) or None


class BaseHasAPIKey(permissions.BasePermission):
    model = None  # AbstractAPIKey
    key_parser = KeyParser()

    def get_key(self, request):
        """
        :type request: django.http.HttpRequest
        :return: str or None
        """
        return self.key_parser.get(request)

    def has_permission(self, request, view):
        """
        :type request: django.http.HttpRequest
        :type view: Any
        :return: bool
        """
        assert self.model is not None, (
            "%s must define `.model` with the API key model to use"
            % self.__class__.__name__
        )
        key = self.get_key(request)
        if not key:
            return False
        return self.model.objects.is_valid(key)

    def has_object_permission(self, request, view, obj):
        """
        :type request: django.http.HttpRequest
        :type view: Any
        :type obj: 'AbstractAPIKey'
        :return: bool
        """
        return self.has_permission(request, view)


class HasAPIKey(BaseHasAPIKey):
    model = APIKey


class HasAPIAccess(permissions.BasePermission):
    message = 'Invalid or missing API Key.'

    def has_permission(self, request, view):
        api_key = request.META.get('HTTP_API_KEY', '')
        return APIKey.objects.filter(key=api_key).exists()
