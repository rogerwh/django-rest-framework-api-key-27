from django.contrib import admin, messages
from django.db import models
from django.http.request import HttpRequest

from .models import AbstractAPIKey, APIKey


class APIKeyModelAdmin(admin.ModelAdmin):
    # model = AbstractAPIKey

    list_display = (
        "prefix",
        "name",
        "created",
        "expiry_date",
        "_has_expired",
        "revoked",
    )
    list_filter = ("created",)
    search_fields = ("name", "prefix")

    def get_readonly_fields(self, request, obj=None):
        """
        :type request: AbstractAPIKey
        :type obj: models.Model
        :return: tuple(str, ...)
        """
        # obj = typing.cast(AbstractAPIKey, obj)
        # fields: typing.Tuple[str, ...]

        fields = ("prefix",)
        if obj is not None and obj.revoked:
            fields = fields + ("name", "revoked", "expiry_date")

        return fields

    def save_model(self, request, obj, form=None, change=False):
        """
        :type request: HttpRequest
        :type obj: AbstractAPIKey
        :type form: Any or None
        :type change: bool
        :return: None
        """

        created = not obj.pk

        if created:
            key = self.model.objects.assign_key(obj)
            obj.save()
            message = (
                "The API key for {} is: {}. ".format(obj.name, key)
                + "Please store it somewhere safe: "
                + "you will not be able to see it again."
            )
            messages.add_message(request, messages.WARNING, message)
        else:
            obj.save()


admin.site.register(APIKey, APIKeyModelAdmin)
