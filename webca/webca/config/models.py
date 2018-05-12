"""Models for the config application."""
import uuid

from django.db import models


def gen_uuid():
    """Return a uuid4 as string."""
    return uuid.uuid4().hex


class ConfigurationObject(models.Model):
    """A generic configuration object."""
    name = models.CharField(
        max_length=100,
        unique=True,
        default=gen_uuid,
        help_text='Name of this object',
    )
    value = models.TextField(
        help_text='Value of this object',
    )

    class Meta:
        verbose_name = 'Parameter'

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Config %s>' % str(self)

    def trim_value(self):
        """Trim the value of the object for displaying."""
        return self.value[0:60] + '...'
    trim_value.short_description = 'Value'

    @staticmethod
    def get_value(name):
        """Return the value of an object or None if it doesn't exist."""
        obj = ConfigurationObject.objects.filter(name=name).first()
        if obj:
            return obj.value
        return None

    @staticmethod
    def set_value(name, value):
        """Set the `value` of parameter with `name`"""
        obj = ConfigurationObject.objects.filter(name=name).first()
        if obj:
            obj.value = value
            obj.save()
        else:
            obj = ConfigurationObject(name=name, value=value)
            obj.save()
        return obj
