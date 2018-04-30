"""Admin configuration for config."""
from django.contrib import admin

from webca.config.models import ConfigurationObject


class ConfigAdmin(admin.ModelAdmin):
    """Admin model for ConfigurationObject."""
    list_display = ['name', 'trim_value']


admin.site.register(ConfigurationObject, ConfigAdmin)
