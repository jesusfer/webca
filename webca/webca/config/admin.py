"""Admin configuration for config."""
from django.contrib import admin

from webca.ca_admin.admin import admin_site
from webca.config.models import ConfigurationObject


@admin.register(ConfigurationObject, site=admin_site)
class ConfigAdmin(admin.ModelAdmin):
    """Admin model for ConfigurationObject."""
    list_display = ['name', 'trim_value']
