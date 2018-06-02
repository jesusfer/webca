"""
Custom template tags and filters.
"""
from datetime import datetime

import pytz
from django import template
from django.contrib.admin.utils import display_for_value

from webca.crypto.utils import components_to_name, int_to_hex
from webca.utils import subject_display

register = template.Library()


@register.filter
def sort_apps(app_list):
    """Sort the apps in the admin site"""
    app_idx = dict()
    app_names = []
    for idx, app in enumerate(app_list):
        app_idx[app['app_label']] = idx
        app_names.append(app['app_label'])

    new_list = []

    if 'auth' in app_names:
        app_names.remove('auth')
        idx = app_idx['auth']
        new_list.append(app_list[idx])
    if 'web' in app_idx.keys():
        app_names.remove('web')
        idx = app_idx['web']
        new_list.append(app_list[idx])
    for name in app_names:
        idx = app_idx[name]
        new_list.append(app_list[idx])

    return new_list

@register.filter
def subject(x509):
    """Return the subject of the certificate."""
    value = components_to_name(x509.get_subject().get_components())
    return subject_display(value).replace('/', ' ').strip()


@register.filter
def serial(x509):
    """Return the serial of the certificate."""
    return int_to_hex(x509.get_serial_number())


@register.filter
def selected(value, target):
    """Return 'selected' if `value` equals `target`."""
    if value == target:
        return 'selected'
    return ''


@register.filter
def active(value, target):
    """Return ' (active)' if `value` equals `target`."""
    if value == target:
        return ' (active)'
    return ''


@register.filter
def from_timestamp(value):
    """Transform a timestamp in a tz-aware datetime."""
    if isinstance(value, int) or isinstance(value, float):
        return datetime.fromtimestamp(value, pytz.utc)
    return None

@register.filter
def boolean_icon(value):
    """Show the Django admin boolean icon."""
    return display_for_value(value, '', True)

@register.filter
def concat(str1, str2):
    """Concat two string."""
    return str1 + str2
