"""
Custom template tags and filters.
"""
from datetime import datetime

import pytz
from django import template
from django.utils.safestring import SafeText

from webca.crypto.utils import components_to_name, int_to_hex
from webca.utils import subject_display

register = template.Library()


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
    return ''
