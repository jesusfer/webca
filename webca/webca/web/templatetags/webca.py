"""
Custom template tags and filters.
"""
from datetime import timedelta

from django import template
from django.utils import timezone
from django.utils.safestring import SafeText

from webca.crypto.utils import components_to_name, int_to_hex
from webca.utils import subject_display

register = template.Library()


@register.filter
def required(value):  # Only one argument.
    """Add the required attribute to an input element."""
    html = str(value)
    if html and html.startswith('<input '):
        html = html.replace('<input ', '<input required ')
    return SafeText(html)


@register.filter
def approval(value):
    """Return the approval status of a request."""
    if value is None:
        return 'Pending'
    if value:
        return 'Approved'
    return 'Denied'


@register.filter
def valid_for(days):
    """Return a text saying for how many days
    the certificate is valid for or years if it spans over years."""
    delta = timedelta(days=days)
    value = ''
    if delta.days / 365 > 1:
        value += '%d years' % (delta.days / 365)
    else:
        value += '%d days' % delta.days
    return value


@register.filter
def valid_until(days):
    """Return a date that is `days` in the future."""
    future = timezone.now() + timedelta(days=days)
    return future


@register.filter
def status(cert):
    """Return a string with the status of the certificate."""
    value = 'Valid'
    if cert.is_revoked:
        value = 'Revoked'
    elif cert.is_expired:
        value = 'Expired'
    return value
