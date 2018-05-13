"""
Custom template tags and filters.
"""
from datetime import timedelta
from django import template
from django.utils.safestring import SafeText
from django.utils import timezone
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
