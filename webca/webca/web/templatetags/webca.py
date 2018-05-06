"""
Custom template tags and filters.
"""
from django import template
from django.utils.safestring import SafeText
register = template.Library()

@register.filter
def required(value): # Only one argument.
    """Add the required attribute to an input element."""
    html = str(value)
    if html and html.startswith('<input '):
        html = html.replace('<input ', '<input required ')
    return SafeText(html)
