"""
Custom template tags and filters.
"""
from django import template
from django.utils.safestring import SafeText

from webca.crypto.utils import components_to_name, int_to_hex
from webca.utils import subject_display

register = template.Library()


@register.filter
def subject(x509):
    """Return the subject of the certificate."""
    subject = components_to_name(x509.get_subject().get_components())
    return subject_display(subject).replace('/', ' ').strip()


@register.filter
def serial(x509):
    """Return the serial of the certificate."""
    return int_to_hex(x509.get_serial_number())
