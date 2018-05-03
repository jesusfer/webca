"""
Validators for models in the web app.
"""
from django.core.exceptions import ValidationError
from OpenSSL import crypto

MAX_DAYS = 50 * 365


def power_two(value):
    """Check that the value is a power of two."""
    number = value
    while number > 1 and number % 2 == 0:
        number = number / 2
    if number != 1:
        raise ValidationError(
            '%(value)s is not a power of two',
            code='invalid-bits',
            params={'value': value},
        )


def valid_pem_csr(value):
    """A valid PEM-encoded CSR."""
    try:
        crypto.load_certificate_request(crypto.FILETYPE_PEM, value)
    except:
        raise ValidationError(
            'This is not a valid PEM-encoded certificate request',
            code='invalid-csr',
        )


def valid_pem_cer(value):
    """A valid PEM-encoded certificate."""
    try:
        crypto.load_certificate(crypto.FILETYPE_PEM, value)
    except:
        raise ValidationError(
            'This is not a valid PEM-encoded certificate',
            code='invalid-cer',
        )


def max_days(value):
    """Maximum certificate validity (70y)."""
    if value > MAX_DAYS:
        raise ValidationError(
            'The validity is beyond 70 years',
            code='invalid-days',
        )
