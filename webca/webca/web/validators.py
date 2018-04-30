from django.core.exceptions import ValidationError
import math

from OpenSSL import crypto


def power_two(value):
    s = value
    while s > 1 and s % 2 == 0:
        s = s / 2
    if s != 1:
        raise ValidationError(
            '%(value)s is not a power of two',
            code='invalid',
            params={'value': value},
        )


def valid_pem_csr(value):
    try:
        crypto.load_certificate_request(crypto.FILETYPE_PEM, value)
    except:
        raise ValidationError(
            'This is not a valid PEM-encoded certificate request',
            code='invalid',
        )

def valid_pem_cer(value):
    try:
        crypto.load_certificate(crypto.FILETYPE_PEM, value)
    except:
        raise ValidationError(
            'This is not a valid PEM-encoded certificate',
            code='invalid',
        )
