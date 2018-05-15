"""
Validators for models in the web app.
"""
from django.core.exceptions import ValidationError
from OpenSSL import crypto

from webca.crypto import constants as c
from webca.crypto.utils import check_key_usage, import_csr, public_key_type
from webca.web import models as web_models

MAX_DAYS = 50 * 365


def valid_key_size_number(number):
    """Check that the value is divisible by 32."""
    if number % 32:
        raise ValidationError(
            '%(value)s is not divisible by 32',
            code='invalid-bits',
            params={'value': number},
        )


def valid_pem_csr(value):
    """A valid PEM-encoded CSR."""
    try:
        import_csr(value)
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


def validate_csr_bits(value, min_bits):
    """Validate the PEM CSR has at least `min_bits`."""
    csr = import_csr(value)
    req_size = csr.get_pubkey().bits()
    if req_size < min_bits:
        raise ValidationError(
            'The public key size is not valid: %(size)s (min required:%(min)s)',
            code='invalid-key-size',
            params={'size': req_size, 'min': min_bits},
        )


def validate_csr_key_usage(value, template):
    """Validate that the key usage required by the template matches
    the public key type/algorithm of the request.

    Arguments
    ---------
    `value` - CSR as a PEM str
    `template` template to validate against

    Follows
    -------
    https://tools.ietf.org/html/rfc3279#section-2.3.5
    https://tools.ietf.org/html/rfc5480
    """
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, value)
    key_usage = [number
                 for number, name in c.KEY_USAGE.items()
                 if name in template.key_usage]

    key_type = public_key_type(csr)
    # Any type is good for digitalSignature nonRepudiation

    is_ca = template.basic_constraints == web_models.Template.BC_CA
    valid = check_key_usage(key_type, key_usage, is_ca)
    if not valid:
        raise ValidationError(
            'The algorithm used in the public key is not valid '
            'for this type of template',
            code='invalid-key-algorithm',
            params={},
        )


def max_days(value):
    """Maximum certificate validity (70y)."""
    if value > MAX_DAYS:
        raise ValidationError(
            'The validity is beyond 70 years',
            code='invalid-days',
        )


def valid_pathlen(value):
    """Make sure `value` is in the range -1 <= `value` < 32767. """
    if value < -1 or value > 32767:
        raise ValidationError(
            'The value must be -1 <= pathlen < 32767',
            code='invalid-pathlen',
        )
