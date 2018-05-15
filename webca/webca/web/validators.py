"""
Validators for models in the web app.
"""
from django.core.exceptions import ValidationError
from OpenSSL import crypto

from webca.crypto import constants as c
from webca.crypto.utils import public_key_type, check_key_usage
from webca.web import models as web_models

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


def validate_csr_bits(value, min_bits):
    """Validate the PEM CSR has at least `min_bits`."""
    valid_pem_csr(value)
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, value)
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
    # FIXME: This should really be validated in the Template model
    if (c.KU_KEYCERTSIGN in key_usage and
            template.basic_constraints != web_models.Template.BC_CA):
        raise ValidationError(
            'Bad template (keyCertSign and !CA)',
            code='invalid-ca-template',
        )
    if (len(key_usage) > 1 and
            c.KU_CRLSIGN in key_usage and
            c.KU_KEYCERTSIGN not in key_usage):
        raise ValidationError(
            'Bad template (crlSign and !keyCertSign)',
            code='invalid-ca-template',
        )

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
