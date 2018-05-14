"""
Helper functions.
"""
import secrets
from datetime import datetime

import pytz
from OpenSSL import crypto

from webca.crypto.constants import SERIAL_BYTES

#################
# ASN.1 helpers #
#################


def new_serial():
    """Return a large positive integer."""
    return abs(secrets.randbits(SERIAL_BYTES * 8))


def int_to_hex(number):
    """Convert an int into a hex string."""
    # number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')
    hex_string = '%x' % number
    return hex_string


def name_to_components(name):
    """Converts a name to a list of components.

    Arguments:
        name - Name in the format /name1=value1/name2=value2/..
    Returns: list of (name, value) tuples
    """
    ret = []
    components = [x for x in name.split('/') if x]
    components = [x.split('=') for x in components]
    components = [x for x in components if len(x) == 2]
    for key, value in components:
        ret.append(
            (key, value)
        )
    return ret


def components_to_name(components):
    """Builds an OpenSSL subject name.

    Arguments:
        components - list of (b'name', b'value') or ('name', 'value')
    """
    subject = ''
    decode = getattr(components[0][0], 'decode', None)
    for name, value in components:
        if decode:
            subject += "/%s=%s" % (name.decode('utf-8'), value.decode('utf-8'))
        else:
            subject += "/%s=%s" % (name, value)
    return subject


ASN1_FMT = '%Y%m%d%H%M%S'


def datetime_to_asn1(when=datetime.utcnow()):
    """Convert a datetime into a byte string ASN.1 format YYYYMMDDhhmmssZ."""
    fmt = ASN1_FMT
    if when.tzinfo == pytz.utc or when.tzname() is None:
        fmt += 'Z'
    else:
        fmt += '%z'
    return when.strftime(fmt).encode('ascii')


def asn1_to_datetime(when):
    """Convert a ASN.1 datetime to datetime offset-aware object."""
    when = when[0:-1] + '+0000'
    datetime_object = datetime.strptime(when, ASN1_FMT + '%z')
    return datetime_object

################
# X509 helpers #
################


##################
# Output helpers #
##################


def export_certificate(certificate, pem=True, text=False):
    """Exports a X509 certificate in PEM format."""
    if text:
        return crypto.dump_certificate(crypto.FILETYPE_TEXT, certificate).decode('utf-8')
    if pem:
        return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode('utf-8')
    return crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)


def export_private_key(key):
    """Exports a private key in PEM format."""
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')


def export_public_key(key):
    """Exports a public key in PEM format."""
    return crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8')


def export_crl(crl, text=False):
    """Exports a CRL in PEM format."""
    if text:
        return crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode('utf-8')
    return crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode('utf-8')


def export_csr(csr, text=False):
    """Export a CSR as text."""
    if text:
        return crypto.dump_certificate_request(crypto.FILETYPE_TEXT, csr).decode('utf-8')
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode('utf-8')


def import_csr(csr):
    """Import a PEM CSR to a OpenSSL.crypto.X509Req."""
    return crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)


def print_certificate(certificate):
    print(crypto.dump_certificate(
        crypto.FILETYPE_TEXT, certificate).decode('utf-8'))


def print_crl(crl):
    print(crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode('utf-8'))
