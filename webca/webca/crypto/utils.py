"""
Helper functions.
"""
import secrets
from datetime import datetime

import pytz
from OpenSSL import crypto

SERIAL_BYTES = 19  # Max allowed serial number is < 20

#################
# ASN.1 helpers #
#################


def new_serial():
    """Return a large positive integer."""
    return abs(secrets.randbits(SERIAL_BYTES * 8))


def serial_int_to_bytes(x):
    """Convert an int into a hex-byte-string."""
    # x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    s = '%x' % x
    return s.encode('ascii')


ASN1_FMT = '%Y%m%d%H%M%S'


def datetime_to_asn1(when=datetime.utcnow()):
    """Convert a datetime into a byte string ASN.1 format YYYYMMDDhhmmssZ."""
    fmt = ASN1_FMT
    if when.tzinfo == pytz.utc or when.tzname() == None:
        fmt += 'Z'
    else:
        fmt += '%z'
    return when.strftime(fmt).encode('ascii')


def asn1_to_datetime(when):
    """Convert a ASN.1 datetime to datetime object."""
    when = when[0:-1] + '+0000'
    datetime_object = datetime.strptime(when, ASN1_FMT + '%z')
    return datetime_object

################
# X509 helpers #
################


##################
# Output helpers #
##################


def export_certificate(certificate):
    """Exports a X509 certificate in PEM format."""
    return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode('utf-8')


def export_private_key(key):
    """Exports a private key in PEM format."""
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')


def export_public_key(key):
    """Exports a public key in PEM format."""
    return crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8')


def export_crl(crl):
    """Exports a CRL in PEM format."""
    return crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode('utf-8')


def print_certificate(certificate):
    print(crypto.dump_certificate(
        crypto.FILETYPE_TEXT, certificate).decode('utf-8'))


def print_crl(crl):
    print(crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode('utf-8'))
