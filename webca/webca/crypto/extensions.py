import json

from OpenSSL import crypto

from webca.crypto.constants import EXT_KEY_USAGE, KEY_USAGE

# Classes


def _create_method(name):
    def method(self):
        self._add(name)
        return self
    return method


def _extend_class(cls, lst):
    for name in lst:
        m = _create_method(name)
        setattr(cls, name, m)


class MultiValueExtension(object):
    """A X509 extension that can have several values."""

    def __init__(self, *args, **kwargs):
        self._value = ''

    def _add(self, usage):
        if not self._value:
            self._value = usage
        else:
            self._value += ',' + usage

    def value(self):
        """Return the value as a comma separated string."""
        return self._value

    def values(self):
        """Return the value a a list of values."""
        return self._value.split(',')

    def from_list(self, values):
        """Build from a comma separated string."""
        for value in values.split(','):
            self._add(value)
        return self

class KeyUsage(MultiValueExtension):
    """The keyUsage extension.

    Build the object by calling KeyUsage().<usage>().<usage>().

    methods - digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
    keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
    """

    #pylint: disable=e1101
    @staticmethod
    def from_extension(extension):
        """Build an object from a cryptography.x509.Extension."""
        if extension.oid.dotted_string != '2.5.29.15':
            raise ValueError('extension')
        usage = KeyUsage()
        if extension.value.digital_signature:
            usage = usage.digitalSignature()
        if extension.value.content_commitment:
            usage = usage.nonRepudiation()
        if extension.value.key_encipherment:
            usage = usage.keyEncipherment()
        if extension.value.data_encipherment:
            usage = usage.dataEncipherment()
        if extension.value.key_agreement:
            usage = usage.keyAgreement()
            # For these to work, key_agreement must be True
            if extension.value.encipher_only:
                usage = usage.encipherOnly()
            if extension.value.decipher_only:
                usage = usage.decipherOnly()
        if extension.value.key_cert_sign:
            usage = usage.keyCertSign()
        if extension.value.crl_sign:
            usage = usage.cRLSign()
        return usage


_extend_class(KeyUsage, KEY_USAGE.values())


class ExtendedKeyUsage(MultiValueExtension):
    """The extendedKeyUsage extension.

    Build the object by calling ExtendedKeyUsage().<usage>().<usage>().

    methods - serverAuth, clientAuth, codeSigning, emailProtection,
    timeStamping, OCSPSigning, ipsecIKE,
    msCodeInd, msCodeCom, msCTLSign, msEFS
    """
    @staticmethod
    def from_extension(extension):
        """Build an object from a cryptography.x509.Extension."""
        if extension.oid.dotted_string != '2.5.29.37':
            raise ValueError('extension')
        eku = ExtendedKeyUsage()
        for oid in extension.value:
            eku = getattr(eku, oid._name)()
        return eku


_extend_class(ExtendedKeyUsage, EXT_KEY_USAGE.values())


def get_certificate_extension(certificate, name):
    ext = None
    for x in range(0, certificate.get_extension_count()):
        e = certificate.get_extension(x)
        if name == e.get_short_name():
            ext = e
            break
    return ext


def get_extension(certificate, name):
    """Returns a cryptography.x509.Extension."""
    ext = None
    c = certificate.to_cryptography()
    for e in c.extensions:
        if e.oid._name == name:
            ext = e
            break
    return ext


def _as_extension(dct):
    """Build an extension from a dictionary.
    {"name":"basicConstraints", "critical":true, "value":"CA:FALSE"}
    """
    name = dct['name'].encode('ascii')
    crit = dct['critical']
    value = dct['value'].encode('ascii')
    return crypto.X509Extension(name, crit, value)


def json_to_extension(json_input):
    obj = json.loads(json_input, encoding='utf-8', object_hook=_as_extension)
    return obj


def build_san(names, critical=False):
    """Return a SubjectAlternativeName OpenSSL.crypto.X509Extension."""
    san = {
        'name': 'subjectAltName',
        'critical': critical,
        'value': names,
    }
    return _as_extension(san)


def build_cdp(locations, critical=False):
    """Return a CRLDistributionPoints OpenSSL.crypto.X509Extension."""
    value = ['URI:%s' % l for l in locations]
    crl = {
        'name': 'crlDistributionPoints',
        'critical': critical,
        'value': ','.join(value),
    }
    return _as_extension(crl)
