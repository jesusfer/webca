import json

from OpenSSL import crypto

from webca.crypto.constants import KEY_USAGE, EXT_KEY_USAGE

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
    def __init__(self, *args, **kwargs):
        self._value = ''

    def _add(self, usage):
        if len(self._value) == 0:
            self._value = usage
        else:
            self._value += ',' + usage

    def value(self):
        return self._value

    def values(self):
        return self._value.split(',')


class KeyUsage(MultiValueExtension):
    @staticmethod
    def from_extension(extension):
        """Build an object from a cryptography.x509.Extension."""
        if extension.oid.dotted_string != '2.5.29.15':
            raise ValueError('extension')
        e = extension.value
        ku = KeyUsage()
        if e.digital_signature:
            ku = ku.digitalSignature()
        if e.content_commitment:
            ku = ku.nonRepudiation()
        if e.key_encipherment:
            ku = ku.keyEncipherment()
        if e.data_encipherment:
            ku = ku.dataEncipherment()
        if e.key_agreement:
            ku = ku.keyAgreement()
            # For these to work, key_agreement must be True
            if e.encipher_only:
                ku = ku.encipherOnly()
            if e.decipher_only:
                ku = ku.decipherOnly()
        if e.key_cert_sign:
            ku = ku.keyCertSign()
        if e.crl_sign:
            ku = ku.cRLSign()
        return ku

_extend_class(KeyUsage, KEY_USAGE.values())


class ExtendedKeyUsage(MultiValueExtension):
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
    """
    [
        {"name":"basicConstraints", "critical":true, "value":"CA:FALSE"}
    ]
    """
    name = dct['name'].encode('ascii')
    crit = dct['critical']
    value = dct['value'].encode('ascii')
    return crypto.X509Extension(name, crit, value)


def json_to_extension(input):
    obj = json.loads(input, encoding='utf-8', object_hook=_as_extension)
    return obj
