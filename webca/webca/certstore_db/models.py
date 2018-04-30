import re
from django.db import models
from OpenSSL import crypto

from webca.utils import dict_as_tuples
from webca.crypto.constants import EXT_KEY_USAGE, KEY_USAGE
from webca.crypto.utils import asn1_to_datetime
from webca.crypto.extensions import get_extension, KeyUsage, ExtendedKeyUsage

# Create your models here.


class KeyPair(models.Model):
    """Represents a key pair that can be either RSA or DSA.

    TODO: need to decide what to do with private keys with a passphrase.
    """
    TYPE_RSA = 'rsa'
    TYPE_DSA = 'dsa'
    KEY_TYPE = (
        (TYPE_RSA, 'RSA'),
        (TYPE_DSA, 'DSA'),
    )

    name = models.CharField(
        max_length=255,
        help_text='Display name for this key pair'
    )
    private_key = models.TextField(
        default='',
        help_text='Private key in PEM format'
    )
    public_key = models.TextField(
        blank=True,
        help_text='Public key in PEM format. Might be blank.'
    )
    key_type = models.CharField(
        max_length=3,
        choices=KEY_TYPE,
        default=TYPE_RSA
    )

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<KeyPair %s>' % self.name

    def get_key_type(self):
        """Return the key type as an OpenSSL key type."""
        if self.key_type == KeyPair.TYPE_RSA:
            return crypto.TYPE_RSA
        return crypto.TYPE_DSA

    def get_private_key(self):
        """Return the private key as a Pkey object."""
        return crypto.load_privatekey(crypto.FILETYPE_PEM, self.private_key)

    def get_public_key(self):
        """Return the public key as a Pkey object."""
        if len(self.public_key) > 0:
            return crypto.load_publickey(crypto.FILETYPE_PEM, self.public_key)
        return None

    @classmethod
    def from_keypair(cls, keys):
        """Create a key pair using an OpenSSL.crypto.PKey key pair."""
        keyPair = KeyPair()
        try:
            keys.check()
            keyPair.private_key = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, keys).decode('utf-8')
            keyPair.public_key = crypto.dump_publickey(
                crypto.FILETYPE_PEM, keys).decode('utf-8')
        except TypeError:
            # check() will raise a TypeError if the key pair
            # only contains the public key and we need a private key
            return None
        keyPair.key_type = KeyPair.TYPE_RSA
        if keys.type() == crypto.TYPE_DSA:
            keyPair.key_type = KeyPair.TYPE_DSA
        return keyPair


class Certificate(models.Model):
    keys = models.ForeignKey(
        'KeyPair',
        on_delete=models.CASCADE,
        help_text='Key pair associated with this certificate'
    )
    subject = models.TextField(
        help_text='Subject as a distinguished name',

    )
    # The serial will be a large integer, represented in a hex string -> '%x' % n
    serial = models.CharField(
        max_length=100,
        help_text='Serial number of the certificate as an hex string'
    )
    valid_from = models.DateTimeField(
        help_text='The certificate is valid from this date'
    )
    valid_to = models.DateTimeField(
        help_text='The certificate is valid until this date'
    )
    basic_constraints = models.CharField(
        max_length=50,
        default='',
        help_text='CA cert indication and pathlen'
    )
    key_usage = models.TextField(
        blank=True,
        verbose_name="KeyUsage"
    )
    ext_key_usage = models.TextField(
        blank=True,
        verbose_name="ExtendedKeyUsage"
    )
    certificate = models.TextField(
        help_text='Certificate in PEM format'
    )

    def __str__(self):
        if 'CN=' in self.subject:
            return re.search('CN=([^/]+)', self.subject).groups()[0]
        return self.subject

    def __repr__(self):
        return "<Certificate %s>" % self.__str__()

    def is_ca(self):
        return 'CA=True' in self.basic_constraints

    is_ca.boolean = True
    is_ca.short_description = 'CA certificate'

    def get_certificate(self):
        """Return the certificate as a X509 object."""
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate)
        return cert

    @classmethod
    def from_certificate(cls, certificate):
        """Create a new Certificate object based on a X509 certificate.

        The new object is not saved by default."""
        cert = Certificate()
        for k, v in certificate.get_subject().get_components():
            cert.subject += "/%s=%s" % (k.decode('utf-8'), v.decode('utf-8'))
        cert.serial = '%x' % certificate.get_serial_number()
        cert.valid_from = asn1_to_datetime(
            certificate.get_notBefore().decode('utf-8'))
        cert.valid_to = asn1_to_datetime(
            certificate.get_notAfter().decode('utf-8'))
        e = get_extension(certificate, 'basicConstraints')
        if e:
            s = "CA=" + str(e.value.ca)
            s += ', pathlen=' + str(e.value.path_length)
            cert.basic_constraints = s
        e = get_extension(certificate, 'keyUsage')
        if e:
            cert.key_usage = KeyUsage.from_extension(e).value()
        e = get_extension(certificate, 'extendedKeyUsage')
        if e:
            cert.ext_key_usage = ExtendedKeyUsage.from_extension(e).value()
        cert.certificate = crypto.dump_certificate(
            crypto.FILETYPE_PEM, certificate).decode('utf-8')

        return cert
