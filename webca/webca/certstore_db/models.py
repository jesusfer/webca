""""""
from django.db import models
from OpenSSL import crypto

from webca.certstore import CertificateExistsError
from webca.config import constants as parameters
from webca.config.models import ConfigurationObject as Config
from webca.crypto import utils as cert_utils
from webca.crypto import constants as c
from webca.crypto.extensions import ExtendedKeyUsage, KeyUsage, get_extension
from webca.utils import dict_as_tuples, subject_display

# Create your models here.


class KeyPair(models.Model):
    """Represents a key pair that can be either RSA or DSA.

    TODO: need to decide what to do with private keys with a passphrase.
    """
    name = models.CharField(
        max_length=255,
        help_text='Display name for this key pair',
    )
    private_key = models.TextField(
        default='',
        help_text='Private key in PEM format',
    )
    public_key = models.TextField(
        blank=True,
        help_text='Public key in PEM format. Might be blank.',
    )
    key_type = models.IntegerField(
        choices=dict_as_tuples(c.KEY_TYPE),
        default=c.KEY_RSA,
    )

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<KeyPair %s>' % self.name

    def delete(self, **kwargs):
        """Prevent removing if this is the certificate in use."""
        _, keysign_serial = Config.get_value(
            parameters.CERT_KEYSIGN).split(',')
        _, crlsign_serial = Config.get_value(
            parameters.CERT_KEYSIGN).split(',')
        _, csrsign_serial = Config.get_value(
            parameters.CERT_CSRSIGN).split(',')
        _, usersign_serial = Config.get_value(
            parameters.CERT_USERSIGN).split(',')
        serial = self.certificate_set.first().serial

        if (serial == keysign_serial or serial == crlsign_serial or
            serial == csrsign_serial or serial == usersign_serial):
            raise models.ProtectedError(
                'This certificate is being used and cannot be removed', self)
        super().delete(**kwargs)

    def get_key_type(self):
        """Return the key type as an OpenSSL key type."""
        if self.key_type == c.KEY_RSA:
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
        """Create a key pair using an `OpenSSL.crypto.PKey` key pair."""
        key_pair = KeyPair()
        key_pair.key_type = cert_utils.private_key_type(keys)
        try:
            key_pair.private_key = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, keys).decode('utf-8')
            if key_pair.key_type == c.KEY_RSA:
                keys.check()
            key_pair.public_key = crypto.dump_publickey(
                crypto.FILETYPE_PEM, keys).decode('utf-8')
        except TypeError as ex:
            # check() will raise a TypeError if the key pair
            # only contains the public key and we need a private key
            return None
        return key_pair


class Certificate(models.Model):
    # FIXME: should be a OneToOneField
    keys = models.ForeignKey(
        'KeyPair',
        on_delete=models.CASCADE,
        help_text='Key pair associated with this certificate',
    )
    subject = models.TextField(
        help_text='Subject as a distinguished name',
    )
    # The serial will be a large integer, represented in a hex string -> '%x' % n
    serial = models.CharField(
        max_length=100,
        help_text='Serial number of the certificate as an hex string',
    )
    valid_from = models.DateTimeField(
        help_text='The certificate is valid from this date',
    )
    valid_to = models.DateTimeField(
        help_text='The certificate is valid until this date',
    )
    basic_constraints = models.CharField(
        max_length=50,
        default='',
        help_text='CA cert indication and pathlen',
    )
    key_usage = models.TextField(
        blank=True,
        verbose_name='Key Usage',
    )
    ext_key_usage = models.TextField(
        blank=True,
        verbose_name='Extended Key Usage',
    )
    certificate = models.TextField(
        help_text='Certificate in PEM format',
    )

    def __str__(self):
        return subject_display(self.subject)

    def __repr__(self):
        return "<Certificate %s>" % self.__str__()

    def is_ca(self):
        """Is this a CA certificate?"""
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
        The new object is not saved."""
        serial = cert_utils.int_to_hex(certificate.get_serial_number())
        old = Certificate.objects.filter(serial=serial).count()
        if old:
            raise CertificateExistsError('duplicated-certificate')
        cert = Certificate()
        cert.subject = cert_utils.components_to_name(
            certificate.get_subject().get_components())
        cert.serial = cert_utils.int_to_hex(
            certificate.get_serial_number())
        cert.valid_from = cert_utils.asn1_to_datetime(
            certificate.get_notBefore().decode('utf-8'))
        cert.valid_to = cert_utils.asn1_to_datetime(
            certificate.get_notAfter().decode('utf-8'))
        ext = get_extension(certificate, 'basicConstraints')
        if ext:
            value = "CA=" + str(ext.value.ca)
            value += ', pathlen=' + str(ext.value.path_length)
            cert.basic_constraints = value
        ext = get_extension(certificate, 'keyUsage')
        if ext:
            cert.key_usage = KeyUsage.from_extension(ext).value()
        else:
            # If there is no keyUsage, then we assume it's valid for
            # all of them that make sense to us
            cert.key_usage = 'digitalSignature,keyCertSign,cRLSign'
        ext = get_extension(certificate, 'extendedKeyUsage')
        if ext:
            cert.ext_key_usage = ExtendedKeyUsage.from_extension(ext).value()
        cert.certificate = crypto.dump_certificate(
            crypto.FILETYPE_PEM, certificate).decode('utf-8')

        return cert
