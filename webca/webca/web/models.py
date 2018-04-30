import re

from django.conf import settings
from django.db import models
from OpenSSL import crypto

from webca.crypto.constants import REV_REASON, REV_UNSPECIFIED
from webca.utils import dict_as_tuples
from webca.web import validators

# TODO: consider the action to take when a FK is deleted.
# We should not delete anything so that we can keep track of everyting, probably


class Request(models.Model):
    """A certificate request from an end user."""
    STATUS_PROCESSING = 1
    STATUS_ISSUED = 2
    STATUS_REJECTED = 3
    STATUS = [
        (STATUS_PROCESSING, 'Processing'),
        (STATUS_ISSUED, 'Issued'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.DO_NOTHING,
    )
    subject = models.CharField(  # OpenSSL format
        max_length=255,
        help_text='Subject of this certificate request',
    )
    csr = models.TextField(
        help_text='CSR for this request in PEM format',
        validators=[validators.valid_pem_csr],
    )
    template = models.ForeignKey(
        'Template',
        on_delete=models.DO_NOTHING,
    )
    status = models.SmallIntegerField(
        choices=STATUS,
        default=STATUS_PROCESSING,
        help_text='Status of this request',
    )
    reject_reason = models.CharField(
        max_length=250,
        blank=True,
        help_text='Why this request has been rejected',
    )
    approved = models.NullBooleanField(
        default=None,
        help_text='Has this request been (auto)approved?',
    )

    def __str__(self):
        if 'CN=' in self.subject:
            return re.search('CN=([^/]+)', self.subject).groups()[0]
        if 'emailAddress=' in self.subject:
            return re.search('emailAddress=([^/]+)', self.subject).groups()[0]
        return self.subject

    def __repr__(self):
        return '<Certificate %s' % str(self)

    def get_csr(self):
        """Return the request as a OpenSSL.crypto.X509Req object."""
        return crypto.load_certificate_request(crypto.FILETYPE_PEM, self.csr)


class Certificate(models.Model):
    """An issued certificate."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.DO_NOTHING,
    )
    csr = models.OneToOneField(
        'Request',
        on_delete=models.CASCADE,
    )
    x509 = models.TextField(
        help_text='PEM of the signed certificate',
        validators=[validators.valid_pem_cer],
    )
    serial = models.CharField(
        max_length=100,
        help_text='Serial number of the certificate as an hex string',
    )
    subject = models.CharField(
        max_length=255,
        help_text='Subject of this certificate',
    )
    valid_from = models.DateTimeField(
        help_text='The certificate is valid from this date',
    )
    valid_to = models.DateTimeField(
        help_text='The certificate is valid until this date',
    )

    class Meta:
        verbose_name = 'Issued certificate'

    def __str__(self):
        return self.subject

    def __repr__(self):
        return '<Certificate %s' % str(self)

    def get_certificate(self):
        """Return the certificate as a OpenSSL.crypto.X509 object."""
        return crypto.load_certificate(crypto.FILETYPE_PEM, self.x509)


class Template(models.Model):
    """A template for a certificate request."""
    name = models.CharField(
        max_length=100,
        help_text='Name for this certificate template',
    )
    days = models.SmallIntegerField(
        help_text='Number of days that this certificate will be valid for',
    )
    enabled = models.BooleanField(
        help_text='Whether this template will be available for end users',
    )
    version = models.IntegerField(
        default=1,
        help_text='Version of this certificate',
    )
    auto_sign = models.BooleanField(
        default=True,
        help_text='Certificates using this template will automatically be signed by the CA',
    )
    min_bits = models.PositiveSmallIntegerField(
        default=2048,
        help_text='Minimum key size',
        validators=[validators.power_two],
    )
    basic_constraints = models.CharField(
        max_length=50,
        default="{'ca':0, 'pathlen':0}",
        help_text='CA cert indication and pathlen',
    )
    key_usage = models.TextField(
        blank=True,
        verbose_name='KeyUsage',
    )
    ext_key_usage = models.TextField(
        blank=True,
        verbose_name='ExtendedKeyUsage',
    )
    crl_points = models.TextField(
        blank=True,
        verbose_name='CRL Distribution Points',
        help_text='Inherited from the signing certificate/system configuration',
    )
    aia = models.TextField(
        blank=True,
        verbose_name='Authority Info Access',
        help_text='Inherited from the signing certificate/system configuration',
    )
    extensions = models.TextField(
        blank=True,
        help_text='Other extensions for this certificate',
    )
    # policies = models.ForeignKey('PolicyInformation')

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Template %s' % str(self)

    def _save(self):
        pass
        # TODO: autobump the version number on updates

    @staticmethod
    def get_enabled():
        """Return all enabled templates."""
        return list(Template.objects.filter(enabled=True))

    @staticmethod
    def get_form_choices():
        """Return all enlabed templates in a list of tuples
        to be used as field choices."""
        return [(t.id, t.name) for t in Template.get_enabled()]


class Revoked(models.Model):
    """A revoked certificate."""
    certificate = models.OneToOneField(
        'Certificate',
        # A revoked cert should always be kept
        on_delete=models.DO_NOTHING
    )
    date = models.DateTimeField(
        auto_now_add=True,
        help_text='When the certificate was revoked'
    )
    reason = models.SmallIntegerField(
        choices=dict_as_tuples(REV_REASON),
        default=REV_UNSPECIFIED
    )

    class Meta:
        verbose_name = 'Revoked certificate'

# TODO: is it really needed to store the CRL?
# maybe like a configuration object?
# class RevocationList(models.Model):
#     extensions = models.TextField(
#         help_text='Extensions for this CRL'
#     )


"""
TODO: define policies
class PolicyInformation(models.Model):
"""
