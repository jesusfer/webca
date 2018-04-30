import json
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from OpenSSL import crypto

from webca.crypto.constants import REV_REASON, REV_UNSPECIFIED
from webca.utils import dict_as_tuples, subject_display
from webca.web import validators

# TODO: consider the action to take when a FK is deleted.
# We should not delete anything so that we can keep track of everyting, probably


class Request(models.Model):
    """A certificate request from an end user."""
    STATUS_PROCESSING = 1
    STATUS_ISSUED = 2
    STATUS_REJECTED = 3
    # TODO: Add a status for error during issuance?
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
        return subject_display(self.subject)

    def __repr__(self):
        return '<Certificate %s' % str(self)

    def save(self, *args, **kwargs):
        # We have to do some validations here as Django validators
        # can't access other stuff than the value to validate
        # Validate key size minimum
        req_size = self.get_csr().get_pubkey().bits()
        if req_size < self.template.min_bits:
            raise ValidationError(
                'Key size must be %(min)d or more',
                code='minBits',
                params={'min':self.template.min_bits}
                )
        super().save(*args, **kwargs)

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
        return subject_display(self.subject)

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
        default='{"ca":0, "pathlen":0}',
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

    __days = None
    __enabled = None
    __auto_sign = None
    __min_bits = None
    __basic_constraints = None
    __key_usage = None
    __ext_key_usage = None
    __crl_points = None
    __aia = None
    __extensions = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Save the original values
        self.__days = self.days
        self.__enabled = self.enabled
        self.__auto_sign = self.auto_sign
        self.__min_bits = self.min_bits
        self.__basic_constraints = self.basic_constraints
        self.__key_usage = self.key_usage
        self.__ext_key_usage = self.ext_key_usage
        self.__crl_points = self.crl_points
        self.__aia = self.aia
        self.__extensions = self.extensions

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Template %s' % str(self)

    def save(self, *args, **kwargs):
        # We want to increment the version only when the admin has made changes
        # Enabling/disabling should not count
        # Since we shouldn't except much concurrency when editing templates,
        # it should be fine to just check current values with previous
        # FUTURE: this may be better done in some other way
        if (self.__days != self.days or
                self.__auto_sign != self.auto_sign or
                self.__min_bits != self.min_bits or
                self.__basic_constraints != self.basic_constraints or
                self.__key_usage != self.key_usage or
                self.__ext_key_usage != self.ext_key_usage or
                self.__crl_points != self.crl_points or
                self.__aia != self.aia or
                self.__extensions != self.extensions):
            self.version += 1
        super().save(*args, **kwargs)

    def get_basic_constraints(self):
        """Return the OpenSSL formated basicConstraints value."""
        const = json.loads(self.basic_constraints)
        value = 'CA:{}'.format(const['ca']).upper()
        if const['pathlen'] >= 0:
            value += ', pathlen:%d' % const['pathlen']
        return value

    def get_extensions(self):
        """Return a list of OpenSSL.crypto.X509Extension with the extensions
        enabled in this template."""
        extensions = []
        # 1. Minimum:
        # basic constranints
        extensions.append(crypto.X509Extension(
            b'basicConstraints',
            True,
            self.get_basic_constraints().encode('ascii')
        ))
        # key usage
        extensions.append(crypto.X509Extension(
            b'keyUsage',
            True,
            self.key_usage.encode('ascii')
        ))
        # 3. Validation
        # TODO: CRL
        extensions.append(crypto.X509Extension(
            b'crlDistributionPoints',
            False,
            b'URI:http://test.net/test.crl'
        ))

        # TODO: OCSP
        # 2. Extras
        # extended key usage
        if self.ext_key_usage:
            extensions.append(crypto.X509Extension(
                b'extendedKeyUsage',
                False,
                self.ext_key_usage.encode('ascii')
            ))
        # TODO: SAN
        # crypto.X509Extension(b'subjectAltName', False, b'DNS:www.test.net')
        # 3. Custom
        # crypto.X509Extension(b'1.6.6', False, b'DER:31:32:33')
        return extensions

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
