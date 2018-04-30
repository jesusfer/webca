
from django.conf import settings
from django.db import models

from webca.crypto.constants import REV_REASON, REV_UNSPECIFIED
from webca.utils import dict_as_tuples

# TODO: consider the action to take when a FK is deleted.
# We should not delete anything so that we can keep track of everyting, probably


class Request(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.DO_NOTHING
    )
    subject = models.CharField(
        max_length=255,
        help_text='Subject of this certificate request'
    )
    csr = models.TextField(
        help_text='CSR for this request in PEM format'
    )


class Certificate(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.DO_NOTHING
    )
    template = models.ForeignKey(
        'Template',
        on_delete=models.DO_NOTHING
    )
    csr = models.OneToOneField(
        'Request',
        on_delete=models.CASCADE
    )
    x509 = models.TextField(
        help_text='PEM of the signed certificate'
    )
    serial = models.CharField(
        max_length=100,
        help_text='Serial number of the certificate as an hex string'
    )
    subject = models.CharField(
        max_length=255,
        help_text='Subject of this certificate'
    )
    valid_from = models.DateTimeField(
        help_text='The certificate is valid from this date'
    )
    valid_to = models.DateTimeField(
        help_text='The certificate is valid until this date'
    )

    class Meta:
        verbose_name = 'Issued certificates'


class Template(models.Model):
    name = models.CharField(
        max_length=100,
        help_text='Name for this certificate template'
    )
    days = models.SmallIntegerField(
        help_text='Number of days that this certificate will be valid for'
    )
    enabled = models.BooleanField(
        help_text='Whether this template will be available for end users'
    )
    version = models.IntegerField(
        help_text='Version of this certificate'
    )
    min_bits = models.PositiveSmallIntegerField(
        default=2048,
        help_text='Minimum key size'
    )
    basic_constraints = models.CharField(
        max_length=50,
        default="{'ca':0, 'pathlen':0}",
        help_text='CA cert indication and pathlen'
    )
    key_usage = models.TextField(
        blank=True,
        verbose_name='KeyUsage'
    )
    ext_key_usage = models.TextField(
        blank=True,
        verbose_name='ExtendedKeyUsage'
    )
    crl_points = models.TextField(
        blank=True,
        verbose_name='CRL Distribution Points',
        help_text='Inherited from the signing certificate/system configuration'
    )
    aia = models.TextField(
        blank=True,
        verbose_name='Authority Info Access',
        help_text='Inherited from the signing certificate/system configuration'
    )
    extensions = models.TextField(
        help_text='Other extensions for this certificate'
    )
    # policies = models.ForeignKey('PolicyInformation')

    def _save(self):
        pass
        # TODO: autobump the version number on updates


class Revoked(models.Model):
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
        verbose_name = 'Revoked certificates'

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
