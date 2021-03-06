"""Models for the public web."""
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from OpenSSL import crypto

from webca.crypto import constants as c
from webca.crypto.utils import (components_to_name, name_to_components,
                                public_key_type)
from webca.utils import dict_as_tuples, subject_display, tuples_as_dict
from webca.web import validators
from webca.web.fields import (ExtendedKeyUsageField, KeyUsageField,
                              SubjectAltNameField)

# TODO: consider the action to take when a FK is deleted.
# We should not delete anything so that we can keep track of everyting, probably


class CAUser(models.Model):
    """Extension to the User model."""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='ca_user',
    )
    code = models.CharField(
        max_length=40,
        blank=True,
        help_text='One-time login code',
    )
    keys = models.TextField(
        blank=True,
        help_text="Public keys",
    )

    class Meta:
        verbose_name = 'User profile'

    def __str__(self):
        return 'CAUser: %s' % self.user.email

    def add_key(self, key):
        """Add a new public key of this user."""
        # FUTURE: the number of keys may be limited
        if self.keys:
            self.keys += ',' + key
        else:
            self.keys = key
        self.save()
    
    @property
    def public_keys(self):
        """Return the list of keys associated with this user."""
        return self.keys.split(',')
    
    @property
    def public_keys_count(self):
        """Return the number of public keys this user has."""
        return len(self.keys)


class Request(models.Model):
    """A certificate request from an end user."""
    STATUS_PROCESSING = 1
    STATUS_ISSUED = 2
    STATUS_REJECTED = 3
    STATUS_ERROR = 4
    STATUS = [
        (STATUS_PROCESSING, 'Processing'),
        (STATUS_ISSUED, 'Issued'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_ERROR, 'Error'),
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
    san = models.TextField(
        blank=True,
        help_text='Alternative Names requested',
        verbose_name='SAN names',
    )
    admin_comment = models.TextField(
        blank=True,
        help_text='Internal messages about this request',
    )

    class Meta:
        ordering = ['-id']

    def __str__(self):
        return subject_display(self.subject)

    def __repr__(self):
        return '<Certificate %s>' % str(self)

    def save(self, *args, **kwargs):
        # If there wasan error processing the request, just save it
        if self.status == Request.STATUS_ERROR:
            super().save(*args, **kwargs)
            return

        # Validate key size minimum
        # We don't need to check that if the request is being rejected
        req_size = self.get_csr().get_pubkey().bits()
        key_type = public_key_type(self.get_csr())
        min_bits = self.template.min_bits_for(key_type)
        if req_size < min_bits and self.status != Request.STATUS_REJECTED:
            raise ValidationError(
                'Key size must be %(min)d or more',
                code='minBits',
                params={'min': min_bits}
            )
        # Clean up the subject (keep only the components we define)
        subject = tuples_as_dict(name_to_components(self.subject))
        new_subject = {}
        for name, value in subject.items():
            if name in c.SUBJECT_PARTS:
                new_subject[name] = value
        # Validate the subject requirements against the template
        # CN is always required at this time
        if 'CN' not in new_subject.keys():
            raise ValidationError(
                'A Common Name is required for this request',
                code='cn-required',
            )
        if self.template.required_subject == Template.SUBJECT_CN:
            # Only keep CN
            self.subject = '/CN={}'.format(
                new_subject['CN']
            )
        elif self.template.required_subject == Template.SUBJECT_USER:
            if 'emailAddress' not in new_subject.keys():
                raise ValidationError(
                    'An E-Mail is required for this request',
                    code='email-required',
                )
            else:
                validate_email(new_subject['emailAddress'])
            # Only keep CN and emailAddress
            self.subject = '/CN={}/emailAddress={}'.format(
                new_subject['CN'],
                new_subject['emailAddress'],
            )
        elif self.template.required_subject == Template.SUBJECT_DN:
            # Check for a full DN
            missing = [name
                       for name in c.SUBJECT_DN
                       if name not in new_subject.keys()]
            if missing:
                raise ValidationError(
                    'A full Distinguished Name is required for this request',
                    code='dn-required',
                )
            self.subject = components_to_name(dict_as_tuples(new_subject))
        else:
            # A partial DN means at least CN and then whatever else
            if 'CN' not in new_subject.keys():
                raise ValidationError(
                    'At least Common Name is required for this request',
                    code='partial-required',
                )
            self.subject = components_to_name(dict_as_tuples(new_subject))
        super().save(*args, **kwargs)

    def get_csr(self):
        """Return the request as a OpenSSL.crypto.X509Req object."""
        return crypto.load_certificate_request(crypto.FILETYPE_PEM, self.csr)

    @property
    def extended_status(self):
        """Return the extended status of this request.
        1. Processing
        2. Pending approval
        3. Approved
        4. Rejected
        5. Issued
        6. Expired
        7. Revoked
        8. Error
        """
        if self.status == self.STATUS_ISSUED and self.certificate.is_expired:
            return 'Expired'
        if self.status == self.STATUS_ISSUED and self.certificate.is_revoked:
            return 'Revoked'
        if self.status == self.STATUS_PROCESSING and not self.approved:
            return 'Pending approval'
        if self.status == self.STATUS_PROCESSING and self.approved:
            return 'Approved'
        if (self.status == self.STATUS_PROCESSING or self.status == self.STATUS_ISSUED or
            self.status == self.STATUS_ERROR or self.status == self.STATUS_REJECTED):
            return self.get_status_display()


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
        db_index=True,
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
        return '<Certificate %s>' % str(self)

    def get_certificate(self):
        """Return the certificate as a OpenSSL.crypto.X509 object."""
        return crypto.load_certificate(crypto.FILETYPE_PEM, self.x509)

    def get_template(self):
        """Return the template used to sign this certificate."""
        return self.csr.template
    get_template.short_description = 'Template'

    @property
    def is_expired(self):
        """Return if the certificate has expired."""
        now = timezone.now()
        return now < self.valid_from or self.valid_to < now

    @property
    def is_revoked(self):
        """Return if the certificate has been revoked."""
        return hasattr(self, 'revoked')

    @property
    def is_valid(self):
        """Return if the certificate is valid."""
        return not self.is_expired and not self.is_revoked

    def subject_filename(self):
        """Return part of the subject to create file names."""
        # if user cert, then return the email
        # else, return the CN
        components = tuples_as_dict(name_to_components(self.subject))
        if 'emailAddress' in components.keys():
            return components['emailAddress']
        else:
            return components['CN']


class Template(models.Model):
    """A template for a certificate request."""
    BC_CA = 1
    BC_ENTITY = 2
    BC_TYPE = [
        (BC_CA, 'Certification Authority'),
        (BC_ENTITY, 'End Entity'),
    ]
    SUBJECT_DN = 1
    SUBJECT_CN = 2
    SUBJECT_USER = 3
    SUBJECT_DN_PARTIAL = 4
    SUBJECT_TYPE = [
        (SUBJECT_CN, 'Common Name'),
        (SUBJECT_USER, 'User (CN + E-Mail)'),
        (SUBJECT_DN, 'Full Distinguished Name'),
        (SUBJECT_DN_PARTIAL, 'Partial Distinguished Name'),
    ]
    SAN_HIDDEN = 1
    SAN_SHOWN = 2
    SAN_TYPE = [
        (SAN_HIDDEN, 'Hidden'),
        (SAN_SHOWN, 'Shown'),
    ]
    name = models.CharField(
        max_length=100,
        help_text='Name for this certificate template',
    )
    description = models.TextField(
        blank=True,
        help_text='Description of the certificate that will be displayed '
        'to the users so that they understand the purpose of this template.',
    )
    days = models.PositiveSmallIntegerField(
        help_text='Number of days that this certificate will be valid for',
        validators=[validators.max_days],
    )
    enabled = models.BooleanField(
        help_text='Whether this template will be available for end users',
    )
    version = models.IntegerField(
        default=1,
        help_text='Version of this template',
    )
    auto_sign = models.BooleanField(
        default=True,
        help_text='Certificate requests using this template will automatically be signed by the CA',
    )
    min_bits_rsa = models.PositiveSmallIntegerField(
        default=2048,
        help_text='Minimum RSA key size',
        verbose_name='RSA Key size',
        validators=[validators.valid_key_size_number],
    )
    min_bits_dsa = models.PositiveSmallIntegerField(
        default=1024,
        help_text='Minimum DSA key size',
        verbose_name='DSA Key size',
        validators=[validators.valid_key_size_number],
    )
    min_bits_ec = models.PositiveSmallIntegerField(
        default=256,
        help_text='Minimum Elliptic Curves (EC) key size',
        verbose_name='EC Key size',
        validators=[validators.valid_key_size_number],
    )
    required_subject = models.SmallIntegerField(
        choices=SUBJECT_TYPE,
        default=SUBJECT_CN,
        help_text="""Type of subject required (which fields are required in requests):<br/>
        - CN: Common Name.<br/>
        - User: CN + email. The email will be added as rfc822Name in the SubjectAltName extension.<br/>
        - Full DN: All fields of the DN are required (C, ST, L, O, OU).<br/>
        - Partial DN: CN is required, the rest are optional.""",
    )
    san_type = models.SmallIntegerField(
        choices=SAN_TYPE,
        default=SAN_HIDDEN,
        verbose_name='Show SAN',
        help_text='Show the Subject Alternative Name field',
    )
    allowed_san = SubjectAltNameField(
        help_text='Allowed SAN keywords. Any number of keywords is allowed.',
        verbose_name='Allowed SAN',
    )
    basic_constraints = models.PositiveSmallIntegerField(
        choices=BC_TYPE,
        default=BC_ENTITY,
        help_text='Type of certificate',
    )
    pathlen = models.SmallIntegerField(
        default=-1,
        help_text="""Max path validation length. Only makes sense if Basic Constraints is CA.
        If value is -1, it won't be included in the certfiicate.""",
        validators=[validators.valid_pathlen],
    )
    key_usage = KeyUsageField(
        verbose_name='KeyUsage',
        help_text='This list defines the allowed algorithms used by the public key of the certificates.',
    )
    ext_key_usage_critical = models.BooleanField(
        default=False,
        verbose_name='Make the ExtendendedKeyUsage extension critical',
    )
    ext_key_usage = ExtendedKeyUsageField(
        blank=True,
        null=True,
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
    allowed_groups = models.ManyToManyField(
        Group,
        blank=True,
        help_text='User groups allowed to use this Template',
    )
    # policies = models.ForeignKey('PolicyInformation')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fields = [str(f).split('.')[2]
                  for f in Template._meta.get_fields()
                  if not f.is_relation
                  or f.one_to_one
                  or (f.many_to_one and f.related_model)]
        ignored_fields = ['id', 'enabled', 'version']
        for field in fields:
            if field not in ignored_fields:
                value = getattr(self, field, None)
                if isinstance(value, list):
                    value = [x for x in value if x]
                setattr(self, "_%s" % field, value)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Template %s>' % str(self)

    def save(self, *args, **kwargs):
        # We want to increment the version only when the admin has made changes
        # Enabling/disabling should not count
        # Since we shouldn't except much concurrency when editing templates,
        # it should be fine to just check current values with previous
        # FUTURE: if there are pending requests and the key is increased, we may want to automatically reject those pending requests
        # TODO: if the Template did not have auto_sign before and it does when saving, approve automatically all requests?
        fields = [str(f).split('.')[2]
                  for f in Template._meta.get_fields()
                  if not f.is_relation
                  or f.one_to_one
                  or (f.many_to_one and f.related_model)]
        ignored_fields = ['id', 'enabled', 'version']
        has_changed = False
        for field in fields:
            if field not in ignored_fields:
                value = getattr(self, field, None)
                old_value = getattr(self, "_%s" % field)
                if value != old_value:
                    has_changed = True
                    break
        if has_changed and self.id is not None:
            self.version += 1
        if self.basic_constraints == Template.BC_ENTITY:
            self.pathlen = -1
        super().save(*args, **kwargs)

    def clean(self):
        # Validate that basic_constraints and key_usage make sense.
        key_usage = [number
                     for number, name in c.KEY_USAGE.items()
                     if name in self.key_usage]
        if (c.KU_KEYCERTSIGN in key_usage and
                self.basic_constraints != Template.BC_CA):
            raise ValidationError({
                'key_usage': ValidationError(
                    'keyCertSign cannot be asserted if Basic Constraints is End Entity',
                    code='invalid-key_usage-keyCertSign',
                ),
            })

    def get_basic_constraints(self):
        """Return the OpenSSL formated basicConstraints value."""
        value = 'CA:FALSE'
        if self.basic_constraints == Template.BC_CA:
            value = 'CA:TRUE'
            if self.pathlen >= 0:
                value += ',pathlen:%d' % self.pathlen
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
            ','.join(self.key_usage).encode('ascii')
        ))

        # 2. Extras
        # extended key usage
        eku = [x for x in self.ext_key_usage if x]
        if eku:
            extensions.append(crypto.X509Extension(
                b'extendedKeyUsage',
                self.ext_key_usage_critical,
                ','.join(eku).encode('ascii')
            ))
        # 3. Custom
        # crypto.X509Extension(b'1.6.6', False, b'DER:31:32:33')
        return extensions

    def min_bits_for(self, key_type):
        """Return the minimum bits required in this template for `key_type`."""
        if key_type == c.KEY_RSA:
            return self.min_bits_rsa
        elif key_type == c.KEY_DSA:
            return self.min_bits_dsa
        else:
            return self.min_bits_ec

    def allowed_key_types(self):
        """Return a list of `webca.crypto.constants.KEY_TYPE`
        with the algorithms that are allowed in this template."""
        template_usages = [number
                           for number, name in c.KEY_USAGE.items()
                           if name in self.key_usage]

        if self.basic_constraints == Template.BC_CA:
            bc_usages = c.KEY_TYPE_KEY_USAGE_CA
        else:
            bc_usages = c.KEY_TYPE_KEY_USAGE_EE
        allowed = []
        for key_type, type_usages in bc_usages.items():
            matches = [x
                       for x in template_usages
                       if x in type_usages]
            if len(matches) == len(template_usages):
                allowed.append(key_type)
        return allowed

    @staticmethod
    def get_enabled():
        """Return all enabled templates."""
        return list(Template.objects.filter(enabled=True))

    @staticmethod
    def get_form_choices(selected):
        """Convert a list of templates to a list of tuples to be used as field choices."""
        return [(t.id, t.name) for t in selected]


class Revoked(models.Model):
    """A revoked certificate."""
    certificate = models.OneToOneField(
        'Certificate',
        # A revoked cert should always be kept
        on_delete=models.CASCADE
    )
    date = models.DateTimeField(
        auto_now_add=True,
        help_text='When the certificate was revoked'
    )
    reason = models.SmallIntegerField(
        choices=dict_as_tuples(c.REV_REASON),
        default=c.REV_UNSPECIFIED
    )

    def __str__(self):
        return '{} ({})'.format(
            str(self.certificate),
            c.REV_REASON[self.reason]
        )

    def __repr__(self):
        return '<Revoked %s>' % str(self.certificate)

    class Meta:
        verbose_name = 'Revoked certificate'


class CRLLocation(models.Model):
    """Represents a URL that points to a CRL location."""
    
    url = models.URLField(
        help_text='URL for this location',
    )
    deleted = models.BooleanField(
        default=False,
        help_text='Has this URL been deleted?',
    )
    certificates = models.ManyToManyField(
        Certificate,
        help_text='Certificates using this location',
    )

    def __str__(self):
        return 'CRL: {}'.format(self.url)

    def __repr__(self):
        return '<CRLLocation %s>' % self.url

    class Meta:
        verbose_name = 'CRL Location'

    @property
    def count(self):
        """Return the number of valid certificates that have this location in their CRL extension."""
        certs = [x for x in self.certificates.all() if x.is_valid]
        return len(certs)

    @staticmethod
    def get_locations():
        """Get non-deleted locations."""
        return CRLLocation.objects.filter(deleted=False)


"""
TODO: define policies
class PolicyInformation(models.Model):
"""
