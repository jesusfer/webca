"""Admin settings for web application."""
from django.conf import settings
from django.contrib import admin, messages
from django.http import HttpResponse
from OpenSSL import crypto

from webca.ca_admin.admin import admin_site
from webca.web.models import (Certificate, CRLLocation, Request, Revoked,
                              Template)


@admin.register(Request, site=admin_site)
class RequestAdmin(admin.ModelAdmin):
    """Admin model for end user requests."""
    list_display = ['id', '__str__', 'user', 'template', 'status', 'approved']
    list_filter = ['status']
    list_display_links = ['__str__']


def cert_readonly_fields():
    """Make fields read only if not in DEBUG mode."""
    if settings.DEBUG:
        return []
    return [
        'user', 'get_template', 'csr', 'serial', 'subject',
        'valid_from', 'valid_to', 'x509',
    ]


@admin.register(Certificate, site=admin_site)
class CertificateAdmin(admin.ModelAdmin):
    """Admin model for certificates."""
    verbose_name = 'Issued Certificates'
    list_display = ['id', '__str__', 'get_template', 'valid_from', 'valid_to']
    list_display_links = ['__str__']
    readonly_fields = cert_readonly_fields()
    actions = ['view_certificate', 'download_certificate']

    def view_certificate(self, request, queryset):
        """View a text version of the certificate."""
        if len(queryset) > 1:
            self.message_user(
                request,
                'You can only choose one certificate.',
                level=messages.ERROR)
            return None
        response = HttpResponse(content_type="text/plain")
        cert = queryset.first()
        response.write(crypto.dump_certificate(
            crypto.FILETYPE_TEXT, cert.get_certificate()))
        return response

    def download_certificate(self, request, queryset):
        """Download a certificate."""
        if len(queryset) > 1:
            self.message_user(
                request,
                'You can only choose one certificate.',
                level=messages.ERROR)
            return None
        response = HttpResponse(content_type="application/pkix-cert")
        for cert in queryset:
            response['Content-Disposition'] = 'attachment; filename="%s.cer"' % str(
                cert)
            response.write(cert.x509)
        return response
    download_certificate.short_description = 'Download CER'


@admin.register(Template, site=admin_site)
class TemplateAdmin(admin.ModelAdmin):
    """Admin model for templates."""
    save_as = True
    save_as_continue = False
    save_on_top = True
    list_display = [
        '__str__', 'days', 'basic_constraints', 'auto_sign', 'enabled', 'version'
    ]
    readonly_fields = ['version']
    fieldsets = (
        (None, {
            'fields': ('name', 'version', 'enabled', 'days', 'min_bits', 'auto_sign')
        }),
        ('Certificate names', {
            'classes': ('',),
            'fields': ('user_subject', 'required_subject', 'san_type', 'allowed_san'),
        }),
        ('Basic Constraints', {
            'classes': ('',),
            'fields': ('basic_constraints', 'pathlen'),
        }),
        ('Validation', {
            'classes': ('collapse',),
            'fields': ('crl_points', 'aia'),
        }),
        ('Extensions', {
            'classes': ('',),
            'fields': ('key_usage', 'ext_key_usage_critical', 'ext_key_usage', 'extensions'),
        }),
        ('Permissions', {
            'classes': ('',),
            'fields': ('allowed_groups',),
        }),
    )
    actions = ['toggle_template']

    def toggle_template(self, request, queryset):
        """Toggle the enabled boolean on a template."""
        for template in queryset:
            template.enabled = not template.enabled
            template.save()
        self.message_user(request, 'Toggled %s template(s)' % len(queryset))


@admin.register(Revoked, site=admin_site)
class RevokedAdmin(admin.ModelAdmin):
    """Admin model for Revoked certificates."""
    list_display = ['certificate', 'reason', 'date']


@admin.register(CRLLocation, site=admin_site)
class CRLLocationAdmin(admin.ModelAdmin):
    """Admin model for CRLLocation objects."""
    list_display = ['url', 'deleted', 'count']
