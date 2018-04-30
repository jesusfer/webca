"""Admin settings for web application."""
from django.conf import settings
from django.contrib import admin, messages
from django.http import HttpResponse

from webca.web.models import Certificate, Request, Revoked, Template


class RequestAdmin(admin.ModelAdmin):
    list_display = ['id', '__str__', 'user', 'status', 'approved']
    list_filter = ['status']
    list_display_links = ['__str__']


def cert_readonly_fields():
    """Make fields read only if not in DEBUG mode."""
    if settings.DEBUG:
        return []
    return [
        'user', 'template', 'csr', 'x509',
        'serial', 'subject', 'valid_from', 'valid_to'
    ]


class CertificateAdmin(admin.ModelAdmin):
    verbose_name = 'Issued Certificates'
    list_display = ['id', '__str__', 'valid_from', 'valid_to']
    list_display_links = ['__str__']
    readonly_fields = cert_readonly_fields()
    actions = ['download_certificate']

    def download_certificate(self, request, queryset):
        """Download a certificate."""
        if len(queryset) > 1:
            self.message_user(request, 'You can only choose one certificate.',
                level=messages.ERROR)
            return
        response = HttpResponse(content_type="application/pkix-cert")
        for cert in queryset:
            response['Content-Disposition'] = 'attachment; filename="%s.cer"' % str(cert)
            response.write(cert.x509)
        return response
    download_certificate.short_description = 'Download CER'


class TemplateAdmin(admin.ModelAdmin):
    save_as = True
    save_on_top = True
    list_display = [
        '__str__', 'enabled', 'version'
    ]
    actions = ['toggle_template']

    def toggle_template(self, request, queryset):
        for template in queryset:
            template.enabled = not template.enabled
            template.save()
        self.message_user(request, 'Toggled %s template(s)' % len(queryset))


admin.site.register(Request, RequestAdmin)
admin.site.register(Certificate, CertificateAdmin)
admin.site.register(Revoked)
admin.site.register(Template, TemplateAdmin)
