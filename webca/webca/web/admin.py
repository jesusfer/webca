from django.contrib import admin
from django.conf import settings
from webca.web.models import *


def cert_readonly_fields():
    if settings.DEBUG == True:
        return []
    return [
        'user', 'template', 'csr', 'x509',
        'serial', 'subject', 'valid_from', 'valid_to'
    ]


class CertificateAdmin(admin.ModelAdmin):
    verbose_name = 'Issued Certificates'

    readonly_fields = cert_readonly_fields()


class TemplateAdmin(admin.ModelAdmin):
    save_as = True


admin.site.register(Request)
admin.site.register(Certificate, CertificateAdmin)
admin.site.register(Revoked)
admin.site.register(Template, TemplateAdmin)
