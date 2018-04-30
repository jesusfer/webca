from django.contrib import admin, messages
from django.forms import Textarea
from django.http import HttpResponse

from webca.certstore_db.models import *

class KeyPairAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'key_type']

    actions = ['download_pem']

    def download_pem(self, request, queryset):
        """Download one key pair in PEM format."""
        if len(queryset) > 1:
            self.message_user(request, 'You can only choose one key pair.',
                level=messages.ERROR)
            return
        response = HttpResponse(content_type="application/pkix-cert")
        for keypair in queryset:
            response['Content-Disposition'] = 'attachment; filename="%s.pem"' % str(keypair)
            response.write(keypair.private_key)
        return response
    download_pem.short_description = 'Download PEM'

class CertificateAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'serial', 'is_ca',
                    'valid_from', 'valid_to', 'key_usage']

    actions = ['download_certificate']

    formfield_overrides = {
        models.TextField: {'widget': Textarea(
                           attrs={'rows': 5,
                                  'cols': 50})},
    }

    def download_certificate(self, request, queryset):
        """Download the public certificate."""
        if len(queryset) > 1:
            self.message_user(request, 'You can only choose one certificate.',
                level=messages.ERROR)
            return
        response = HttpResponse(content_type="application/pkix-cert")
        for cert in queryset:
            response['Content-Disposition'] = 'attachment; filename="%s.cer"' % str(cert)
            response.write(cert.certificate)
        return response
    download_certificate.short_description = 'Download CER'

admin.site.register(KeyPair, KeyPairAdmin)
admin.site.register(Certificate, CertificateAdmin)
