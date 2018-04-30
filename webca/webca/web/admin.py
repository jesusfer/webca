from django.contrib import admin
from django.conf import settings
from webca.web.models import *


class RequestAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'user', 'status', 'approved', 'id']

    list_filter = ['status']

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

    readonly_fields = cert_readonly_fields()


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
