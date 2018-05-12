"""Admin site definition."""
from django.contrib import admin
from django.contrib.auth.models import Group, User
from django.template.response import TemplateResponse
from django.urls import path

from webca.ca_admin.views import crl


class AdminSite(admin.AdminSite):
    site_title = 'WebCA Admin'
    site_header = 'WebCA Configuration'
    index_title = 'Home'
    index_template = 'ca_admin/index.html'

    def get_urls(self):
        urls = super().get_urls()
        urls += [
            path('certs/', self.admin_view(self.certificates), name='certs'),
            path('crl/', self.admin_view(crl.CRLView.as_view()), name='crl'),
            path('crl/update/',
                 self.admin_view(crl.CRLView.as_view()),
                 {'update': True},
                 name='crl_update'
                 ),
        ]
        return urls

    def certificates(self, request):
        # ...
        context = dict(
            # Include common variables for rendering the admin template.
            self.each_context(request),
            title='Certificates',
            # Anything else you want in the context...
            #    key=value,
        )
        return TemplateResponse(request, "ca_admin/certificates.html", context)


admin_site = AdminSite(name='admin')

admin_site.register(User)
admin_site.register(Group)
