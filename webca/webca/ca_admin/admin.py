"""Admin site definition."""
from django.contrib import admin
from django.contrib.auth.models import Group, User
from django.template.response import TemplateResponse
from django.urls import path

from webca.ca_admin.views import crl, certs


class AdminSite(admin.AdminSite):
    site_title = 'WebCA Admin'
    site_header = 'WebCA Configuration'
    index_title = 'Home'
    index_template = 'ca_admin/index.html'

    def get_urls(self):
        urls = super().get_urls()
        urls += [
            path('certs/', self.admin_view(certs.CertificatesView.as_view()), name='certs'),
            path('certs/update/',
                 self.admin_view(certs.CertificatesView.as_view()),
                 {'update': True},
                 name='certs_update',
                 ),
            path('crl/', self.admin_view(crl.CRLView.as_view()), name='crl'),
            path('crl/update/',
                 self.admin_view(crl.CRLView.as_view()),
                 {'update': True},
                 name='crl_update',
                 ),
        ]
        return urls


admin_site = AdminSite(name='admin')

admin_site.register(User)
admin_site.register(Group)
