"""Admin site definition."""
from django.contrib import admin
from django.contrib.auth.models import Group, User
from django.template.response import TemplateResponse
from django.urls import path

from webca.ca_admin.views import certs, crl


class AdminSite(admin.AdminSite):
    site_title = 'WebCA Admin'
    site_header = 'WebCA Configuration'
    index_title = 'Home'
    index_template = 'ca_admin/index.html'

    def get_urls(self):
        urls = super().get_urls()
        urls += [
            # CA certs configuration
            path('certs/view/', self.admin_view(certs.CertificatesView.as_view()), name='certs_view'),
            path('certs/view/<slug:serial>/', self.admin_view(certs.CertificatesView.as_view()), name='certs_view'),
            path('certs/setup/', self.admin_view(certs.CertificateSetupView.as_view()), name='certs_setup'),
            path('certs/update/', self.admin_view(certs.CertificateSetupView.as_view()),
                 {'update': True}, name='certs_update'),
            # Upload CA certs
            path('certs/add/', self.admin_view(certs.AddCertificateView.as_view()),  # choose an option
                 {'step': certs.AddCertificateView.STEP_CHOOSE}, name='certs_add'),
            path('certs/add/create/', self.admin_view(certs.AddCertificateView.as_view()),  # fill in option reqs
                 {'step': certs.AddCertificateView.STEP_CREATE}, name='certs_add_create'),
            path('certs/add/confirm/', self.admin_view(certs.AddCertificateView.as_view()),  # confirm
                 {'step': certs.AddCertificateView.STEP_CONFIRM}, name='certs_add_confirm'),
            # CRL configuration
            path('crl/', self.admin_view(crl.CRLView.as_view()), name='crl'),
            path('crl/update/', self.admin_view(crl.CRLView.as_view()),
                 {'update': True}, name='crl_update'),
            path('crl/status/', self.admin_view(crl.CRLStatusView.as_view()),
                 name='crl_status'),
            path('crl/status/update/', self.admin_view(crl.CRLStatusView.as_view()),
                 {'update': True}, name='crl_status_update'),
        ]
        return urls


admin_site = AdminSite(name='admin')

admin_site.register(User)
admin_site.register(Group)
