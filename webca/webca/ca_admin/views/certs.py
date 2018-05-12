from django import forms
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import reverse
from django.views import View

from webca.ca_admin import admin
from webca.ca_admin.templatetags.ca_admin import serial, subject
from webca.certstore import CertStore
from webca.config import constants as parameters
from webca.config.models import ConfigurationObject as Config


class CertificatesForm(forms.Form):
    ca = forms.ChoiceField(required=False)
    crl = forms.ChoiceField(required=False)
    user = forms.ChoiceField(required=False)
    submit_ca = forms.CharField(required=False)
    submit_crl = forms.CharField(required=False)
    submit_user = forms.CharField(required=False)

    def __init__(self, ca=None, crl=None, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ca = ca or []
        crl = crl or []
        user = user or []
        self.fields['ca'].choices = ca
        self.fields['crl'].choices = crl
        self.fields['user'].choices = user

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data


class CertificatesView(View):
    form_class = CertificatesForm
    template = 'ca_admin/certificates.html'

    def get_context(self, request, **kwargs):
        """Get a default context."""
        keysign = Config.get_value(parameters.CERT_KEYSIGN)
        crlsign = Config.get_value(parameters.CERT_CRLSIGN)
        usersign = Config.get_value(parameters.CERT_USERSIGN)

        initial = {
            'ca': keysign,
            'crl': crlsign,
            'user': usersign,
        }
        # list of tuples ('store_id,serial', certificate)
        ca_certificates = []
        for store in CertStore.stores():
            for cert in store.get_ca_certificates():
                value = '{},{}'.format(store.STORE_ID, serial(cert))
                ca_certificates.append((value, cert))

        crl_certificates = []
        for store in CertStore.stores():
            for cert in store.get_crl_certificates():
                value = '{},{}'.format(store.STORE_ID, serial(cert))
                crl_certificates.append((value, cert))

        context = dict(
            admin.admin_site.each_context(request),
            title='CA Certificates',
            stores=CertStore.all(),
            ca_certificates=ca_certificates,
            crl_certificates=crl_certificates,
            user_certificates=ca_certificates,
            keysign=keysign,
            crlsign=crlsign,
            usersign=usersign,
            initial=initial,
            form=self.form_class(
                ca=ca_certificates,
                crl=crl_certificates,
                user=ca_certificates,
                initial=initial,
            )
        )
        return context

    def get(self, request, *args, **kwargs):
        if 'update' in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:certs'))
        context = self.get_context(request)
        return TemplateResponse(request, self.template, context)

    def post(self, request, *args, **kwargs):
        if 'update' not in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:certs'))
        context = self.get_context(request)
        form = self.form_class(
            ca=context['ca_certificates'],
            crl=context['crl_certificates'],
            user=context['user_certificates'],
            data=request.POST,
            initial=context['initial'],
        )
        if form.is_valid():
            if form.has_changed():
                if 'submit_ca' in form.changed_data and 'ca' in form.changed_data:
                    ca = form.cleaned_data['ca']
                    Config.set_value(parameters.CERT_KEYSIGN, ca)
                    messages.add_message(
                        request, messages.INFO, 'Changes saved')
                elif 'submit_crl' in form.changed_data and 'crl' in form.changed_data:
                    crl = form.cleaned_data['crl']
                    Config.set_value(parameters.CERT_CRLSIGN, crl)
                    messages.add_message(
                        request, messages.INFO, 'Changes saved')
                elif 'submit_user' in form.changed_data and 'user' in form.changed_data:
                    user = form.cleaned_data['user']
                    Config.set_value(parameters.CERT_USERSIGN, user)
                    messages.add_message(
                        request, messages.INFO, 'Changes saved')
                else:
                    messages.add_message(
                        request, messages.WARNING, 'No changes done')
            url = reverse('admin:certs')
            return HttpResponseRedirect(url)
        return TemplateResponse(request, self.template, context)
