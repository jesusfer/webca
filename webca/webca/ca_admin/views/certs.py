"""
CA certificates views.
"""
from cryptography import hazmat
from django import forms
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.safestring import SafeString
from django.views import View
from OpenSSL import crypto

from webca.ca_admin import admin
from webca.ca_admin.templatetags import ca_admin as admin_tags
from webca.certstore import CertificateExistsError, CertStore
from webca.config import constants as parameters
from webca.config.models import ConfigurationObject as Config
from webca.crypto import constants as c
from webca.crypto.utils import (asn1_to_datetime, components_to_name,
                                export_certificate, int_to_hex,
                                private_key_type)
from webca.utils import subject_display

class CertificatesView(View):
    """Render a page to see the installed certificates and details about them."""
    template = 'ca_admin/certs_view.html'

    def get(self, request, *args, **kwargs):
        """Render a page to see the installed certificates and details about them."""
        context = dict(
            admin.admin_site.each_context(request),
            title='Installed Certificates',
        )
        if 'serial' in kwargs.keys():
            store, serial = kwargs.pop('serial').split('-')
            cert = CertStore.get_by_name(store).get_certificate(serial)
            text = export_certificate(cert, text=True)
            context['text'] = SafeString(text)
        else:
            certs = {}
            for name, store in CertStore.all():
                for usage in [c.KU_KEYCERTSIGN, c.KU_CRLSIGN]:
                    usage_name = c.KEY_USAGE[usage]
                    for cert in store().get_certificates(key_usage=[usage]):
                        serial = int_to_hex(cert.get_serial_number())
                        if serial not in certs.keys():
                            # TODO: this is ugly!
                            subject = subject_display(components_to_name(
                                cert.get_subject().get_components()))
                            cert = {
                                'store': name,
                                'serial': serial,
                                'subject': subject,
                                'valid_from': asn1_to_datetime(cert.get_notBefore().decode('utf-8')),
                                'valid_until': asn1_to_datetime(cert.get_notAfter().decode('utf-8')),
                                c.KEY_USAGE[c.KU_KEYCERTSIGN]: False,
                                c.KEY_USAGE[c.KU_CRLSIGN]: False,
                                c.EXT_KEY_USAGE[c.EKU_OCSPSIGNING]: False,
                            }
                        else:
                            cert = certs[serial]
                        cert[usage_name] = True
                        certs[serial] = cert
                for usage in [c.EKU_OCSPSIGNING]:
                    usage_name = c.EXT_KEY_USAGE[usage]
                    for cert in store().get_certificates(ext_key_usage=[usage]):
                        serial = int_to_hex(cert.get_serial_number())
                        if serial not in certs.keys():
                            # TODO: this is ugly!
                            subject = subject_display(components_to_name(
                                cert.get_subject().get_components()))
                            cert = {
                                'store': name,
                                'serial': serial,
                                'subject': subject,
                                'valid_from': asn1_to_datetime(cert.get_notBefore().decode('utf-8')),
                                'valid_until': asn1_to_datetime(cert.get_notAfter().decode('utf-8')),
                                c.KEY_USAGE[c.KU_KEYCERTSIGN]: False,
                                c.KEY_USAGE[c.KU_CRLSIGN]: False,
                                c.EXT_KEY_USAGE[c.EKU_OCSPSIGNING]: False,
                            }
                        else:
                            cert = certs[serial]
                        cert[usage_name] = True
                        certs[serial] = cert
            context['certificates'] = certs
        return TemplateResponse(request, self.template, context)


class CertificateSetupForm(forms.Form):
    ca = forms.ChoiceField(required=False)
    crl = forms.ChoiceField(required=False)
    ocsp = forms.ChoiceField(required=False)
    # user = forms.ChoiceField(required=False)
    submit_ca = forms.CharField(required=False)
    submit_crl = forms.CharField(required=False)
    submit_ocsp = forms.CharField(required=False)
    # submit_user = forms.CharField(required=False)

    def __init__(self, ca=None, crl=None, ocsp=None, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ca = ca or []
        crl = crl or []
        ocsp = ocsp or []
        # user = user or []
        self.fields['ca'].choices = ca
        self.fields['crl'].choices = crl
        self.fields['ocsp'].choices = ocsp
        # self.fields['user'].choices = user

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data


class CertificateSetupView(View):
    form_class = CertificateSetupForm
    template = 'ca_admin/certs_setup.html'

    def get_context(self, request, **kwargs):
        """Get a default context."""
        keysign = Config.get_value(parameters.CERT_KEYSIGN)
        crlsign = Config.get_value(parameters.CERT_CRLSIGN)
        ocspsign = Config.get_value(parameters.CERT_OCSPSIGN)
        # usersign = Config.get_value(parameters.CERT_USERSIGN)

        initial = {
            'ca': keysign,
            'crl': crlsign,
            'ocsp': ocspsign,
            # 'user': usersign,
        }
        # list of tuples ('store_id,serial', certificate)
        ca_certificates = []
        for store in CertStore.stores():
            for cert in store.get_ca_certificates():
                value = '{},{}'.format(store.STORE_ID, admin_tags.serial(cert))
                ca_certificates.append((value, cert))

        crl_certificates = []
        for store in CertStore.stores():
            for cert in store.get_crl_certificates():
                value = '{},{}'.format(store.STORE_ID, admin_tags.serial(cert))
                crl_certificates.append((value, cert))

        ocsp_certificates = []
        for store in CertStore.stores():
            for cert in store.get_ocsp_certificates():
                value = '{},{}'.format(store.STORE_ID, admin_tags.serial(cert))
                ocsp_certificates.append((value, cert))

        context = dict(
            admin.admin_site.each_context(request),
            title='Setup certificates',
            stores=CertStore.all(),
            ca_certificates=ca_certificates,
            crl_certificates=crl_certificates,
            ocsp_certificates=ocsp_certificates,
            # user_certificates=ca_certificates,
            keysign=keysign,
            crlsign=crlsign,
            ocspsign=ocspsign,
            # usersign=usersign,
            initial=initial,
            form=self.form_class(
                ca=ca_certificates,
                crl=crl_certificates,
                ocsp=ocsp_certificates,
                # user=ca_certificates,
                initial=initial,
            )
        )
        return context

    def get(self, request, *args, **kwargs):
        if 'update' in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:certs_update'))
        context = self.get_context(request)
        return TemplateResponse(request, self.template, context)

    def post(self, request, *args, **kwargs):
        if 'update' not in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:certs_update'))
        context = self.get_context(request)
        form = self.form_class(
            ca=context['ca_certificates'],
            crl=context['crl_certificates'],
            ocsp=context['ocsp_certificates'],
            user=context['user_certificates'],
            data=request.POST,
            initial=context['initial'],
        )
        if form.is_valid():
            if form.has_changed():
                if 'submit_ca' in form.changed_data and 'ca' in form.changed_data:
                    ca = form.cleaned_data['ca']
                    Config.set_value(parameters.CERT_KEYSIGN, ca)
                    messages.add_message(request, messages.INFO, 'Changes saved')
                elif 'submit_crl' in form.changed_data and 'crl' in form.changed_data:
                    crl = form.cleaned_data['crl']
                    Config.set_value(parameters.CERT_CRLSIGN, crl)
                    messages.add_message(request, messages.INFO, 'Changes saved')
                elif 'submit_ocsp' in form.changed_data and 'ocsp' in form.changed_data:
                    ocsp = form.cleaned_data['ocsp']
                    Config.set_value(parameters.CERT_OCSPSIGN, ocsp)
                    messages.add_message(request, messages.INFO, 'Changes saved')
                elif 'submit_user' in form.changed_data and 'user' in form.changed_data:
                    user = form.cleaned_data['user']
                    Config.set_value(parameters.CERT_USERSIGN, user)
                    messages.add_message(request, messages.INFO, 'Changes saved')
                else:
                    messages.add_message(request, messages.WARNING, 'No changes done')
            url = reverse('admin:certs_setup')
            return HttpResponseRedirect(url)
        return TemplateResponse(request, self.template, context)


OPTION_PFX = 1
OPTION_KEYCERT = 2
OPTION_KEYGENCERT = 3
OPTION_GENERATE = 4
OPTIONS = [
    (OPTION_PFX, SafeString(
        '<span>PFX/PKCS#12:</span> Upload a PFX file with a private key and certificate.')),
    # (OPTION_KEYCERT, SafeString(
    #     '<span>Key+Cert:</span> Upload a key and certificate in separate files.')),
    # (OPTION_KEYGENCERT, SafeString(
    #     '<span>Key:</span> upload a key and display a form to generate a certificate.')),
    # (OPTION_GENERATE, SafeString(
    #     '<span></span>Generate a key/certificate in the server')),
]


class AddStep1Form(forms.Form):
    """Form to choose what to do next."""
    option = forms.ChoiceField(
        widget=forms.RadioSelect,
        choices=OPTIONS,
        label='Choose an option to continue:',
    )


class AddStep2PFX(AddStep1Form):
    """Form to upload a PFX file."""
    file = forms.FileField(
        label='PFX file',
    )
    store = forms.ChoiceField(
        label='Save the key/certificate in this store',
    )

    def __init__(self, stores=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        stores = stores or []
        self.fields['store'].choices = stores

    def clean(self):
        data = super().clean()
        if data['file'].size > 1 * 1024 * 1024:
            raise forms.ValidationError(
                'file too big (> 1MB)',
                code='file-too-big',
            )
        if data['file'].content_type != 'application/x-pkcs12':
            raise forms.ValidationError(
                'content-type not valid (not a PFX file?)',
                code='invalid-content-type',
            )
        try:
            pfx = data['file'].read()
            pfx = crypto.load_pkcs12(pfx)
            data['pfx'] = pfx
        except:
            self.add_error(
                'file', 'could not read the PFX file. Does it have a passphrase?')
        return data


class AddCertificateView(View):
    """Add a certificate to a store."""
    STEP_CHOOSE = 1
    STEP_CREATE = 2
    STEP_CONFIRM = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cert_stores = [(store.STORE_ID, name)
                            for name, store in CertStore.all()]

    def dispatch(self, request, *args, **kwargs):
        # Try to dispatch to the right method; if a method doesn't exist,
        # defer to the error handler. Also defer to the error handler if the
        # request method isn't on the approved list.
        handler = self.http_method_not_allowed
        if request.method.lower() in self.http_method_names:
            if request.method.lower() == 'get':
                handler = self.get
            else:
                step = kwargs.pop('step')
                if step == self.STEP_CREATE:
                    handler = self.post_create
                elif step == self.STEP_CONFIRM:
                    handler = self.post_confirm
        return handler(request, *args, **kwargs)

    def get_context(self, request, **kwargs):
        """Return a default context."""
        context = dict(
            admin.admin_site.each_context(request),
            title='Add a CA certificate',
        )

        return context

    def get(self, request, *args, **kwargs):
        """Begin the add certificate process by choosing how to add a certificate."""
        context = self.get_context(request)
        template = 'ca_admin/add_certs/step1.html'
        step = kwargs.pop('step')
        if step != self.STEP_CHOOSE:
            return HttpResponseRedirect(reverse('admin:certs_add'))
        form = AddStep1Form(
            initial={'option': OPTION_PFX},
        )
        context['form'] = form
        return TemplateResponse(request, template, context)

    def post_create(self, request, *args, **kwargs):
        """Render a form depending on the option chosen."""
        template = 'ca_admin/add_certs/step2.html'
        context = self.get_context(request)
        choose_form = AddStep1Form(
            request.POST,
        )
        if not choose_form.is_valid():
            messages.add_message(request, messages.WARNING,
                                 'Not a valid option')
            return HttpResponseRedirect(reverse('admin:certs_add'))

        option = int(choose_form.cleaned_data['option'])
        initial = {'option': option}
        if option == OPTION_PFX:
            form = AddStep2PFX(
                stores=self.cert_stores,
                initial=initial,
            )
        # TODO: Add the rest of the options
        context['form'] = form
        return TemplateResponse(request, template, context)

    def post_confirm(self, request, *args, **kwargs):
        """Process the request and store the new key/certificate."""
        form = AddStep1Form(
            request.POST
        )
        if form.is_valid():
            handler = None
            option = int(form.cleaned_data['option'])
            if option == OPTION_PFX:
                handler = self.post_confirm_pfx
            # TODO: Add the rest of the options
            if handler:
                return handler(request, *args, **kwargs)
        messages.add_message(request, messages.WARNING, 'Not a valid option')
        return HttpResponseRedirect(reverse('admin:certs_add'))

    def post_confirm_pfx(self, request, *args, **kwargs):
        """Process a PFX upload."""
        template = 'ca_admin/add_certs/step3.html'
        context = self.get_context(request)
        create_form = AddStep2PFX(
            stores=self.cert_stores,
            data=request.POST,
            files=request.FILES,
        )
        context['form'] = create_form
        if not create_form.is_valid():
            if create_form.non_field_errors():
                messages.add_message(
                    request, messages.WARNING,
                    'Not a valid PFX: %s' % create_form.non_field_errors()[0]
                )
            else:
                messages.add_message(
                    request, messages.WARNING,
                    'Not a valid PFX: %s' % create_form.errors['file'][0]
                )
            return HttpResponseRedirect(reverse('admin:certs_add'))

        pfx = create_form.cleaned_data['pfx']
        key_type = private_key_type(pfx)
        context['pfx'] = {
            'subject': subject_display(components_to_name(pfx.get_certificate().get_subject().get_components())),
            'type': c.KEY_TYPE[key_type],
            'bits': pfx.get_privatekey().bits,
        }

        store = CertStore.get_store(create_form.cleaned_data['store'])
        try:
            store.add_certificate(
                pfx.get_privatekey(),
                pfx.get_certificate(),
            )
        except CertificateExistsError:
            messages.add_message(request, messages.ERROR,
                                 'The certificate already exists')
            return HttpResponseRedirect(reverse('admin:certs_add'))

        create_form.fields['store'].disabled = True
        return TemplateResponse(request, template, context)
