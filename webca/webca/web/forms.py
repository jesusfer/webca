from django import forms

from webca.crypto.constants import REV_USER
from webca.crypto.utils import import_csr, public_key_type
from webca.utils import dict_as_tuples
from webca.web.fields import SubjectAltNameCertificateField
from webca.web.models import Template
from webca.web.validators import (valid_country_code, valid_pem_csr,
                                  validate_csr_bits, validate_csr_key_usage)

NAME_DICT = {
    'country': 'C',
    'state': 'ST',
    'locality': 'L',
    'org': 'O',
    'ou': 'OU',
    'cn': 'CN',
    'email': 'emailAddress',
}


class TemplateSelectorForm(forms.Form):
    template = forms.ChoiceField(
        label='Choose a template',
    )

    def __init__(self, *args, **kwargs):
        """Pass template_choices to limit the choices in the template selector."""
        template_choices = kwargs.pop('template_choices', [])
        super().__init__(*args, **kwargs)
        templates = Template.get_form_choices(template_choices)
        if templates:
            self.fields['template'].choices = templates
        else:
            self.fields['template'].choices = [('', 'There are no available templates')]


class RequestNewForm(forms.Form):
    """
    Form used to create a certificate request.

    Arguments:
        template_choices: list of Template
        template: Template chosen by the user
        san_current: filled in SAN names
    """
    template = forms.ChoiceField(
        label='Template',
    )
    country = forms.CharField(
        max_length=2,
        required=False,
        label='Country (2 letters)',
        validators=[valid_country_code],
    )
    state = forms.CharField(
        max_length=50,
        required=False,
        label='State or province',
    )
    locality = forms.CharField(
        max_length=50,
        required=False,
        label='Locality',
    )
    org = forms.CharField(
        max_length=50,
        required=False,
        label='Organization',
    )
    ou = forms.CharField(
        max_length=50,
        required=False,
        label='Organizational Unit',
    )
    cn = forms.CharField(
        max_length=50,
        required=False,
        label='Common Name',
    )
    email = forms.EmailField(
        max_length=50,
        required=False,
        label='Email Address',
    )
    csr = forms.CharField(
        widget=forms.Textarea,
        label='Paste here your CSR in PEM format',
        validators=[valid_pem_csr],
    )

    def __init__(self, template, template_choices=None, san_current=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.template_obj = template
        template_choices = template_choices or []
        # if the form is built with some templates, we only show those
            templates = Template.get_form_choices(template_choices)
        self.fields['template'].choices = templates

        if self.template_obj.san_type == Template.SAN_SHOWN:
            self.fields['san'] = SubjectAltNameCertificateField(
                san_prefixes=self.template_obj.allowed_san,
                san_current=san_current,
                label='Subject Alternative Names',
                required=False,
            )

        # Set up required fields per subject type
        self.fields['cn'].required = True
        if self.template_obj.required_subject == Template.SUBJECT_USER:
            self.fields['email'].required = True
        elif self.template_obj.required_subject == Template.SUBJECT_DN:
            self.fields['country'].required = True
            self.fields['state'].required = True
            self.fields['locality'].required = True
            self.fields['org'].required = True
            self.fields['ou'].required = True

    def get_subject(self):
        """Return the subject in OpenSSL string format."""
        if self.is_valid():
            data = self.cleaned_data
            value = ''
            fields = ['cn', 'email', 'country',
                      'state', 'locality', 'org', 'ou']
            for component in fields:
                if data[component]:
                    value += '/%s=%s' % (NAME_DICT[component], data[component])
            return value
        return None

    def clean(self):
        cleaned_data = super().clean()
        # TODO: logic for subject names missing
        if self.template_obj.required_subject == Template.SUBJECT_DN_PARTIAL:
            # At least common name should be set
            if 'cn' not in cleaned_data:
                # self.add_error('cn', 'This field is required')
                # self.add_error('email', 'This field is required')
                raise forms.ValidationError(
                    'At least Common Name must be present',
                    code='invalid-dn',
                )
        return cleaned_data

    def clean_country(self):
        """Make the country code uppercase."""
        value = self.cleaned_data['country']
        if value:
            value = value.upper()
        return value


    def clean_csr(self):
        """Extended checks in the Certificate Request."""
        text = self.cleaned_data['csr']
        valid_pem_csr(text)
        key_type = public_key_type(import_csr(text))
        min_bits = self.template_obj.min_bits_for(key_type)
        validate_csr_bits(text, min_bits)
        validate_csr_key_usage(text, self.template_obj)
        return text


class RevocationForm(forms.Form):
    reason = forms.ChoiceField(
        choices=dict_as_tuples(REV_USER),
        label='Reason for revocation',
    )

    confirm = forms.BooleanField(
        label='I understand that revocation is a one-way process and cannot be undone',
    )
