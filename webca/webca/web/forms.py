from django import forms

from webca.web.fields import SubjectAltNameCertificateField
from webca.web.models import Template
from webca.web.validators import valid_pem_csr, validate_csr_bits

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
        template_choices = kwargs.pop('template_choices', None)
        super().__init__(*args, **kwargs)
        self.fields['template'].choices = Template.get_form_choices(
            template_choices)
        # self.fields['template'] = forms.ChoiceField(
        #     choices=templates,
        #     label='Choose a template',
        # )


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
        label='Your CSR in PEM format',
        validators=[valid_pem_csr],
    )

    def __init__(self, template, template_choices=None, san_current=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.template_obj = template

        # if the form is built with some templates, we only show those
        if template_choices:
            templates = Template.get_form_choices(template_choices)
        else:
            templates = Template.get_form_choices()
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
            fields = ['cn', 'email', 'country', 'state', 'locality', 'org', 'ou']
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
            if not cleaned_data['cn']:
                # self.add_error('cn', 'This field is required')
                # self.add_error('email', 'This field is required')
                raise forms.ValidationError(
                    'At least Common Name must be present',
                    code='invalid-dn',
                )
        return cleaned_data

    def clean_csr(self):
        text = self.cleaned_data['csr']
        validate_csr_bits(text, self.template_obj.min_bits)
        return text
