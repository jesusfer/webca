from django import forms

from webca.web.models import Template
from webca.web.validators import valid_pem_csr

NAME_DICT = {
    'country': 'C',
    'state': 'ST',
    'locality': 'L',
    'org': 'O',
    'ou': 'OU',
    'cn': 'CN',
    'email': 'emailAddress',
}


class RequestNewForm(forms.Form):
    country = forms.CharField(
        max_length=2,
        required=False,
        label='Country',
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

    def __init__(self, *args, **kwargs):
        """Pass template_choices to limit the choices in the template selector."""
        template_choices = kwargs.pop('template_choices', None)
        super().__init__(*args, **kwargs)
        # if the form is built with some templates, we only show those
        if template_choices:
            templates = Template.get_form_choices(template_choices)
        else:
            templates = Template.get_form_choices()
        # Add it here so that we can use dynamic choices
        self.fields['template'] = forms.ChoiceField(
            choices=templates,
            label='Choose a template',
        )

    def get_subject(self):
        """Return the subject in OpenSSL string format."""
        if self.is_valid():
            data = self.cleaned_data
            value = '/'
            for component in ['cn', 'email', 'country', 'state', 'locality', 'org', 'ou']:
                if data[component]:
                    value += '%s=%s/' % (NAME_DICT[component], data[component])
            return value
        return ''
