from django import forms
from webca.web.models import Template

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
        label='Country'
    )
    state = forms.CharField(
        max_length=50,
        required=False,
        label='State or province'
    )
    locality = forms.CharField(
        max_length=50,
        required=False,
        label='Locality'
    )
    org = forms.CharField(
        max_length=50,
        required=False,
        label='Organization'
    )
    ou = forms.CharField(
        max_length=50,
        required=False,
        label='Organizational Unit'
    )
    cn = forms.CharField(
        max_length=50,
        required=False,
        label='Common Name'
    )
    email = forms.EmailField(
        max_length=50,
        required=False,
        label='Email Address'
    )
    csr = forms.CharField(
        widget=forms.Textarea,
        label='Your CSR in PEM format'
    )
    template = forms.ChoiceField(
        choices=Template.get_form_choices,
        label='Choose a template'
    )

    def get_subject(self):
        if self.is_valid():
            f = self.cleaned_data
            s = '/'
            for c in ['cn', 'email', 'country', 'state', 'locality', 'org', 'ou']:
                if len(f[c]) > 0:
                    s += '%s=%s/' % (NAME_DICT[c], f[c])
            return s
