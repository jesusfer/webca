from django import forms
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.views import View

from webca.ca_admin import admin
from webca.web.models import CRLLocation


class CRLForm(forms.Form):
    crl_list = forms.ChoiceField(
        required=False,
    )
    remove = forms.CharField(
        required=False,
    )
    add = forms.CharField(
        required=False,
    )
    crl = forms.CharField(
        required=False,
    )

    def __init__(self, crl_list=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        crl_current = crl_list or []
        self.fields['crl_list'].choices = crl_current

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data['remove'] and not cleaned_data['crl_list']:
            self.add_error('crl_list', 'Choose one URL to remove it.')
        if cleaned_data['add'] and not cleaned_data['crl']:
            self.add_error('crl', 'Type a URL to add it.')
        # return cleaned_data


class CRLView(View):
    form_class = CRLForm

    def get_context(self, request, **kwargs):
        """Get a default context."""
        locations = CRLLocation.objects.all()
        crl_list = [(x.id, x.url) for x in locations.filter(deleted=False)]
        crl_historic = [(x.url, x.count) for x in locations]

        context = dict(
            admin.admin_site.each_context(request),
            title='CRL locations',
            crl_list=crl_list,
            crl_historic=crl_historic,
            form=self.form_class(
                crl_list=crl_list,
            )
        )
        return context

    def get(self, request, *args, **kwargs):
        context = self.get_context(request)
        return TemplateResponse(request, "ca_admin/crl.html", context)

    def post(self, request, *args, **kwargs):
        context = self.get_context(request)
        form = self.form_class(
            data=request.POST,
            crl_list=context['crl_list'],
        )
        context['form'] = form
        if form.is_valid():
            location = None
            if form.cleaned_data['remove']:
                id = form.cleaned_data['crl_list']
                location = CRLLocation.objects.get(pk=id)
                location.deleted = True
                location.save()
            elif form.cleaned_data['add']:
                url = form.cleaned_data['crl']
                location = CRLLocation.objects.filter(url=url).first()
                if location:
                    # If the URL existed before, undelete it
                    location.deleted = False
                    location.save()
                else:
                    location = CRLLocation(url=url)
                    location.save()
            context = self.get_context(request)
            if form.cleaned_data['remove']:
                context['form'].initial = {'crl': location.url}
        return TemplateResponse(request, "ca_admin/crl.html", context)
