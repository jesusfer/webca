from django import forms
from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import reverse
from django.views import View
from django.core import serializers

from webca.ca_admin import admin
from webca.web.models import CRLLocation,Revoked
from webca.config.models import ConfigurationObject as Config
from webca.config.constants import CRL_CONFIG
from webca.config import new_crl_config

import json

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


class CRLView(View):
    form_class = CRLForm
    template = 'ca_admin/crl.html'

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
        if 'update' in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:crl'))
        context = self.get_context(request)
        if 'deleted'in request.GET.keys() and request.GET.get('crl'):
            loc_id = int(request.GET.get('crl'))
            try:
                location = CRLLocation.objects.get(pk=loc_id)
                context['form'].initial = {'crl': location.url}
            except CRLLocation.DoesNotExist:
                pass
        return TemplateResponse(request, self.template, context)

    def post(self, request, *args, **kwargs):
        if 'update' not in kwargs.keys():
            return HttpResponseRedirect(reverse('admin:crl'))
        context = self.get_context(request)
        form = self.form_class(
            data=request.POST,
            crl_list=context['crl_list'],
        )
        context['form'] = form
        if form.is_valid():
            location = None
            if form.cleaned_data['remove']:
                loc_id = form.cleaned_data['crl_list']
                location = CRLLocation.objects.get(pk=loc_id)
                location.deleted = True
                location.save()
                messages.add_message(request, messages.INFO, 'CRL location deleted')
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
                messages.add_message(request, messages.INFO, 'CRL location added')
            url = reverse('admin:crl')
            if form.cleaned_data['remove']:
                url += '?crl={}&deleted'.format(
                    location.id,
                )
            return HttpResponseRedirect(url)
        messages.add_message(request, messages.ERROR, 'Please check below')
        return TemplateResponse(request, self.template, context)


class CRLConfigForm(forms.Form):
    days = forms.IntegerField(
        min_value=1,
    )
    delta_days = forms.IntegerField(
        min_value=1,
    )
    path = forms.CharField(

    )

class CRLStatusView(View):
    template = 'ca_admin/crl_status.html'
    form_class = CRLConfigForm

    def get_context(self, request):
        crl_config = json.loads(Config.get_value(CRL_CONFIG))
        initial = {
            'path':crl_config['path'],
            'days':crl_config['days'],
            'delta_days':crl_config['delta_days'],
        }
        context = dict(
            admin.admin_site.each_context(request),
            title='CRL Status',
            config=crl_config,
            revoked_count=Revoked.objects.count(),
            initial=initial,
            form=self.form_class(
                initial=initial,
            )
        )
        return context        

    def get(self, request, *args, **kwargs):
        context = self.get_context(request)
        return TemplateResponse(request, self.template, context)

    def post(self, request, *args, **kwargs):
        context = self.get_context(request)
        form = self.form_class(
            request.POST,
            initial=context['initial'],
        )
        context['form'] = form
        if form.is_valid():
            if form.has_changed():
                print(form.cleaned_data)
                for key in form.changed_data:
                    new_value = form.cleaned_data[key]
                    context['config'][key] = new_value
                # TODO: If days have changed, a CRL may need to be published
                value = json.dumps(context['config'])
                Config.set_value(CRL_CONFIG, value)
                messages.add_message(request, messages.INFO, 'Settings updated')
            return HttpResponseRedirect(reverse('admin:crl_status'))
        print(form.errors)
        messages.add_message(request, messages.ERROR, 'Please check below')
        return TemplateResponse(request, self.template, context)
