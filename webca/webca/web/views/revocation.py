"""
Views related to the certificate revocation process.
"""
from urllib.parse import urlparse

from django import forms, http
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from django.contrib import messages

from webca.crypto.utils import export_certificate, export_csr
from webca.web.forms import RequestNewForm, TemplateSelectorForm, RevocationForm
from webca.web.models import Certificate, Request, Template, Revoked


class IndexView(View):
    """Welcome page for the revocation process."""
    template = 'webca/web/revocation/index.html'

    def get(self, request, *args, **kwargs):
        """Show the welcome page."""
        certificates = Certificate.objects.filter(
            Q(user=request.user),
            Q(csr__status=Request.STATUS_ISSUED),
        )
        certificates = [c for c in certificates if c.is_valid]
        context = {
            'certificates': certificates,
        }
        return render(request, self.template, context)


class RevocationView(View):
    """Process the revocation of a certificate."""
    template = 'webca/web/revocation/revocation.html'
    form_class = RevocationForm

    def get(self, request, *args, **kwargs):
        """Show the revocation form."""
        certificate_id = kwargs.pop('certificate_id', None)
        if not certificate_id:
            return http.HttpResponseRedirect(reverse('revoke:index'))
        certificate = Certificate.objects.filter(
            Q(user=request.user),
            Q(csr__status=Request.STATUS_ISSUED),
            Q(pk=certificate_id),
        ).first()
        if not certificate:
            return http.HttpResponseRedirect(reverse('revoke:index'))
        context = {
            'certificate': certificate,
            'form': self.form_class(),
        }
        return render(request, self.template, context)

    def post(self, request, *args, **kwargs):
        """Process the revocation of a certificate."""
        certificate_id = kwargs.pop('certificate_id', None)
        if not certificate_id:
            return http.HttpResponseRedirect(reverse('revoke:index'))
        certificate = Certificate.objects.filter(
            Q(user=request.user),
            Q(csr__status=Request.STATUS_ISSUED),
            Q(pk=certificate_id),
        ).first()
        if not certificate:
            return http.HttpResponseRedirect(reverse('revoke:index'))
        form = self.form_class(
            request.POST,
        )
        if form.is_valid():
            revoke = Revoked()
            revoke.certificate = certificate
            revoke.reason = form.cleaned_data['reason']
            revoke.save()
            messages.add_message(request, messages.INFO,
                'The certificate has been revoked.',
            )
            return http.HttpResponseRedirect(reverse('revoke:index'))
        context = {
            'certificate': certificate,
            'form': form,
        }
        return render(request, self.template, context)
