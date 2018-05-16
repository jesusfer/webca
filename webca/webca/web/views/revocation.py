"""
Views related to the certificate revocation process.
"""
from django import http
from django.contrib import messages
from django.db.models import Q
from django.shortcuts import render
from django.urls import reverse

from webca.web.forms import RevocationForm
from webca.web.models import Certificate, Request, Revoked
from webca.web.views import WebCAView


class IndexView(WebCAView):
    """Welcome page for the revocation process."""
    template = 'webca/web/revocation/index.html'

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.context.update({
            'section_title': 'Revocation',
        })

    def get(self, request, *args, **kwargs):
        """Show the welcome page."""
        certificates = Certificate.objects.filter(
            Q(user=request.user),
            Q(csr__status=Request.STATUS_ISSUED),
        )
        certificates = [c for c in certificates if c.is_valid]
        self.context.update({
            'certificates': certificates,
        })
        return render(request, self.template, self.context)


class RevocationView(WebCAView):
    """Process the revocation of a certificate."""
    template = 'webca/web/revocation/revocation.html'
    form_class = RevocationForm

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.context.update({
            'section_title': 'Revocation',
            'section_url': reverse('revoke:index'),
            'page_title': 'Revoke a certificate',
        })

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
        self.context.update({
            'certificate': certificate,
            'form': self.form_class(),
        })
        return render(request, self.template, self.context)

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
            messages.add_message(request, messages.SUCCESS,
                                 'The certificate has been revoked.')
            return http.HttpResponseRedirect(reverse('revoke:index'))
        self.context.update({
            'certificate': certificate,
            'form': form,
        })
        return render(request, self.template, self.context)
