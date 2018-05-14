"""
Views related to the certificate revocation process.
"""
from urllib.parse import urlparse

from django import http
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.shortcuts import render
from django.urls import reverse
from django.views import View

from webca.crypto.utils import export_certificate, export_csr
from webca.web.forms import RequestNewForm, TemplateSelectorForm
from webca.web.models import Certificate, Request, Template


class IndexView(View):
    """Welcome page for the revocation process."""
    template = 'webca/web/revocation/index.html'

    def get(self, request, *args, **kwargs):
        """Show the welcome page."""
        certificates = Certificate.objects.filter(
            Q(user=request.user),
        )
        certificates = [c for c in certificates if c.is_valid]
        context = {
            'certificates': certificates,
        }
        return render(request, self.template, context)
