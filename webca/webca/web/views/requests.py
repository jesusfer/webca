"""
Views related to the certificate request process.
"""
from urllib.parse import urlparse

from django import http
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.shortcuts import render
from django.urls import reverse

from webca.crypto import constants as c
from webca.crypto.utils import export_certificate, export_csr
from webca.web.forms import RequestNewForm, TemplateSelectorForm
from webca.web.models import Certificate, Request, Template
from webca.web.views import WebCAAuthView


def is_referrer_ok(request, allowed):
    """Check if the referer is an allowed URL."""
    if 'HTTP_REFERER' in request.META.keys():
        ref = request.META['HTTP_REFERER']
        ref_path = urlparse(ref)[2]
        if ref_path not in allowed:
            return False
    return True


@login_required
def view_certificate(request, request_id):
    """
    Displays a certificate as text or the CSR if there is no certificate issued.
    """
    try:
        request = Request.objects.get(
            Q(pk=request_id),
            Q(user=request.user),
        )
    except Request.DoesNotExist:
        return http.HttpResponseNotFound('Cannot find the request')
    try:
        content = export_certificate(
            request.certificate.get_certificate(), text=True)
    except Certificate.DoesNotExist:
        content = export_csr(request.get_csr(), text=True)
    return http.HttpResponse(content, content_type='text/plain')


@login_required
def download_certificate(request, request_id, pem=True):
    """Downloads a certificate from a request."""
    try:
        request = Request.objects.get(
            Q(pk=request_id),
            Q(user=request.user),
        )
    except Request.DoesNotExist:
        return http.HttpResponseRedirect(reverse('request:index'))

    try:
        x509 = request.certificate.get_certificate()
    except Certificate.DoesNotExist:
        return http.HttpResponseRedirect(reverse('request:index'))

    if pem:
        content = export_certificate(x509, pem=True)
        content_type = 'application/x-pem-file'
        extension = '.cer'
    else:
        content = export_certificate(x509, pem=False)
        content_type = 'application/pkix-cert'
        extension = '.cer'

    response = http.HttpResponse(content_type=content_type)
    response['Content-Disposition'] = 'attachment; filename="{}{}"'.format(
        request.certificate.subject_filename(),
        extension,
    )
    response.write(content)
    return response


@login_required
def request_confirmation(request):
    """
    Confirmation that a request has been successfully created.
    """
    previous = [
        reverse('request:submit'),
        reverse('request:new'),
    ]
    if not is_referrer_ok(request, previous):
        return render(request, 'webca/web/requests/referer.html', {})
    context = {
        'title': 'WebCA',
        'section_title': 'Requests',
        'section_url': reverse('request:index'),
        'page_title': 'New request',
    }
    return render(request, 'webca/web/requests/ok.html', context)


def view_examples(request):
    """
    Render the examples template.
    """
    context = {
        'title': 'WebCA',
        'section_title': 'Requests',
        'section_url': reverse('request:index'),
        'page_title': 'Examples',
    }
    return render(request, 'webca/web/requests/examples.html', context)


class IndexView(WebCAAuthView):
    """Index view for the requests section."""
    form_class = TemplateSelectorForm

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.context.update({
            'section_title': 'Requests',
            'show_sidebar': True,
        })

    def get(self, request, *args, **kwargs):
        """Display welcome page."""
        request_list = Request.objects.filter(user=request.user)
        self.context.update({
            'request_list': request_list,
            'templates': request.user.templates,
            'templates_form': self.form_class(
                template_choices=request.user.templates,
            ),
            'issued': Request.STATUS_ISSUED,
        })
        return render(request, 'webca/web/requests/index.html', self.context)


class NewView(WebCAAuthView):
    """Create a request for a certificate using a template."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.context.update({
            'section_title': 'Requests',
            'section_url': reverse('request:index'),
            'page_title': 'New request',
        })

    def get(self, request, *args, **kwargs):
        """GET is not a correct verb."""
        self.context.update({
            'error': "You can't access this page like this."
        })
        return render(request, 'webca/web/requests/error.html', self.context)

    def post(self, request, *args, **kwargs):
        """Start a new request for a given template."""
        previous = [
            reverse('request:index'),
        ]
        if not is_referrer_ok(request, previous):
            return render(request, 'webca/web/requests/referer.html', {})
        template_form = TemplateSelectorForm(
            request.POST,
            template_choices=request.user.templates,
        )
        if not template_form.is_valid():
            return http.HttpResponseRedirect(reverse('request:index'))
        template_id = int(template_form.cleaned_data['template'])
        template = [x for x in request.user.templates if x.id == template_id][0]
        initial = {
            'template': template_id
        }
        request_form = RequestNewForm(
            template=template,
            initial=initial,
        )
        self.context.update({
            'DN': Template.SUBJECT_DN,
            'CN': Template.SUBJECT_CN,
            'DN_PARTIAL': Template.SUBJECT_DN_PARTIAL,
            'USER': Template.SUBJECT_USER,
            'allowed_key_types': template.allowed_key_types(),
            'KEY_RSA': c.KEY_RSA,
            'KEY_DSA': c.KEY_DSA,
            'KEY_EC': c.KEY_EC,
            'form': request_form,
        })
        return render(request, 'webca/web/requests/new.html', self.context)


class SubmitView(WebCAAuthView):
    """Process a request submission."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.context.update({
            'section_title': 'Requests',
            'section_url': reverse('request:index'),
            'page_title': 'New request',
        })

    def get(self, request, *args, **kwargs):
        """GET is not a correct verb."""
        self.context.update({
            'error': "You can't access this page like this."
        })
        return render(request, 'webca/web/requests/error.html', self.context)

    def post(self, request, *args, **kwargs):
        """POST method."""
        previous = [
            reverse('request:new'),
            reverse('request:submit'),
        ]
        if not is_referrer_ok(request, previous):
            return render(request, 'webca/web/requests/referer.html', {})
        template_id = int(request.POST.get('template'))
        template = [x for x in request.user.templates if x.id == template_id][0]
        san_current = []
        if request.POST.getlist('san'):
            san_current = request.POST.getlist('san')
        form = RequestNewForm(
            data=request.POST,
            template_choices=request.user.templates,
            template=template,
            san_current=san_current,
        )
        if form.is_valid():
            data = form.cleaned_data
            new_req = Request()
            new_req.user = request.user
            new_req.subject = form.get_subject()
            new_req.csr = data['csr']
            if san_current:
                san = ','.join(data['san'])
                new_req.san = san
            template = Template.objects.get(pk=data['template'])
            if template not in request.user.templates:
                raise ValidationError(
                    'Not a valid template',
                    code='invalid-template',
                )
            new_req.template = template
            if template.auto_sign:
                new_req.approved = True
            new_req.save()
        else:
            messages.add_message(request, messages.ERROR,
                                 'Please review the errors below')
            self.context.update({
                'DN': Template.SUBJECT_DN,
                'CN': Template.SUBJECT_CN,
                'DN_PARTIAL': Template.SUBJECT_DN_PARTIAL,
                'USER': Template.SUBJECT_USER,
                'allowed_key_types': template.allowed_key_types(),
                'KEY_RSA': c.KEY_RSA,
                'KEY_DSA': c.KEY_DSA,
                'KEY_EC': c.KEY_EC,
                'form': form,
            })
            return render(request, 'webca/web/requests/new.html', self.context)
        # TODO: for now a static confirmation page should be ok
        messages.add_message(request, messages.SUCCESS, 'Request submitted.')
        return http.HttpResponseRedirect(reverse('request:ok'))
