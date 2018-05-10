from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.views import View

from webca.ca_admin import admin  # import admin_site


class CRLView(View):
    def get(self, request, *args, **kwargs):
        context = dict(
            admin.admin_site.each_context(request),
            title='CRL',
        )
        return TemplateResponse(request, "ca_admin/crl.html", context)

    def post(self, request, *args, **kwargs):
        return HttpResponse('POST request!')
