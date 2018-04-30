from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template import loader
from django.views import View

from webca.web.models import Request, Template
from webca.web.forms import RequestNewForm


class RequestView(View):
    def get(self, request, *args, **kwargs):
        request_list = Request.objects.filter(user=request.user)
        context = {
            'request_list': request_list,
        }
        return render(request, 'requests/index.html', context)


class RequestNewView(View):
    form_class = RequestNewForm
    initial = {}

    def get(self, request, *args, **kwargs):
        templates_available = len(Template.get_form_choices()) > 0
        context = {}
        if templates_available:
            form = self.form_class(initial=self.initial)
            context['form'] = form

        return render(request, 'requests/new.html', context)

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            new_req = Request()
            new_req.user = request.user
            new_req.subject = form.get_subject()
            new_req.csr = ''  # TODO: build a CSR from the form and the template
            new_req.template = Template.objects.get(pk=data['template'])
            new_req.save()
            return HttpResponseRedirect('/req/')
        else:
            context = {
                'form': form
            }
            return render(request, 'requests/new.html', context)
        return HttpResponseRedirect('/req/')
        # return render(request, self.template_name, {'form': form})
