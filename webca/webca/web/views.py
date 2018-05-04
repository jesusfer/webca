from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template import loader
from django.views import View

from webca.web.forms import RequestNewForm
from webca.web.models import Request, Template


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
        """GET method."""
        context = {}
        if request.user.templates:
            form = self.form_class(
                template_choices=request.user.templates,
                initial=self.initial
            )
            context['form'] = form

        return render(request, 'requests/new.html', context)

    def post(self, request, *args, **kwargs):
        """POST method."""
        form = self.form_class(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            new_req = Request()
            new_req.user = request.user
            new_req.subject = form.get_subject()
            new_req.csr = data['csr']
            template = Template.objects.get(pk=data['template'])
            if template not in request.user.templates:
                raise ValidationError(
                    'Not a valid template',
                    code='invalid-template',
                    )
            new_req.template = template
            new_req.save()
            return HttpResponseRedirect('/req/')
        else:
            context = {
                'form': form
            }
            return render(request, 'requests/new.html', context)
        return HttpResponseRedirect('/req/')
        # return render(request, self.template_name, {'form': form})
