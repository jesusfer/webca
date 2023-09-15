"""
Middleware for the web app.
"""
from webca.web.models import Template
from webca.web.rules import PERM_USE_TEMPLATE

class TemplatePermissionsMiddleware:
    """Adds the templates property to the User object in the request."""
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        if request.user.is_authenticated:
            available = []
            for template in Template.get_enabled():
                if request.user.has_perm(PERM_USE_TEMPLATE, template):
                    available.append(template)
            setattr(request.user, 'templates', available)

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response
