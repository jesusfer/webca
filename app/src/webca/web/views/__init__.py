"""
General view classes.
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.views import View
from django.shortcuts import render, reverse


class WebCAView(View):
    """Class that views should inherit that support minimal context
    to render the pages correctly."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = {
            'title': 'WebCA',
            'section_title': None,
            'section_url': None,
            'page_title': None,
        }


class WebCAAuthView(LoginRequiredMixin, WebCAView):
    """Class that views should inherit when they need authenticated access."""
    pass

class IndexView(WebCAView):
    """Welcome page."""

    def get(self, request, *args, **kwargs):
        """Render the welcome page."""
        return render(request, 'webca/web/index.html', self.context)
