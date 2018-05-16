"""
General view classes.
"""

from django.http import HttpResponse
from django.views import View
from django.shortcuts import render


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


class IndexView(WebCAView):
    """Welcome page."""

    def get(self, request, *args, **kwargs):
        """Render the welcome page."""
        return render(request, 'webca/web/index.html', self.context)
