"""
Login views.
"""

import secrets
from hashlib import sha256

from django import http
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.views import logout
from django.shortcuts import render, reverse

from webca.crypto.utils import int_to_hex
from webca.web.forms import LoginForm, SignupForm
from webca.web.views import WebCAView

User = get_user_model()


def logout_user(request, *args, **kwargs):
    """Log a user out."""
    logout(request)
    return http.HttpResponseRedirect(reverse('webca:index'))


def set_code(email):
    """Store the unique code in the user profile."""
    user = User.objects.filter(email=email).first()
    if not user:
        user = User.objects.create_user(
            username=sha256(email.encode('utf8')).hexdigest(),
            email=email,
        )
        user.is_active = False
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        user.save()
        # request.session['first_visit']=True
    user.ca_user.code = secrets.token_hex(16)
    if settings.DEBUG:
        print("Created code {} for {}".format(
            user.ca_user.code,
            user.username,
        ))
    return user.ca_user.save()


def is_code_valid(email, code):
    """Check if the unique code is valid for a user."""
    user = User.objects.filter(email=email).first()
    if not user:
        raise ValueError('email')
    stored_code = user.ca_user.code
    if stored_code == code:
        user.is_active = True
        user.save()
        user.ca_user.code = ''
        user.ca_user.save()
        return user
    return None


class SignupView(WebCAView):
    """Display and process the first step of the login."""
    template = 'webca/web/login/signup.html'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context.update({
            'section_title': 'Login',
        })

    def get(self, request, *args, **kwargs):
        """Render the signup form."""
        self.context.update({
            'form': SignupForm(),
        })
        return render(request, self.template, self.context)

    def post(self, request, *args, **kwargs):
        """Process a signup form."""
        form = SignupForm(request.POST)
        if form.is_valid():
            set_code(form.cleaned_data['email'])
            initial = {
                'email': form.cleaned_data['email'],
            }
            login_form = LoginForm(initial=initial)
            self.context.update({
                'form': login_form,
            })
            return render(request, self.template, self.context)
        self.context.update({
            'form': form,
        })
        return render(request, self.template, self.context)


class LoginView(WebCAView):
    """Log the user in."""
    template = 'webca/web/login/signup.html'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context.update({
            'section_title': 'Login',
        })

    def get(self, request, *args, **kwargs):
        """GET is not a valid Verb."""
        return http.HttpResponseRedirect(reverse('auth:signup'))

    def post(self, request, *args, **kwargs):
        """Process a code login."""
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user_code = form.cleaned_data['code']
            user = is_code_valid(email, user_code)
            if user:
                login(request, user,
                      backend='django.contrib.auth.backends.ModelBackend')
                return http.HttpResponseRedirect(reverse('webca:index'))
            else:
                messages.add_message(
                    request, messages.ERROR, 'The code is not correct')
            form = LoginForm(initial={
                'email': email,
            })
        self.context.update({
            'form': form,
        })
        return render(request, self.template, self.context)
