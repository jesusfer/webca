"""
Login views.
"""

import base64
import secrets
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django import http
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.views import logout
from django.shortcuts import render, reverse

from webca.web.forms import EmailLoginForm, KeysLoginForm, CodeLoginForm
from webca.web.views import WebCAAuthView, WebCAView

User = get_user_model()

def logout_user(request, *args, **kwargs):
    """Log a user out."""
    logout(request)
    return http.HttpResponseRedirect(reverse('webca:index'))

def set_code(email):
    """Store the unique code in the user profile, creating the user if it's the first time."""
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


class CodeLoginView(WebCAView):
    """Display and process the first step of the login."""
    template = 'webca/web/auth/code.html'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context.update({
            'section_title': 'Login',
        })

    def get(self, request, *args, **kwargs):
        """Render the signup form."""
        self.context.update({
            'form': EmailLoginForm(),
        })
        return render(request, self.template, self.context)

    def post(self, request, *args, **kwargs):
        """Process a signup form."""
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            set_code(form.cleaned_data['email'])
            initial = {
                'email': form.cleaned_data['email'],
            }
            login_form = CodeLoginForm(initial=initial)
            self.context.update({
                'form': login_form,
            })
            return render(request, self.template, self.context)
        self.context.update({
            'form': form,
        })
        return render(request, self.template, self.context)


class CodeLoginSubmitView(WebCAView):
    """Log the user in."""
    template = 'webca/web/auth/code.html'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context.update({
            'section_title': 'Login',
        })

    def get(self, request, *args, **kwargs):
        """GET is not a valid Verb."""
        return http.HttpResponseRedirect(reverse('auth:code'))

    def post(self, request, *args, **kwargs):
        """Process a code login."""
        form = CodeLoginForm(request.POST)
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
            form = CodeLoginForm(initial={
                'email': email,
            })
        self.context.update({
            'form': form,
        })
        return render(request, self.template, self.context)



class KeysSetupView(WebCAAuthView):
    """Setup the browser keys for faster login."""

    def get(self, request, *args, **kwargs):
        self.context.update({
            'section_title': 'Setup browser keys',
        })
        return render(request, 'webca/web/auth/keys_setup.html', self.context)

    def post(self, request, *args, **kwargs):
        """Store a user's public key."""
        if not 'key' in request.POST:
            return http.HttpResponseBadRequest()
        public_key = request.POST['key'] or None
        if not public_key:
            return http.HttpResponseBadRequest()
        request.user.ca_user.add_key(public_key)
        return http.HttpResponse()

class KeysLoginView(WebCAView):
    
    def get(self, request, *args, **kwargs):
        """Try to log the user in with a key pair."""
        self.context.update({
            'section_title': 'Login',
        })
        return render(request, 'webca/web/auth/keys_login.html', self.context)

    def post(self, request, *args, **kwargs):
        """Check if a signature challenge is valid."""
        form = KeysLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            signed = form.cleaned_data['signed']
            user = User.objects.filter(email=email).first()
            if user:
                for key in user.ca_user.public_keys:
                    public_key = load_pem_public_key(key.encode('utf8'), default_backend())
                    if isinstance(public_key, rsa.RSAPublicKey):
                        try:
                            public_key.verify(
                                base64.b64decode(signed),
                                email.encode('utf8'),
                                padding.PKCS1v15(),
                                hashes.SHA512(),
                            )
                            login(request, user,
                                  backend='django.contrib.auth.backends.ModelBackend')
                            return http.HttpResponse(reverse('webca:index'))
                        except InvalidSignature:
                            print('Signature not valid')
        return http.HttpResponse(reverse('auth:code'))
