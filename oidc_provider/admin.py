from hashlib import sha224
from random import randint
from uuid import uuid4

from django.forms import ModelForm
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _
from django.utils.crypto import get_random_string

from oidc_provider.models import Client, Code, Token, RSAKey, UserConsent



class ClientForm(ModelForm):

    class Meta:
        model = Client
        exclude = []

    def __init__(self, *args, **kwargs):
        super(ClientForm, self).__init__(*args, **kwargs)
        # self.fields['client_id'].required = False
        # self.fields['client_id'].widget.attrs['disabled'] = 'true'
        # self.fields['client_secret'].required = False
        # self.fields['client_secret'].widget.attrs['disabled'] = 'true'

    def clean_client_id(self):
        instance = getattr(self, 'instance', None)
        if instance and instance.pk:
            return self.cleaned_data['client_id']
        else:
            return get_random_string(12)

    def clean_client_secret(self):
        instance = getattr(self, 'instance', None)

        if self.cleaned_data['client_type'] != 'confidential':
            return ''

        if instance and instance.pk:
            return self.cleaned_data['client_secret']

        return sha224(uuid4().hex.encode()).hexdigest()


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):

    fieldsets = [
        [_(u''), {
            'fields': (
                'name', 'owner', 'client_type', 'response_type', '_redirect_uris', 'jwt_alg',
                'require_consent', 'reuse_consent'),
        }],
        [_(u'Credentials'), {
            'fields': ('client_id', 'client_secret'),
        }],
        [_(u'Information'), {
            'fields': ('contact_email', 'website_url', 'terms_url', 'logo', 'date_created'),
        }],
        [_(u'Session Management'), {
            'fields': ('_post_logout_redirect_uris',),
        }],
    ]
    form = ClientForm
    list_display = ['name', 'client_id', 'response_type', 'date_created']
    readonly_fields = ['date_created']
    search_fields = ['name']
    raw_id_fields = ['owner']


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(RSAKey)
class RSAKeyAdmin(admin.ModelAdmin):

    readonly_fields = ['kid']


@admin.register(UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    pass
