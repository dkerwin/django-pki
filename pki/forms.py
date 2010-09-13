from django import forms
from django.forms.util import ErrorList
from django.utils.safestring import mark_safe

from pki.models import *
from openssl import md5_constructor
import re

##------------------------------------------------------------------##
## Form validation
##------------------------------------------------------------------##

class CertificateAuthorityForm(forms.ModelForm):
    """Validation class for CertificateAuthority form"""
    
    passphrase        = forms.CharField(widget=forms.PasswordInput)
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    
    class Meta:
        model = CertificateAuthority
    
    def clean(self):
        """Verify crucial fields"""
        
        cleaned_data = self.cleaned_data
        
        action = cleaned_data.get('action')
        parent = cleaned_data.get('parent')
        pf = cleaned_data.get('passphrase')
        enc_p_pf = None

        if action in ('create', 'renew'):
            ## Check if name contains invalid chars
            name = cleaned_data.get('name')
            
            if name != None and re.search('[^a-zA-Z0-9-_\.]', name):
                self._errors['name'] = ErrorList(['Name may only contain characters in range a-Z0-9_-.'])
            
            ## Verify passphrase length
            if action == 'create' and pf and len(pf) < 8:
                self._errors['passphrase'] = ErrorList(['Passphrase has to be at least 8 characters long'])
            
            ## Take care that parent is active when action is revoke
            if action == 'renew':
                ca = CertificateAuthority.objects.get(name='%s' % name)
                
                if ca.parent is not None and ca.parent.active is not True:
                    self._errors['action'] = ErrorList(['Cannot renew CA certificate when parent "%s" isn\'t active!' % ca.parent.name])
                    return cleaned_data
                
                ## Self-signed renew. compare passphrase
                if ca.parent is None:
                    if not pf or ca.passphrase != md5_constructor(pf).hexdigest():
                        self._errors['passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % name])
            
            if parent:                
                ca = CertificateAuthority.objects.get(name='%s' % parent)
                p_pf = cleaned_data.get('parent_passphrase')
                if p_pf: enc_p_pf = md5_constructor(p_pf).hexdigest()
                
                ## Check if parent allows sub CA
                if not ca.subcas_allowed:
                    self._errors['parent'] = ErrorList(['Parent CA %s doesn\'t allow a sub CA. Only non CA certificates can be created' % ca.name])
                    
                ## Check parent passphrase if not RootCA
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent])
        
        elif action == 'revoke':
            
            if parent:
                ca = CertificateAuthority.objects.get(name='%s' % parent)
                enc_p_pf = md5_constructor(cleaned_data.get('parent_passphrase')).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA %s' % parent])
            else:
                self._errors['action'] = ErrorList(['You cannot revoke a self-signed root certificate as this would break the whole chain!'])
        
        return cleaned_data

class CertificateForm(forms.ModelForm):
    """Validation class for Certificate form"""
    
    passphrase        = forms.CharField(widget=forms.PasswordInput, required=False)
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    pkcs12_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    
    class Meta:
        model = Certificate
    
    def clean(self):
        """Verify crucial fields"""
        
        cleaned_data = self.cleaned_data
        
        action = cleaned_data.get('action')
        parent = cleaned_data.get('parent')
        pf = cleaned_data.get('passphrase')
        p_pf = cleaned_data.get('parent_passphrase')
        subjaltname = cleaned_data.get('subjaltname')
        pkcs12_passphrase = cleaned_data.get('pkcs12_passphrase')
        pkcs12_encoded = cleaned_data.get('pkcs12_encoded')
        
        print "P12: %s %s" % (pkcs12_passphrase, pkcs12_encoded)
        
        enc_p_pf = None
        
        if action in ('create', 'renew'):
            ## Check if name contains invalid chars
            name = cleaned_data.get('name')
            
            if name != None and re.search('[^a-zA-Z0-9-_\.]', name):
                self._errors['name'] = ErrorList(['Name may only contain characters in range a-Z0-9'])
            
            ## Verify passphrase length
            if action == 'create' and pf and len(pf) < 8:
                self._errors['passphrase'] = ErrorList(['Passphrase has to be at least 8 characters long'])
            
            ## Verify that pkcs12 passphrase isn't empty when encoding is requested
            if pkcs12_encoded and len(pkcs12_passphrase) < 8:
                self._errors['pkcs12_passphrase'] = ErrorList(['PKCS12 passphrase has to be at least 8 characters long'])
            
            ## Take care that parent is active when action is revoke
            if action == 'renew':
                cert = Certificate.objects.get(name='%s' % name)
                
                if cert.parent is not None and cert.parent.active is not True:
                    self._errors['action'] = ErrorList(['Cannot renew certificate when parent CA "%s" isn\'t active!' % cert.parent.name])
                    return cleaned_data
            
            if parent:
                ca = CertificateAuthority.objects.get(name='%s' % parent)
                if p_pf: enc_p_pf = md5_constructor(p_pf).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA %s' % parent])
            else:
                self._errors['parent'] = ErrorList(['You cannot renew a certificate while the parent is not active. Renew requires the intial parent to be active'])
            
            ## Verify subjAltName
            if subjaltname and len(subjaltname) > 0:
                allowed = { 'email': '^copy|\w+\@[\w\.]+\.\w+$',
                            'IP'   : '^[\d\.\:]+$',
                            'DNS'  : '^[a-zA-Z0-9\-\.]+$',
                          }
                items = subjaltname.split(',')
                
                for i in items:
                    kv  = i.split(':')
                    key = kv[0].lstrip().rstrip()
                    val = kv[1].lstrip().rstrip()
                    
                    if key in allowed:
                        if not re.match( allowed[key], val ):
                            self._errors['subjaltname'] = ErrorList(['Invalid subjAltName value supplied: \"%s\"' % i])
                    else:
                        self._errors['subjaltname'] = ErrorList(['Invalid subjAltName key supplied: "%s" (supported are %s)' % (key, ', '.join(allowed.keys()))])
        elif action == 'revoke':
            if parent:
                ca = CertificateAuthority.objects.get(name='%s' % parent)
                if p_pf: enc_p_pf = md5_constructor(p_pf).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA %s' % parent])
        elif action == 'update':
            ## Verify that pkcs12 passphrase isn't empty when encoding is requested
            if pkcs12_encoded and len(pkcs12_passphrase) < 8:
                self._errors['pkcs12_passphrase'] = ErrorList(['PKCS12 passphrase has to be at least 8 characters long'])
        
        return cleaned_data

##------------------------------------------------------------------##
## Dynamic forms
##------------------------------------------------------------------##

class CaPassphraseForm(forms.Form):
    passphrase = forms.CharField(max_length=100, widget=forms.PasswordInput)
    ca_id      = forms.CharField(widget=forms.HiddenInput)
    
    def clean(self):
        """Verify crucial fields"""
        
        cleaned_data = self.cleaned_data
        passphrase   = cleaned_data.get('passphrase')
        
        if passphrase: 
            e_passphrase = md5_constructor(cleaned_data.get('passphrase')).hexdigest()
            ca_id        = cleaned_data.get('ca_id')
            ca           = CertificateAuthority.objects.get(pk=ca_id)
            
            if ca.passphrase != e_passphrase:
                self._errors["passphrase"] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA %s' % ca.name])
        else:
            self._errors["passphrase"] = ErrorList(['Passphrase is missing!'])
        
        return cleaned_data

##------------------------------------------------------------------##
## Readonly setup
##------------------------------------------------------------------##

class ReadOnlyWidget(forms.Widget):
    def __init__(self, original_value, display_value):
        self.original_value = original_value
        self.display_value = display_value
        
        super(ReadOnlyWidget, self).__init__()
    
    def render(self, name, value, attrs=None):
        if self.display_value is not None:
            return mark_safe(unicode(self.display_value))
        return mark_safe(unicode(self.original_value))

    def value_from_datadict(self, data, files, name):
        return self.original_value

class ReadOnlyAdminFields(object):
    def get_form(self, request, obj=None):
        form = super(ReadOnlyAdminFields, self).get_form(request, obj)
        
        if hasattr(self, 'readonly'):
            for field_name in self.readonly:
                if field_name in form.base_fields:
                    
                    if hasattr(obj, 'get_%s_display' % field_name):
                        display_value = getattr(obj, 'get_%s_display' % field_name)()
                    else:
                        display_value = None
                        
                    form.base_fields[field_name].widget = ReadOnlyWidget(getattr(obj, field_name, ''), display_value)
                    form.base_fields[field_name].required = False
        
        return form
