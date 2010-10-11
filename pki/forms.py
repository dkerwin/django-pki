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
    passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    created           = forms.DateField(widget=forms.DateField, required=False)
    
    class Meta:
        model = CertificateAuthority
    
    def clean(self):
        """Verify crucial fields"""
        
        cleaned_data = self.cleaned_data
        
        action = cleaned_data.get('action')
        parent = cleaned_data.get('parent')
        pf = cleaned_data.get('passphrase')
        pf_v = cleaned_data.get('passphrase_verify')
        enc_p_pf = None

        if action in ('create', 'renew'):
            
            ## Check if name contains invalid chars
            name = cleaned_data.get('name')
            
            if name != None and re.search('[^a-zA-Z0-9-_\.]', name):
                self._errors['name'] = ErrorList(['Name may only contain characters in range a-Z0-9_-.'])
            
            ## Verify passphrase length
            if action == 'create':
                if pf and len(pf) < 8:
                    self._errors['passphrase'] = ErrorList(['Passphrase has to be at least 8 characters long'])
                
                if not pf_v or pf != pf_v:
                    self.errors['passphrase_verify'] = ErrorList(['Passphrase mismtach detected'])
            
            ## Take care that parent is active when action is revoke
            if action == 'renew':
                ca = CertificateAuthority.objects.get(name='%s' % name)
                
                ## Prevent renewal when parent is disabled
                if ca.parent is not None and ca.parent.active is not True:
                    self._errors['action'] = ErrorList(['Cannot renew CA certificate when parent "%s" isn\'t active!' % ca.parent.name])
                    return cleaned_data
                
                ## Compare passphrase
                if not pf or ca.passphrase != md5_constructor(pf).hexdigest():
                    self._errors['passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % cleaned_data.get('common_name')])
            
            if parent:                
                ca = CertificateAuthority.objects.get(name='%s' % parent.name)
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
                ca = CertificateAuthority.objects.get(name='%s' % parent.name)
                enc_p_pf = md5_constructor(cleaned_data.get('parent_passphrase')).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent])
            else:
                self._errors['action'] = ErrorList(['You cannot revoke a self-signed root certificate as this would break the whole chain!'])
        
        return cleaned_data

class CertificateForm(forms.ModelForm):
    """Validation class for Certificate form"""
    
    passphrase        = forms.CharField(widget=forms.PasswordInput, required=False)
    passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)
    
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    
    pkcs12_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    pkcs12_passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)
    
    class Meta:
        model = Certificate
    
    def clean(self):
        """Verify crucial fields"""
        
        cleaned_data = self.cleaned_data
        
        action = cleaned_data.get('action')
        parent = cleaned_data.get('parent')
        pf = cleaned_data.get('passphrase')
        pf_v = cleaned_data.get('passphrase_verify')
        p_pf = cleaned_data.get('parent_passphrase')
        subjaltname = cleaned_data.get('subjaltname')
        pkcs12_passphrase = cleaned_data.get('pkcs12_passphrase')
        pkcs12_encoded = cleaned_data.get('pkcs12_encoded')
        
        enc_p_pf = None
        
        if action in ('create', 'renew'):
            ## Check if name contains invalid chars
            name = cleaned_data.get('name')
            
            if name != None and re.search('[^a-zA-Z0-9-_\.]', name):
                self._errors['name'] = ErrorList(['Name may only contain characters in range a-Z0-9'])
            
            ## Verify passphrase length
            if action == 'create':
                if pf and len(pf) < 8:
                    self._errors['passphrase'] = ErrorList(['Passphrase has to be at least 8 characters long'])
                
                if not pf_v or pf != pf_v:
                    self.errors['passphrase_verify'] = ErrorList(['Passphrase mismtach detected'])
            
            ## Verify that pkcs12 passphrase isn't empty when encoding is requested
            if pkcs12_encoded and len(pkcs12_passphrase) < 8:
                self._errors['pkcs12_passphrase'] = ErrorList(['PKCS12 passphrase has to be at least 8 characters long'])
            
            ## Take care that parent is active when action is revoke
            if action == 'renew':
                cert = Certificate.objects.get(name='%s' % name)
                
                if cert.parent is not None and cert.parent.active is not True:
                    self._errors['action'] = ErrorList(['Cannot renew certificate when parent CA "%s" isn\'t active!' % cert.parent])
                    return cleaned_data
            
            if parent:
                ca = CertificateAuthority.objects.get(name='%s' % parent.name)
                if p_pf: enc_p_pf = md5_constructor(p_pf).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent])
            else:
                self._errors['parent'] = ErrorList(['You cannot renew a certificate while the parent is not active. Renew requires the intial parent to be active'])
            
            ## Verify subjAltName
            if subjaltname and len(subjaltname) > 0:
                allowed = { 'email': '^copy|[\w\-\.]+\@[\w\-\.]+\.\w{2,4}$',
                            'IP'   : '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                            'DNS'  : '^[a-zA-Z0-9\-\.\*]+$',
                          }
                items = subjaltname.split(',')
                
                for i in items:
                    if not re.match( '^\s*(email|IP|DNS)\s*:\s*.+$', i):
                        self._errors['subjaltname'] = ErrorList(['Item "%s" doesn\'t match specification' % i])
                    else:
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
                ca = CertificateAuthority.objects.get(name='%s' % parent.name)
                if p_pf: enc_p_pf = md5_constructor(p_pf).hexdigest()
                
                ## Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors['parent_passphrase'] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent])
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
                self._errors["passphrase"] = ErrorList(['Passphrase is wrong. Enter correct passphrase for CA "%s"' % ca])
        else:
            self._errors["passphrase"] = ErrorList(['Passphrase is missing!'])
        
        return cleaned_data
