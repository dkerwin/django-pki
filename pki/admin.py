from pki.models import CertificateAuthority, Certificate
from pki.forms import ReadOnlyAdminFields, CertificateAuthorityForm, CertificateForm
from pki.settings import PKI_DIR, PKI_LOG, PKI_LOGLEVEL, JQUERY_URL

from django.contrib import admin
from django.utils.safestring import mark_safe

import os

##------------------------------------------------------------------##
## Create PKI_DIR if it's missing
##------------------------------------------------------------------##

if not os.path.exists( PKI_DIR ):
    try:
        os.mkdir( PKI_DIR, 0750 )
    except OSError, e:
        print "Failed to create PKI_DIR %s: %s" % (PKI_DIR, e)

##------------------------------------------------------------------##
## Initialize logging
##------------------------------------------------------------------##

import logging

LOG_LEVELS = { 'debug'    : logging.DEBUG,
               'info'     : logging.INFO,
               'warning'  : logging.WARNING,
               'error'    : logging.ERROR,
               'critical' : logging.CRITICAL
             }

logger = logging.getLogger("pki")

l_hdlr = logging.FileHandler(PKI_LOG)
l_hdlr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s.%(funcName)s > %(message)s"))

if LOG_LEVELS[PKI_LOGLEVEL]:
    logger.setLevel(LOG_LEVELS[PKI_LOGLEVEL])

logger.addHandler(l_hdlr)

##---------------------------------##
## Interface setup
##---------------------------------##

class Certificate_Authority_Admin(ReadOnlyAdminFields, admin.ModelAdmin):
    form               = CertificateAuthorityForm
    list_display       = ( 'id', 'common_name', 'serial', 'active_center', 'Locate_link', 'Tree_link', 'Parent',
                           'Expiry_date', 'Description', 'type', 'revoked', 'download', 'Email_send', )
    list_display_links = ( 'common_name', )
    save_on_top        = True
    actions            = []
    list_filter        = ( 'parent', 'active', )
    radio_fields       = { "action": admin.VERTICAL }
    search_fields      = [ 'name', 'common_name', 'description' ]
    date_hierarchy     = 'created'
    readonly           = ( 'expiry_date', 'key', 'cert', 'serial', 'ca_chain', )
    exclude            = ( 'pf_encrypted', 'pem_encoded', )
    fieldsets          = ( ( 'Define action',    { 'fields': ( 'action', ) }, ),
                           ( 'Documentation',    { 'fields': ( 'description', ) } ), 
                           ( 'Certificate',      { 'fields': ( 'common_name', 'name', 'country', 'state', 'locality', 'organization', 'OU',
                                                               'email', 'key_length', 'valid_days', 'passphrase', 'serial', 'expiry_date',
                                                             )
                                                 }
                           ),
                           ( 'Encoding options', { 'fields': ( 'der_encoded', ), } ),
                           ( 'CA setup',         { 'fields': ( 'subcas_allowed', 'ca_chain', 'parent', 'type', 'parent_passphrase', 'policy', ), } ),
                         )
    
    class Media:
        js = ( JQUERY_URL, 'pki/ca_admin.js', )
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        '''Skip CAs that dont have subcas_allowed set''' 
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(subcas_allowed=True, active=True)
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Authority_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)

admin.site.register(CertificateAuthority, Certificate_Authority_Admin)

class Certificate_Admin(ReadOnlyAdminFields, admin.ModelAdmin):
    form               = CertificateForm
    list_display       = ( 'id', 'common_name', 'serial', 'active_center', 'Locate_link', 'Parent',
                           'Expiry_date', 'Description', 'created', 'revoked', 'download', 'Email_send' )
    list_display_links = ( 'common_name', )
    save_on_top        = True
    actions            = []
    radio_fields       = { "action": admin.VERTICAL }
    list_filter        = ( 'parent', 'active', )
    search_fields      = [ 'name', 'description' ]
    date_hierarchy     = 'created'
    readonly           = ( 'created', 'expiry_date', 'key', 'cert', 'serial', )
    exclude            = ( 'pf_encrypted', 'ca_chain', )
    fieldsets          = ( ( 'Define action',   { 'fields': ( 'action', ) } ),
                           ( 'Documentation',   { 'fields': ( 'description', ) } ), 
                           ( 'Certificate',     { 'fields': ( 'common_name', 'name', 'country', 'state', 'locality', 'organization', 'OU',
                                                              'email', 'subjaltname', 'key_length', 'cert_extension', 'valid_days', 'passphrase', 'serial', 'expiry_date',
                                                            ),
                                                }
                           ),
                           ( 'Encoding options', { 'fields': ( 'der_encoded', 'pkcs12_encoded', 'pkcs12_passphrase', ), } ),
                           ( 'CA setup',         { 'fields': ( 'parent', 'parent_passphrase', ), } ),
                         )
    
    class Media:
        js = ( JQUERY_URL, 'pki/cert_admin.js', )
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        '''Skip CAs that have subcas_allowed set''' 
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(subcas_allowed=False, active=True)
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Authority_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)

admin.site.register(Certificate, Certificate_Admin)
admin.site.disable_action('delete_selected')

