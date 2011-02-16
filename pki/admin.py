import os

from django.contrib import admin
from django.utils.safestring import mark_safe

from pki.models import CertificateAuthority, Certificate
from pki.forms import CertificateAuthorityForm, CertificateForm
from pki.settings import PKI_DIR, PKI_LOG, PKI_LOGLEVEL, JQUERY_URL

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

class Certificate_Authority_Admin(admin.ModelAdmin):
    """CertificateAuthority admin definition"""
    form               = CertificateAuthorityForm
    list_display       = ( 'id', 'common_name', 'Serial_align_right', 'Valid_center', 'Chain_link', 'Tree_link', 'Parent_link',
                           'Expiry_date', 'Description', 'Creation_date', 'Revocation_date', 'Child_certs', 'Download_link', 'Email_link', )
    list_display_links = ( 'common_name', )
    save_on_top        = True
    actions            = []
    list_filter        = ( 'parent', 'active', )
    radio_fields       = { "action": admin.VERTICAL }
    search_fields      = [ 'name', 'common_name', 'description' ]
    date_hierarchy     = 'created'
    readonly_fields    = ( 'Expiry_date', 'Creation_date', 'Revocation_date', 'serial', 'Chain', 'Certificate_Dump', 'CA_Clock', 'State', )
    exclude            = ( 'pf_encrypted', 'pem_encoded', )
    fieldsets          = ( ( 'Define action',    { 'fields': ( 'action', ), }, ),
                           ( 'Documentation',    { 'fields': ( 'description', ),
                                                   'classes': [ 'wide', ],
                                                 },
                           ),
                           ( 'Certificate Dump', { 'fields': ( 'Certificate_Dump', ),
                                                   'classes': [ 'collapse', 'wide', ],
                                                 },
                           ),
                           ( 'Certificate',      { 'fields': ( 'State', 'common_name', 'name', 'country', 'state', 'locality', 'organization',
                                                               'OU', 'email', 'key_length', 'valid_days', 'passphrase', 'passphrase_verify',
                                                               'serial', 'Expiry_date', 'Creation_date', 'Revocation_date',
                                                             ),
                                                   'classes': [ 'wide', ],
                                                 },
                           ),
                           ( 'Encoding options', { 'fields': ( 'der_encoded', ), },
                           ),
                           ( 'Certificate signing', { 'fields': ( 'CA_Clock', 'subcas_allowed', 'Chain', 'parent', 'type', 'parent_passphrase',
                                                                  'crl_distribution', 'policy', ),
                                                      'classes': [ 'wide', ],
                                                    },
                           ),
                         )
    
    class Media:
        js  = ( JQUERY_URL, 'pki/js/jquery.tipsy.js', 'pki/js/pki_admin.min.js', )
        css = { 'screen': ( 'pki/css/pki.css', 'pki/css/tipsy.css', ), }
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        
        Skip CAs that dont have subcas_allowed set or are not active
        """
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(subcas_allowed=True, active=True)
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Authority_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)
    
    def save_model(self, request, obj, form, change):
        """Override builtin save_model function to pass user to model save"""
        
        obj.user = request.user
        obj.save()

admin.site.register(CertificateAuthority, Certificate_Authority_Admin)

class Certificate_Admin(admin.ModelAdmin):
    """CertificateAuthority admin definition"""
    form               = CertificateForm
    list_display       = ( 'id', 'common_name', 'Serial_align_right', 'Valid_center', 'Chain_link', 'Parent_link',
                           'Expiry_date', 'Description', 'Creation_date', 'Revocation_date', 'Download_link', 'Email_link' )
    list_display_links = ( 'common_name', )
    save_on_top        = True
    actions            = []
    radio_fields       = { "action": admin.VERTICAL }
    list_filter        = ( 'parent', 'active', )
    search_fields      = [ 'name', 'description' ]
    date_hierarchy     = 'created'
    readonly_fields    = ( 'Expiry_date', 'Creation_date', 'Revocation_date', 'serial', 'Chain', 'Certificate_Dump', 'CA_Clock', 'State', )
    exclude            = ( 'pf_encrypted', )
    fieldsets          = ( ( 'Define action',   { 'fields': ( 'action', ) } ),
                           ( 'Documentation',   { 'fields': ( 'description', ),
                                                  'classes': [ 'wide', ],
                                                },
                           ),
                           ( 'Certificate Dump', { 'fields': ( 'Certificate_Dump', ),
                                                   'classes': [ 'collapse', 'wide', ],
                                                 },
                           ),
                           ( 'Certificate',     { 'fields': ( 'State', 'common_name', 'name', 'country', 'state', 'locality', 'organization',
                                                               'OU', 'email', 'key_length', 'cert_extension', 'valid_days', 'passphrase',
                                                              'passphrase_verify', 'serial', 'Expiry_date', 'Creation_date', 'Revocation_date',
                                                            ),
                                                  'classes': [ 'wide', ],
                                                },
                           ),
                           ( 'Multi-domain / SubjectAltName', { 'fields': ( 'subjaltname', ),
                                                                'classes': [ 'wide', ],
                                                              },
                           ),
                           ( 'Encoding options', { 'fields': ( 'der_encoded', 'pkcs12_encoded', 'pkcs12_passphrase', 'pkcs12_passphrase_verify', ),
                                                   'classes': [ 'wide', ],
                                                 },
                           ),
                           ( 'Certificate signing', { 'fields': ( 'CA_Clock', 'Chain', 'parent', 'parent_passphrase', ),
                                                      'classes': [ 'wide', ],
                                                    },
                           ),
                         )
    
    class Media:
        js = ( JQUERY_URL, 'pki/js/jquery.tipsy.js', 'pki/js/pki_admin.min.js', )
        css = { 'screen': ( 'pki/css/pki.css', 'pki/css/tipsy.css', ), }
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        
        Skip CAs that dont have subcas_allowed set or are not active
        """
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(subcas_allowed=False, active=True)
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Authority_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)
    
    def save_model(self, request, obj, form, change):
        """Override builtin save_model function to pass user to model save"""
        
        obj.user = request.user
        obj.save()

admin.site.register(Certificate, Certificate_Admin)
admin.site.disable_action('delete_selected')

