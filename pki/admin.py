import os
import logging

from django.contrib import admin, messages
from django.db.models import Q
from django.http import HttpResponseRedirect

from pki.models import CertificateAuthority, Certificate, x509Extension
from pki.forms import CertificateAuthorityForm, CertificateForm, x509ExtensionForm
from pki.views import admin_delete, admin_history
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

## Disable delete_selected
admin.site.disable_action('delete_selected')

class CertificateBaseAdmin(admin.ModelAdmin):
    """Base class for Certificate* Admin models"""
    
    save_on_top   = True
    actions       = []
    list_per_page = 25
    
    class Media:
        js  = ( JQUERY_URL, 'pki/js/jquery.tipsy.js', 'pki/js/pki_admin.min.js', )
        css = { 'screen': ( 'pki/css/pki.css', 'pki/css/tipsy.css', ), }
    
    def save_model(self, request, obj, form, change):
        """Override builtin save_model function to pass user to model save"""
        
        obj.user = request.user
        obj.save()

class Certificate_Authority_Admin(CertificateBaseAdmin):
    """CertificateAuthority admin definition"""
    
    form               = CertificateAuthorityForm
    list_display       = ( 'id', 'common_name', 'Serial_align_right', 'Valid_center', 'Chain_link', 'Tree_link', 'Parent_link',
                           'Expiry_date', 'Description', 'Creation_date', 'Revocation_date', 'Child_certs', 'Download_link', 'Email_link', )
    list_display_links = ( 'common_name', )
    list_filter        = ( 'parent', 'active', )
    radio_fields       = { "action": admin.VERTICAL }
    search_fields      = [ 'name', 'common_name', 'description' ]
    date_hierarchy     = 'created'
    readonly_fields    = ( 'Expiry_date', 'Creation_date', 'Revocation_date', 'serial', 'Chain', 'Certificate_Dump', 'CA_Clock', 'State', )
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
                                                               'OU', 'email', 'key_length', 'valid_days', 'extension', 'passphrase', 'passphrase_verify',
                                                               'serial', 'Expiry_date', 'Creation_date', 'Revocation_date',
                                                             ),
                                                   'classes': [ 'wide', ],
                                                 },
                           ),
                           ( 'Encoding options', { 'fields': ( 'der_encoded', ), },
                           ),
                           ( 'Certificate signing', { 'fields': ( 'CA_Clock', 'Chain', 'parent', 'parent_passphrase', 'crl_distribution', 'policy', ),
                                                      'classes': [ 'wide', ],
                                                    },
                           ),
                         )
    
    def delete_view(self, request, object_id, extra_context=None):
        return admin_delete(request, self.model._meta.module_name, object_id)
    
    def history_view(self, request, object_id, extra_context=None):
        return admin_history(request, self.model._meta.module_name, object_id)
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        
        Skip CAs that dont have a matching x509 extension or are not active.
        """
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(extension__basic_constraints__contains="CA:TRUE", active=True).exclude(extension__basic_constraints__contains="pathlen:0")
            return db_field.formfield(**kwargs)
        elif db_field.name == "extension":
            kwargs["queryset"] = x509Extension.objects.filter(basic_constraints__contains="CA:TRUE", key_usage__name__contains="keyCertSign")
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Authority_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)
    
admin.site.register(CertificateAuthority, Certificate_Authority_Admin)

class Certificate_Admin(CertificateBaseAdmin):
    """CertificateAuthority admin definition"""
    form               = CertificateForm
    list_display       = ( 'id', 'common_name', 'Serial_align_right', 'Valid_center', 'Chain_link', 'Parent_link',
                           'Expiry_date', 'Description', 'Creation_date', 'Revocation_date', 'Download_link', 'Email_link' )
    list_display_links = ( 'common_name', )
    radio_fields       = { "action": admin.VERTICAL }
    list_filter        = ( 'parent', 'active', )
    search_fields      = [ 'name', 'description' ]
    date_hierarchy     = 'created'
    readonly_fields    = ( 'Expiry_date', 'Creation_date', 'Revocation_date', 'serial', 'Chain', 'Certificate_Dump', 'CA_Clock', 'State', )
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
                                                               'OU', 'email', 'key_length', 'valid_days', 'extension',
                                                               'passphrase', 'passphrase_verify', 'serial', 'Expiry_date', 'Creation_date',
                                                               'Revocation_date',
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
    
    def delete_view(self, request, object_id, extra_context=None):
        return admin_delete(request, self.model._meta.module_name, object_id)
    
    def history_view(self, request, object_id, extra_context=None):
        return admin_history(request, self.model._meta.module_name, object_id)
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        
        Skip CAs that dont have a matching x509 extension or are not active.
        Skip x509 extensions that are not sufficient for enduser certificates.
        """
        
        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(extension__basic_constraints__contains="CA:TRUE", \
                                                                     active=True).filter(extension__basic_constraints__contains="pathlen:0")
            return db_field.formfield(**kwargs)
        elif db_field.name == "extension":
            kwargs["queryset"] = x509Extension.objects.filter(Q(basic_constraints__contains="CA:FALSE") | \
                                                              ((Q(basic_constraints__contains="CA:TRUE") & \
                                                                Q(basic_constraints__contains="pathlen:0")) & \
                                                                ~Q(key_usage__name__contains="keyCertSign")))
            return db_field.formfield(**kwargs)
        
        return super(Certificate_Admin, self).formfield_for_foreignkey(db_field, request, **kwargs)
    
admin.site.register(Certificate, Certificate_Admin)

class x509Extension_Admin(CertificateBaseAdmin):
    """Admin instance for x509 extensions"""
    
    form               = x509ExtensionForm
    list_display       = ( 'id', 'name', 'description', 'created', 'basic_constraints', 'subject_key_identifier', 'authority_key_identifier', 'crl_distribution_point', )
    list_display_links = ( 'name', )
    search_fields      = [ 'name', 'description', ]
    date_hierarchy     = 'created'
    fieldsets          = ( ( 'X509 extension',    { 'fields': ( 'name', 'description', 'basic_constraints', 'basic_constraints_critical', 'key_usage',
                                                                'key_usage_critical', 'extended_key_usage', 'extended_key_usage_critical', 
                                                                'subject_key_identifier', 'authority_key_identifier', 'crl_distribution_point',
                                                              ),
                                                    'classes': [ 'wide', ],
                                                  },
                            ),
                         )
    
    def save_model(self, request, obj, form, change):
        if change:
            request.user.get_and_delete_messages()
        else:
            obj.user = request.user
            obj.save()
    
    def delete_view(self, request, object_id, extra_context=None):
        x509 = x509Extension.objects.get(pk=object_id)
        if x509.certificateauthority_set.all() or x509.certificate_set.all():
            logger.error("x509 extension \"%s\" cannot be removed because it is in use!" % x509.name)
            messages.error(request, 'x509 extension "%s" cannot be removed because it is in use!' % x509.name)
            return HttpResponseRedirect("../../")
        else:
            return super(x509Extension_Admin, self).delete_view(request, object_id, extra_context)
    
    def response_change(self, request, obj):
        messages.warning(request, 'You cannot modify x509 extensions!')
        return HttpResponseRedirect("../")
    
admin.site.register(x509Extension, x509Extension_Admin)
