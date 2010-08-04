from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.utils.safestring import mark_safe
from django.template import RequestContext

from pki.settings import PKI_DIR, PKI_LOG, MEDIA_URL
from pki.models import CertificateAuthority, Certificate
from pki.openssl import handle_exception
from pki.forms import CaPassphraseForm

import os, sys
import logging

logger = logging.getLogger("pki")

##------------------------------------------------------------------##
## Download views
##------------------------------------------------------------------##

@permission_required('pki.can_download', login_url='/pki/permission_denied')
def ca_download(request, ca, type):
    '''Download ca stuff'''
    
    ca_dir    = os.path.join(PKI_DIR, ca)
    file      = None
    file_name = None

    ## Create the file name
    if type == 'chain':
        file      = os.path.join(ca_dir, '%s-chain.cert.pem' % ca)
        file_name = '%s-chain.cert.pem' % ca
    elif type == 'crl':
        file      = os.path.join(ca_dir, 'crl', '%s.crl.pem' % ca)
        file_name = '%s.crl.pem' % ca
    elif type == 'pem':
        file      = os.path.join(ca_dir, 'certs', '%s.cert.pem' % ca)
        file_name = '%s.cert.pem' % ca
    elif type == 'der':
        file      = os.path.join(ca_dir, 'certs', '%s.cert.der' % ca)
        file_name = '%s.cert.der' % ca
    
    ## open and read the file if it exists
    if os.path.exists(file):
        f = open(file, 'r')
        x = f.readlines()
        f.close()
        
        ## return the HTTP response
        response = HttpResponse(x, mimetype='application/force-download')
        response['Content-Disposition'] = 'attachment; filename="%s"' % file_name
        
        return response
    else:
        raise Http404

@login_required
def cert_download(request, cert, type):
    '''Download certificate stuff'''
    
    c  = Certificate.objects.get(name=cert)
    ca = c.parent.name
    
    ca_dir = os.path.join(PKI_DIR, ca)
    
    ## Create the file name
    if type == 'chain':
        file      = os.path.join(ca_dir, '%s-chain.cert.pem' % ca)
        file_name = '%s-chain.cert.pem' % ca
    elif type == 'crl':
        file      = os.path.join(ca_dir, 'crl', '%s.crl.pem' % ca)
        file_name = '%s.crl.pem' % ca
    elif type == 'pem':
        file      = os.path.join(ca_dir, 'certs', '%s.cert.pem' % cert)
        file_name = '%s.cert.pem' % cert
    elif type == 'der':
        file      = os.path.join(ca_dir, 'certs', '%s.cert.der' % cert)
        file_name = '%s.cert.der' % cert
    elif type == 'pkcs12':
        file      = os.path.join(ca_dir, 'certs', '%s.cert.p12' % cert)
        file_name = '%s.cert.p12' % cert
    
    ## open and read the file if it exists
    if os.path.exists(file):
        f = open(file, 'r')
        x = f.readlines()
        f.close()
        
        ## return the HTTP response
        response = HttpResponse(x, mimetype='application/force-download')
        response['Content-Disposition'] = 'attachment; filename="%s"' % file_name
        
        return response
    else:
        raise Http404
    
##------------------------------------------------------------------##
## Admin views
##------------------------------------------------------------------##

## Helper function for recusion
def chain_recursion(r_id, store):
    
    i = CertificateAuthority.objects.get(pk=r_id)
    
    #div_content = "<ul><li>Serial: %s</li><li>Description: %s</li><li>Created: %s</li><li>Expiry date: %s</li></ul>" % ( i.serial, i.description, i.created, i.expiry_date)
    div_content = build_delete_item(i)
    
    store.append( mark_safe('Certificate Authority: <a href="../../%d/">%s</a> <img src="%spki/img/plus.png" class="switch" /><div id="detail_%s" class="details">%s</div>' % (i.pk, i.name, MEDIA_URL, i.pk, div_content)) )
    
    ## Search for child certificates
    child_certs = Certificate.objects.filter(parent=r_id)
    if child_certs:
        helper = []
        for cert in child_certs:
            div_content = build_delete_item(cert)
            #div_content = "<ul><li>Serial: %s</li><li>Description: %s</li><li>Created: %s</li><li>Expiry date: %s</li></ul>" % ( cert.serial, cert.description, cert.created, cert.expiry_date)
            helper.append( mark_safe('Certificate: <a href="../../../certificate/%d/">%s</a> <img src="%spki/img/plus.png" class="switch" /><div id="detail_%s" class="details">%s</div>' % (cert.pk, cert.name, MEDIA_URL, cert.pk, div_content)) )
        store.append(helper)
    
    ## Search for related CA's
    child_cas = CertificateAuthority.objects.filter(parent=r_id)
    if child_cas:
        helper = []
        for ca in child_cas:
            chain_recursion(ca.pk, helper)
        store.append(helper)

## Helper function for ul delete tree
def build_delete_item(i):
    
    return "<ul><li>Serial: %s</li><li>Description: %s</li><li>Created: %s</li><li>Expiry date: %s</li></ul>" % ( i.serial, i.description, i.created, i.expiry_date)

@login_required
#@permission_required('pki.can_revoke', login_url='/admin/')
def admin_delete(request, model, id):
    '''Overwite the default admin delete view'''
    
    deleted_objects    = []
    parent_object_name = CertificateAuthority._meta.verbose_name
    title              = 'Are you sure?'
    
    if model == 'certificateauthority':
        ## Get the list of objects to delete as list of lists
        item = get_object_or_404(CertificateAuthority, pk=id)
        chain_recursion(item.id, deleted_objects)
        
        ## Fill the required data for delete_confirmation.html template
        opts               = CertificateAuthority._meta
        object             = item.name
        initial_ca_id      = False
        
        ## Set the CA to verify the passphrase against
        if item.parent_id:
            initial_ca_id = item.parent_id
            auth_object   = CertificateAuthority.objects.get(pk=item.parent_id).name
        else:
            initial_ca_id = item.pk
            auth_object   = item.name
    elif model == 'certificate':
        ## Fetch the certificate data
        try:
            item = Certificate.objects.select_related().get(pk=id)
        except:
            raise Http404
        
        div_content = build_delete_item(item)
        deleted_objects.append( mark_safe('Certificate: <a href="../../../certificate/%d/">%s</a> <img src="%spki/img/plus.png" class="switch" /><div id="detail_%s" class="details">%s</div>' % (item.pk, item.name, MEDIA_URL, item.pk, div_content)) )
        
        ## Fill the required data for delete_confirmation.html template
        opts               = Certificate._meta
        object             = item.name
        initial_ca_id      = item.parent_id
        
        ## Set the CA to verify the passphrase against
        auth_object = item.parent.name
    
    if request.method == 'POST':
        form = CaPassphraseForm(request.POST)
        
        if form.is_valid():
            item.delete(request.POST['passphrase'])
            request.user.message_set.create(message='The %s "%s" was deleted successfully.' % (opts.verbose_name, object))
            return HttpResponseRedirect("../../")
    else:
        form = CaPassphraseForm()
        form.fields['ca_id'].initial = initial_ca_id
    
    return render_to_response('admin/pki/delete_confirmation.html', { 'deleted_objects': deleted_objects, 'object_name': opts.verbose_name,
                                                                      'app_label': opts.app_label, 'opts': opts, 'object': object, 'form': form,
                                                                      'auth_object': auth_object, 'parent_object_name': parent_object_name,
                                                                      'title': title,
                                                                    }, RequestContext(request))

#@login_required
#def multi_revoke(request, type, ids):
#    '''Revoke multiple certificates in 1 view'''
#    
#    certs    = ids.split(',')
#    errors   = []
#    parents  = []
#    ca       = ''
#    cert_obj = []
#    
#    form = None
#    
#    if type == 'ca':
#        for item in certs:
#            cert = CertificateAuthority.objects.get(pk=item)
#            logger.error( cert.parent)
#            
#            if cert.parent == None:
#                logger.error( "The CA '%s' is a self-signed RootCA. Revoking this certificate kills the whole chain. Forget it!" % cert.name )
#                errors.append('Certificate Authority "%s" is self-signed RootCA and cannot be revoked. Revoking this certificate kills the whole chain!' % cert.name)
#            else:
#                cert_obj.append(cert)
#                
#                if ca != '':
#                    if ca != cert.parent.pk:
#                        errors.append('You tried to revoke certificates with different parents. Make sure all certificates belong to the same parent')
#                else:
#                    ca = cert.parent.pk
#                
#                parents.append({ 'parent': cert.parent.name, 'name': cert.name})
#                
#    
#    if ( len(errors) == 0 ):
#        if request.method == 'POST':
#            form = CaPassphraseForm(request.POST)
#            if form.is_valid():
#                ## Let's revoke our certs
#                for c in cert_obj:
#                    c.action = 'revoke'
#                    c.parent_passphrase = form.cleaned_data['passphrase']
#                    c.save()
#                
#                return render_to_response('pki/multi_revoke.html', { 'message': 'Certificate(s) have been revoked successfully',
#                                                                 'errors': errors,
#                                                                 'back_url': 'pki/certificateauthority/',
#                                                                 'back_name': 'Back to CA management'
#                                                               })
#        else:
#            form = CaPassphraseForm()
#            form.fields['ca_id'].initial = ca
#        
#    
#    return render_to_response('pki/multi_revoke.html', { 'form': form,
#                                                     'errors': errors,
#                                                     'parents': parents,
#                                                     'back_url': 'pki/certificateauthority/',
#                                                     'back_name': 'Back to CA management'
#                                                   })

@login_required
def show_exception(request):
    
    f = open(PKI_LOG, 'r')
    log = f.readlines()
    f.close()
    
    return render_to_response('pki/error.html', {'log': log})
