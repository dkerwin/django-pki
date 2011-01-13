import os
import logging

from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseBadRequest
from django.utils.safestring import mark_safe
from django.template import RequestContext
from django.core import urlresolvers

from pki.settings import PKI_LOG, MEDIA_URL, PKI_ENABLE_GRAPHVIZ, PKI_ENABLE_EMAIL
from pki.models import CertificateAuthority, Certificate
from pki.forms import CaPassphraseForm, CertPassphraseForm
from pki.graphviz import ObjectChain, ObjectTree
from pki.email import SendCertificateData
from pki.helper import files_for_object, chain_recursion, build_delete_item, generate_temp_file, build_zip_for_object

logger = logging.getLogger("pki")

##------------------------------------------------------------------##
## Download views
##------------------------------------------------------------------##

@login_required
def pki_download(request, model, id):
    """Download PKI data.
    
    Type (ca/cert) and ID are used to determine the object to download.
    """
    
    if model == "certificateauthority":
        c = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        c = get_object_or_404(Certificate, pk=id)
    else:
        logger.error( "Unsupported type %s requested!" % type )
        return HttpResponseBadRequest()
    
    if not c.active:
        raise Http404
    
    zip = build_zip_for_object(c, request)
    
    ## open and read the file if it exists
    if os.path.exists(zip):
        f = open(zip)
        x = f.readlines()
        f.close()
        
        ## return the HTTP response
        response = HttpResponse(x, mimetype='application/force-download')
        response['Content-Disposition'] = 'attachment; filename="PKI_DATA_%s.zip"' % c.name
        
        return response
    else:
        logger.error( "File not found: %s" % zip )
        raise Http404

##------------------------------------------------------------------##
## Graphviz views
##------------------------------------------------------------------##

@login_required
def pki_chain(request, model, id):
    """Display the CA chain as PNG.
    
    Requires PKI_ENABLE_GRAPHVIZ set to true. Type (ca/cert) and ID are used to determine the object.
    Create object chain PNG using graphviz and return it to the user.
    """
    
    if PKI_ENABLE_GRAPHVIZ is not True:
        raise Exception( "Chain view is inoperable unless PKI_ENABLE_GRAPHVIZ is enabled" )
    
    if model == "certificateauthority":
        obj = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        obj = get_object_or_404(Certificate, pk=id)
    
    png = generate_temp_file()

    ObjectChain(obj, png)
    
    try:
        if os.path.exists(png):
            f = open(png)
            x = f.read()
            f.close()
            
            os.remove(png)
    except OSError,e:
        logger.error( "Failed to load depency tree: %s" % e)
        raise Exception( e )
    
    response = HttpResponse(x, mimetype='image/png')
    return response

@login_required
def pki_tree(request, id):
    """Display the CA tree as PNG.
    
    Requires PKI_ENABLE_GRAPHVIZ set to true. Only works for Certificate Authorities.
    All object related to the CA obj are fetched and displayed in a Graphviz tree.
    """
    
    if PKI_ENABLE_GRAPHVIZ is not True:
        raise Exception( "Tree view is inoperable unless PKI_ENABLE_GRAPHVIZ is enabled!" )
    
    obj = get_object_or_404(CertificateAuthority, pk=id)
    png = generate_temp_file()
    
    ObjectTree(obj, png)
    
    try:
        if os.path.exists(png):
            f = open(png)
            x = f.read()
            f.close()
            
            os.remove(png)
    except OSError,e:
        logger.error( "Failed to load depency tree: %s" % e)
        raise Exception( e )
    
    response = HttpResponse(x, mimetype='image/png')
    return response

##------------------------------------------------------------------##
## Email views
##------------------------------------------------------------------##

@login_required
def pki_email(request, model, id):
    """Send email with certificate data attached.
    
    Requires PKI_ENABLE_EMAIL set to true. Type (ca/cert) and ID are used to determine the object.
    Build ZIP, send email and return to changelist.
    """
    
    if PKI_ENABLE_EMAIL is not True:
        raise Exception( "Email sending is inoperable unless PKI_ENABLE_EMAIL is enabled!" )
    
    if model == "certificateauthority":
        obj  = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        obj = get_object_or_404(Certificate, pk=id)
    
    back = request.META.get('HTTP_REFERER', None) or '/'
    
    if obj.email and obj.active:
        SendCertificateData(obj, request)
    else:
        raise Http404
    
    request.user.message_set.create(message='Email to "%s" was sent successfully.' % obj.email)
    return HttpResponseRedirect(back)

##------------------------------------------------------------------##
## Admin views
##------------------------------------------------------------------##

@login_required
def admin_delete(request, model, id):
    """Overwite the default admin delete view"""
    
    deleted_objects    = []
    parent_object_name = CertificateAuthority._meta.verbose_name
    title              = 'Are you sure?'
    
    if model == 'certificateauthority':
        ## Get the list of objects to delete as list of lists
        item = get_object_or_404(CertificateAuthority, pk=id)
        chain_recursion(item.id, deleted_objects, id_dict={ 'cert': [], 'ca': [], })
        
        ## Fill the required data for delete_confirmation.html template
        opts       = CertificateAuthority._meta
        object     = item.name
        initial_id = False
        
        ## Set the CA to verify the passphrase against
        if item.parent_id:
            initial_id = item.parent_id
            auth_object   = CertificateAuthority.objects.get(pk=item.parent_id).name
        else:
            initial_id = item.pk
            auth_object   = item.name
    elif model == 'certificate':
        ## Fetch the certificate data
        try:
            item = Certificate.objects.select_related().get(pk=id)
        except:
            raise Http404
        
        if not item.parent_id:
            parent_object_name = "self-signed certificate"
            initial_id = item.id
            authentication_obj = item.name
        else:
            initial_id = item.parent_id
            authentication_obj = item.parent.name
        
        div_content = build_delete_item(item)
        deleted_objects.append( mark_safe('Certificate: <a href="%s">%s</a> <img src="%spki/img/plus.png" class="switch" /><div class="details">%s</div>' % \
                                          (urlresolvers.reverse('admin:pki_certificate_change', args=(item.pk,)), item.name, MEDIA_URL, div_content)) )
        
        ## Fill the required data for delete_confirmation.html template
        opts       = Certificate._meta
        object     = item.name
        #initial_id = initial_id
        
        ## Set the CA to verify the passphrase against
        auth_object = authentication_obj
    
    if request.method == 'POST':
        if model == 'certificateauthority':
            form = CaPassphraseForm(request.POST)
        elif model == 'certificate':
            form = CertPassphraseForm(request.POST)
        
        if form.is_valid():
            item.delete(request.POST['passphrase'])
            request.user.message_set.create(message='The %s "%s" was deleted successfully.' % (opts.verbose_name, object))
            return HttpResponseRedirect("../../")
    else:
        if model == 'certificateauthority':
            form = CaPassphraseForm()
            form.fields['ca_id'].initial = initial_id
        elif model == 'certificate':
            form = CertPassphraseForm()
            form.fields['cert_id'].initial = initial_id
    
    return render_to_response('admin/pki/delete_confirmation.html', { 'deleted_objects': deleted_objects, 'object_name': opts.verbose_name,
                                                                      'app_label': opts.app_label, 'opts': opts, 'object': object, 'form': form,
                                                                      'auth_object': auth_object, 'parent_object_name': parent_object_name,
                                                                      'title': title,
                                                                    }, RequestContext(request))

@login_required
def show_exception(request):
    """Render error page and fill it with the PKI_LOG content"""
    
    f = open(PKI_LOG, 'r')
    log = f.readlines()
    f.close()
    
    return render_to_response('500.html', {'log': log})
