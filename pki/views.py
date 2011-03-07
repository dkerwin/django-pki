import os
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseBadRequest
from django.utils.safestring import mark_safe
from django.template import RequestContext
from django.core import urlresolvers

from pki.settings import PKI_LOG, MEDIA_URL, PKI_ENABLE_GRAPHVIZ, PKI_ENABLE_EMAIL
from pki.models import CertificateAuthority, Certificate
from pki.forms import DeleteForm
from pki.graphviz import ObjectChain, ObjectTree
from pki.email import SendCertificateData
from pki.helper import files_for_object, chain_recursion, build_delete_item, generate_temp_file, build_zip_for_object
from pki.openssl import refresh_pki_metadata

logger = logging.getLogger("pki")

##------------------------------------------------------------------##
## Download views
##------------------------------------------------------------------##

@login_required
def pki_download(request, model, id):
    """Download PKI data.
    
    Type (ca/cert) and ID are used to determine the object to download.
    """
    
    if not request.user.has_perm('can_download'):
        messages.error(request, "Permission denied!")
        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
    
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
        messages.warning(request, "Chain view is disabled unless setting PKI_ENABLE_GRAPHVIZ is set to True")
        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
    
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
        messages.warning(request, "Tree view is disabled unless setting PKI_ENABLE_GRAPHVIZ is set to True")
        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_certificateauthority_changelist' % model))
    
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
        messages.warning(request, "Email delivery is disabled unless setting PKI_ENABLE_EMAIL is set to True")
        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
    
    if model == "certificateauthority":
        obj  = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        obj = get_object_or_404(Certificate, pk=id)
    
    if obj.email and obj.active:
        SendCertificateData(obj, request)
    else:
        raise Http404
    
    messages.info(request, 'Email to "%s" was sent successfully.' % obj.email)
    return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))

##------------------------------------------------------------------##
## Management views
##------------------------------------------------------------------##

@login_required
def pki_refresh_metadata(request):
    """Rebuild PKI metadate.
    
    Renders openssl.conf template and cleans PKI_DIR.
    """
    
    ca_objects = list(CertificateAuthority.objects.all())
    refresh_pki_metadata(ca_objects)
    messages.info(request, 'Successfully refreshed PKI metadata (%d certificate authorities)' % len(ca_objects))
    
    back = request.META.get('HTTP_REFERER', None) or '/'
    return HttpResponseRedirect(back)

##------------------------------------------------------------------##
## Admin views
##------------------------------------------------------------------##

@login_required
def admin_history(request, model, id):
    """Overwrite the default admin history view"""
    
    from django.contrib.contenttypes.models import ContentType
    from pki.models import PkiChangelog
    
    ct  = ContentType.objects.get(model=model)
    model_obj = ct.model_class()
    obj = model_obj.objects.get(pk=id)
    
    changelogs = PkiChangelog.objects.filter(model_id=ct.pk).filter(object_id=id)
    
    return render_to_response('admin/pki/object_changelogs.html', { 'changelogs': changelogs, 'title': "Change history: %s" % obj.common_name,
                                                                    'app_label': model_obj._meta.app_label, 'object': obj,
                                                                    'module_name': model_obj._meta.verbose_name_plural,
                                                                  }, RequestContext(request))

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
            initial_id  = item.pk
            auth_object = item.name
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
        opts   = Certificate._meta
        object = item.name
        
        ## Set the CA to verify the passphrase against
        auth_object = authentication_obj
    
    if request.method == 'POST':
        form = DeleteForm(request.POST)
        
        if form.is_valid():
            item.delete(request.POST['passphrase'])
            messages.info(request, 'The %s "%s" was deleted successfully.' % (opts.verbose_name, object))
            return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
    else:
        form = DeleteForm()
        
        form.fields['_model'].initial = model
        form.fields['_id'].initial    = id
    
    return render_to_response('admin/pki/delete_confirmation.html', { 'deleted_objects': deleted_objects, 'object_name': opts.verbose_name,
                                                                      'app_label': opts.app_label, 'opts': opts, 'object': object, 'form': form,
                                                                      'auth_object': auth_object, 'parent_object_name': parent_object_name,
                                                                      'title': title,
                                                                    }, RequestContext(request))

##------------------------------------------------------------------##
## Exception viewer
##------------------------------------------------------------------##

@login_required
def show_exception(request):
    """Render error page and fill it with the PKI_LOG content"""
    
    f = open(PKI_LOG, 'r')
    log = f.readlines()
    f.close()
    
    return render_to_response('500.html', {'log': log})
