import os
import logging

from pki.settings import PKI_ENABLE_EMAIL

if PKI_ENABLE_EMAIL is True:
    try:
        from django.core.mail import EmailMessage
        import zipfile
    except ImportError, e:
        raise Exception("Library import failed. Disable PKI_ENABLE_EMAIL or \
                        install/update the missing Python lib: %s" % e)

from django.shortcuts import get_object_or_404

from pki.models import Certificate, CertificateAuthority
from pki.helper import files_for_object, subject_for_object, \
                       build_zip_for_object

logger = logging.getLogger("pki")

##------------------------------------------------------------------##
## Email functions
##------------------------------------------------------------------##


def SendCertificateData(obj, request):
    """Send the zipped certificate data as email.
    
    Verify that the given object has all the flags set,
    create a zipfile and mail it to the
    email address from the certificate.
    """
    
    ## Check that email flag is set in the DB
    if obj.email:
        zip_f = build_zip_for_object(obj, request)
        
        ## Read ZIP content and remove it
        try:
            if os.path.exists(zip_f):
                f = open(zip_f)
                x = f.read()
                f.close()
                
                os.remove(zip_f)
        except OSError, e:
            logger.error("Failed to read zipfile: %s" % e)
            raise Exception(e)
        
        ## Build email obj and send it out
        parent_name = 'self-signed'
        if obj.parent:
            parent_name = obj.parent.common_name
        
        subj_msg = subject_for_object(obj)
        body_msg = "Certificate data sent by django-pki:\n\n  * subject: %s\n\
                   * parent: %s\n" % (subj_msg, parent_name)
        
        email = EmailMessage(to=[obj.email, ],
                             subject="Certificate data for \"%s\"" %
                             subj_msg, body=body_msg)
        email.attach('PKI_DATA_%s.zip' % obj.name, x, 'application/zip')
        email.send(fail_silently=False)
