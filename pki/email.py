from pki.settings import PKI_ENABLE_EMAIL

if PKI_ENABLE_EMAIL is True:
    try:
        from django.core.mail import EmailMessage
        import zipfile
    except ImportError, e:
        raise Exception( "Library import failed. Disable PKI_ENABLE_EMAIL or install/update the missing Python lib: %s" % e )

from pki.models import Certificate, CertificateAuthority
from pki.helper import files_for_object, subject_for_object

from django.shortcuts import get_object_or_404

import logging, os

logger = logging.getLogger("pki")

##------------------------------------------------------------------##
## Email functions
##------------------------------------------------------------------##

def SendCertificateData(obj, zip_f):
    """Verify that the given object has all the flags set, create a zipfile and mail it to the
       email address from the certificate"""
    
    ## Determine object instance
    if ( isinstance( obj, Certificate) ):
        db_obj = get_object_or_404( Certificate, pk=obj.pk )
    elif ( isinstance( obj, CertificateAuthority) ):
        db_obj = get_object_or_404( CertificateAuthority, pk=obj.pk )
    else:
        raise Exception( "Invalid object instance given!" )
    
    ## Check that email flag is set in the DB
    if db_obj.email:
        try:
            ## Create the ZIP archive
            base_folder = 'PKI_DATA_%s' % db_obj.name
            files       = files_for_object(db_obj)
            #logger.error( files)
            
            c_zip = zipfile.ZipFile(zip_f, 'w')
            
            c_zip.write( files['pem']['path'], files['pem']['name'] )
            c_zip.write( files['key']['path'], files['key']['name'] )
            
            if db_obj.pkcs12_encoded:
                c_zip.write( files['pkcs12']['path'], files['pkcs12']['name'] )
            
            if db_obj.der_encoded:
                c_zip.write( files['der']['path'], files['der']['name'] )
            
            c_zip.close()
        except Exception, e:
            logger.error( "Exception during zip file creation: %s" % e )
            raise Exception( e )
        
        ## Read ZIP content and remove it
        try:
            if os.path.exists(zip_f):
                f = open(zip_f)
                x = f.read()
                f.close()
                
                os.remove(zip_f)
        except OSError,e:
            logger.error( "Failed to read zipfile: %s" % e)
            raise Exception( e )
        
        ## Build email obj and send it out
        subj_msg = subject_for_object(db_obj)
        body_msg = "Certificate data sent by django-pki:\n\n  * subject: %s\n  * parent: %s\n" % (subj_msg, db_obj.parent.name)
        
        email = EmailMessage( to=["daniel@linuxaddicted.de", ], subject="Certificate data for \"%s\"" % subj_msg, body=body_msg,  )
        email.attach( 'PKI_DATA_%s.zip' % db_obj.name, x, 'application/zip' )
        email.send(fail_silently=False)
