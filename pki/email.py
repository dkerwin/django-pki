from pki.settings import PKI_ENABLE_EMAIL

if PKI_ENABLE_EMAIL is True:
    try:
        from django.core.mail import EmailMessage
    except ImportError, e:
        raise Exception( "Failed to import EmailMessage. Disable PKI_ENABLE_EMAIL or update your Django installation: %s" % e )

from pki.models import Certificate, CertificateAuthority
from django.shortcuts import get_object_or_404
##------------------------------------------------------------------##
## Email functions
##------------------------------------------------------------------##

def SendCertificateData(obj):
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
        email = EmailMessage( to=[obj.email], subject="Test from django-pki", body="body - it's all about the body" )
        email.send(fail_silently=False)
    
    
    

