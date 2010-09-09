import pki.models
from pki.settings import PKI_DIR, MEDIA_URL

from django.utils.safestring import mark_safe

import os

## Get the files associated with a object
def files_for_object(obj):
    
    if ( isinstance( obj, pki.models.CertificateAuthority) ):
        chain   = c_name = obj.name
        ca_dir  = os.path.join(PKI_DIR, obj.name)
        key_loc = os.path.join(ca_dir, 'private')
    elif ( isinstance( obj, pki.models.Certificate) ):
        chain   = obj.parent.name
        c_name  = obj.name
        ca_dir  = os.path.join(PKI_DIR, obj.parent.name)
        key_loc = os.path.join(ca_dir, 'certs')
    else:
        raise Exception( "Given object is no known type!" )
    
    c_map = { 'chain' : { 'path': os.path.join(ca_dir, '%s-chain.cert.pem' % chain),
                          'name': '%s-chain.cert.pem' % chain,
                        },
              'crl'   : { 'path': os.path.join(ca_dir, 'crl', '%s.crl.pem' % c_name),
                          'name': '%s.crl.pem' % c_name,
                        },
              'pem'   : { 'path': os.path.join(ca_dir, 'certs', '%s.cert.pem' % c_name),
                          'name': '%s.cert.pem' % c_name,
                        },
              'csr'   : { 'path': os.path.join(ca_dir, 'certs', '%s.csr.pem' % c_name),
                          'name': '%s.csr.pem' % c_name,
                        },
              'der'   : { 'path': os.path.join(ca_dir, 'certs', '%s.cert.der' % c_name),
                          'name': '%s.cert.der' % c_name,
                        },
              'pkcs12': { 'path': os.path.join(ca_dir, 'certs', '%s.cert.p12' % c_name),
                          'name': '%s.cert.p12' % c_name,
                        },
              'key'   : { 'path': os.path.join(ca_dir, key_loc, '%s.key.pem' % c_name),
                          'name': '%s.key.pem' % c_name,
                        },
            }
    
    return c_map

## Get the subject of a object
def subject_for_object(obj):
    '''Return a subject string based on given object'''
    
    subj = '/CN=%s/C=%s/ST=%s/localityName=%s/O=%s' % ( obj.common_name,
                                                        obj.country,
                                                        obj.state,
                                                        obj.locality,
                                                        obj.organization,
                                                      )
    
    if obj.OU:
        subj += '/organizationalUnitName=%s' % obj.OU
    
    if obj.email:
        subj += '/emailAddress=%s' % obj.email
    
    return subj

## Helper function for recusion
def chain_recursion(r_id, store, id_dict):
    
    i = pki.models.CertificateAuthority.objects.get(pk=r_id)
    
    div_content = build_delete_item(i)
    store.append( mark_safe('Certificate Authority: <a href="../../%d/">%s</a> <img src="%spki/img/plus.png" class="switch" /><div class="details">%s</div>' % (i.pk, i.name, MEDIA_URL, div_content)) )
    
    id_dict['ca'].append(i.pk)
    
    ## Search for child certificates
    child_certs = pki.models.Certificate.objects.filter(parent=r_id)
    if child_certs:
        helper = []
        for cert in child_certs:
            div_content = build_delete_item(cert)
            helper.append( mark_safe('Certificate: <a href="../../../certificate/%d/">%s</a> <img src="%spki/img/plus.png" class="switch" /><div class="details">%s</div>' % (cert.pk, cert.name, MEDIA_URL, div_content)) )
            id_dict['cert'].append(cert.pk)
        store.append(helper)
    
    ## Search for related CA's
    child_cas = pki.models.CertificateAuthority.objects.filter(parent=r_id)
    if child_cas:
        helper = []
        for ca in child_cas:
            chain_recursion(ca.pk, helper, id_dict)
        store.append(helper)

## Helper function for ul delete tree
def build_delete_item(obj):
    
    parent = 'None'
    if obj.parent is not None:
        parent = obj.parent.name
    
    return "<ul><li>Serial: %s</li><li>Subject: %s</li><li>Parent: %s</li><li>Description: %s</li><li>Created: %s</li><li>Expiry date: %s</li></ul>" % ( obj.serial, subject_for_object(obj), parent, obj.description, obj.created, obj.expiry_date)
