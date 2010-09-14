import unittest
import datetime
import os
import sys

from django.core.mail import get_connection

##-----------------------------------------##
## <MonkeyPatching: ugly but necessary>
##-----------------------------------------##
from pki.settings import PKI_DIR, PKI_ENABLE_EMAIL
PKI_DIR = os.path.join( PKI_DIR, '../TEST_PKI')

from pki.models  import CertificateAuthority
from pki import openssl
from pki.helper import *

openssl.PKI_DIR = PKI_DIR
openssl.PKI_OPENSSL_CONF = os.path.join(PKI_DIR, 'openssl.conf')
##-----------------------------------------##
## </MonkeyPatching>
##-----------------------------------------##

## Logging to STDOUT on level ERROR
import logging

logger = logging.getLogger("pki")

l_hdlr = logging.FileHandler(os.path.join(PKI_DIR, 'pki.log'))
l_hdlr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s.%(funcName)s > %(message)s"))
logger.addHandler(l_hdlr)
logger.setLevel(logging.DEBUG)

class CertificateAuthorityTestCase(unittest.TestCase):
    '''Testcase for a self-signed RootCA. Any affected function and the complete process (save+remove) are tested''' 
    
    def setUp(self):
        '''Create a self-signed RootCA'''
        
        ## Root CA object
        self.rca = CertificateAuthority( common_name='Root CA', name='Root_CA', description="unit test", country='DE', state='Bavaria', \
                                         locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                                         pem_encoded=True, der_encoded=False, parent=None, passphrase='1234567890', subcas_allowed=True )
        
        ## Intermediate CA object
        self.ica = CertificateAuthority( common_name='Intermediate CA', name='Intermediate_CA', description="unit test IM CA", country='DE', \
                                         state='Bavaria', locality='Berlin', organization='Bozo Clown Inc.', OU=None, email='a@b.com', valid_days=365, \
                                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                                         pem_encoded=True, der_encoded=False, parent=self.rca, parent_passphrase="1234567890", \
                                         passphrase='1234567890', subcas_allowed=True)
        
        ## Sub CA object (RootCA->IntermediateCA->SubCA)
        self.sca = CertificateAuthority( common_name='Sub CA', name='Sub_CA', description="unit test sub CA", country='DE', state='Bavaria', \
                                         locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=365, \
                                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                                         pem_encoded=True, der_encoded=False, parent=self.ica, parent_passphrase="1234567890", \
                                         passphrase='1234567890', subcas_allowed=False)
        
        
        openssl.refresh_pki_metadata([self.rca, self.ica, self.sca])
        self.rca_action = openssl.OpensslActions(self.rca)
        self.ica_action = openssl.OpensslActions(self.ica)
        self.sca_action = openssl.OpensslActions(self.sca)
    
    def test_001_OpensslExec(self):
        self.assertTrue(self.rca_action.exec_openssl(['version'], None))
    
    def test_002_GenerateKey(self):
        self.rca_action.generate_key()
        self.assertTrue(os.path.exists(self.rca_action.key))
    
    def test_003_GenerateCsr(self):
        self.rca_action.generate_csr()
        self.assertTrue(os.path.exists(self.rca_action.csr))
    
    def test_004_GenerateSelfSignedCA(self):
        self.rca_action.generate_self_signed_cert()
        self.assertTrue(os.path.exists(self.rca_action.crt))
    
    def test_005_DerExport(self):
        self.rca_action.generate_der_encoded()
        self.assertTrue(os.path.exists(self.rca_action.der))
    
    def test_006_DerRemove(self):
        self.rca_action.remove_der_encoded()
        self.assertFalse(os.path.exists(self.rca_action.der))
    
    def test_007_SubjectBuild(self):
        self.assertEqual(subject_for_object(self.rca), '/CN=%s/C=%s/ST=%s/localityName=%s/O=%s/organizationalUnitName=%s/emailAddress=%s' % \
                                                         ( self.rca.common_name, self.rca.country, self.rca.state,
                                                           self.rca.locality, self.rca.organization, self.rca.OU, self.rca.email ))
    
    def test_008_GenerateCrl(self):
        self.rca_action.generate_crl(ca=self.rca.name, pf='1234567890')
        self.assertTrue(os.path.exists(self.rca_action.crl))
    
    def test_009_SaveObject(self):
        self.assertEqual(self.rca.save(), None)
    
    def test_010_GetSerial(self):
        self.assertEqual(self.rca_action.get_serial_from_cert(), CertificateAuthority.objects.get(pk=1).serial)
    
    def test_011_RemoveObject(self):
        ca = CertificateAuthority.objects.get(pk=1)
        self.assertEqual(ca.delete(None), None)
    
    def test_012_ReSaveObject(self):
        self.assertEqual(self.rca.save(), None)
    
    def test_013_CreateIntermediateCA(self):       
        self.assertEqual(self.ica.save(), None)
    
    def test_014_CreateLeafCA(self):
        self.assertEqual(self.sca.save(), None)
    
    def test_015_RevokeIntermediateCA(self):
        self.ica.action = 'revoke'
        self.ica.parent_passphrase = self.rca.passphrase
        self.ica.pk = CertificateAuthority.objects.get(name=self.ica.name).pk
        self.assertEqual(self.ica.save(), None)
    
    def test_016_CheckCertificateRevokeStatus(self):
        self.ica.serial = CertificateAuthority.objects.get(name=self.ica.name).serial
        self.assertTrue(self.ica_action.get_revoke_status_from_cert())
    
    def test_017_FilesForObject(self):
        self.assertEqual(type(files_for_object(self.rca)), type(dict()))
    
class EmailDeliveryTestCase(unittest.TestCase):
    
    def test_101_CheckSmtpConnection(self):
        if PKI_ENABLE_EMAIL:
            self.assertTrue(get_connection(backend="django.core.mail.backends.smtp.EmailBackend").open())
        else:
            self.assertTrue(True)

