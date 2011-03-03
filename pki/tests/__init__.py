import unittest
import datetime
import os
import sys
import logging

from django.core.mail import get_connection
from django.test.client import Client
from django.test import TestCase
from django.conf import settings

from windmill.authoring import djangotest 

from pki.models import CertificateAuthority, Certificate, x509Extension
from pki import openssl
from pki.helper import *
from pki.settings import PKI_DIR, PKI_ENABLE_EMAIL

if not os.path.exists(PKI_DIR):
    os.mkdir(PKI_DIR, 0700)

logger = logging.getLogger("pki")

l_hdlr = logging.FileHandler(os.path.join(PKI_DIR, 'pki.log'))
l_hdlr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s.%(funcName)s > %(message)s"))
logger.addHandler(l_hdlr)
logger.setLevel(logging.DEBUG)

##-----------------------------------------##
## TestCases
##-----------------------------------------##

def CreateCaChain():
    """Create a 3 level CA chain"""
    
    from django.core.management import call_command
    call_command("loaddata", "eku_and_ku.json", verbosity=0)
    
    ## Reset PKI_DIR
    openssl.refresh_pki_metadata([])
    
    ## Root CA object
    CertificateAuthority(common_name='Root CA', name='Root_CA', description="unit test", country='DE', state='Bavaria', \
                         locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                         der_encoded=False, parent=None, passphrase='1234567890', extension=x509Extension.objects.get(pk=1)).save()
    
    rca = CertificateAuthority.objects.get(pk=1)
    
    ## Intermediate CA object
    CertificateAuthority(common_name='Intermediate CA', name='Intermediate_CA', description="unit test IM CA", country='DE', \
                         state='Bavaria', locality='Berlin', organization='Bozo Clown Inc.', OU=None, email='a@b.com', valid_days=365, \
                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                         der_encoded=False, parent=rca, parent_passphrase="1234567890", passphrase='1234567890', \
                         extension=x509Extension.objects.get(pk=1)).save()
    
    ica = CertificateAuthority.objects.get(pk=2)
    
    ## Edge CA object (RootCA->IntermediateCA->SubCA)
    CertificateAuthority(common_name='Edge CA', name='Edge_CA', description="unit test edge CA", country='DE', state='Bavaria', \
                         locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=365, \
                         key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                         der_encoded=False, parent=ica, parent_passphrase="1234567890", passphrase='1234567890', \
                         extension=x509Extension.objects.get(pk=2)).save()
    
class CertificateAuthorityTestCase(unittest.TestCase):
    '''Testcase for a self-signed RootCA. Any affected function and the complete process (save+remove) are tested''' 
    
    def setUp(self):
        '''Create a self-signed RootCA'''
        
        CreateCaChain()
        
        self.rca = CertificateAuthority.objects.get(pk=1)
        self.ica = CertificateAuthority.objects.get(pk=2)
        self.eca = CertificateAuthority.objects.get(pk=3)
        
        self.rca_openssl = openssl.Openssl(self.rca)
        self.ica_openssl = openssl.Openssl(self.ica)
        self.eca_openssl = openssl.Openssl(self.eca)        
        
        openssl.refresh_pki_metadata([self.rca, self.ica, self.eca])
    
    def tearDown(self):
        CertificateAuthority.objects.all().delete()
    
    def test_OpensslExec(self):
        self.assertTrue(self.rca_openssl.exec_openssl(['version'], None))
    
    def test_GenerateSelfSignedCertificateAuthority(self):
        self.assertTrue(os.path.exists(self.rca_openssl.key))
        self.assertTrue(os.path.exists(self.rca_openssl.crt))
    
    def test_GenerateIntermediateCertificateAuthority(self):
        self.assertTrue(os.path.exists(self.ica_openssl.key))
        self.assertTrue(os.path.exists(self.ica_openssl.csr))
        self.assertTrue(os.path.exists(self.ica_openssl.crt))
    
    def test_GenerateEdgeCertificateAuthority(self):
        self.assertTrue(os.path.exists(self.eca_openssl.key))
        self.assertTrue(os.path.exists(self.eca_openssl.csr))
        self.assertTrue(os.path.exists(self.eca_openssl.crt))
    
    def test_RevokeIntermediateCertificateAuthority(self):
        self.ica.action = "revoke"
        self.ica.parent_passphrase = "1234567890"
        self.ica.save()
        self.assertFalse(CertificateAuthority.objects.get(pk=self.ica.pk).active)
        self.assertFalse(CertificateAuthority.objects.get(pk=self.eca.pk).active)
        self.assertTrue(self.ica_openssl.get_revoke_status_from_cert())
    
    def test_DerEncodeCertificateAuthority(self):
        self.rca.der_encoded = True
        self.rca.save()
        self.assertTrue(os.path.exists(self.rca_openssl.der))
        self.rca.der_encoded = False
        self.rca.save()
        self.assertFalse(os.path.exists(self.rca_openssl.der))
    
    def test_DeleteEdgeCertificateAuthority(self):
        self.eca.delete(passphrase="1234567890")
        self.assertFalse(os.path.exists(self.eca_openssl.ca_dir))
    
    def test_DeleteRootCertificateAuthority(self):
        self.rca.delete(passphrase="1234567890")
        self.assertFalse(os.path.exists(self.rca_openssl.ca_dir))
        self.assertFalse(os.path.exists(self.ica_openssl.ca_dir))
        self.assertFalse(os.path.exists(self.eca_openssl.ca_dir))
        self.assertEqual(len(CertificateAuthority.objects.all()), 0)
    
    def test_DeleteIntermediateCertificateAuthority(self):
        self.ica.delete("1234567890")
        self.assertTrue(os.path.exists(self.rca_openssl.ca_dir))
        self.assertFalse(os.path.exists(self.ica_openssl.ca_dir))
        self.assertFalse(os.path.exists(self.eca_openssl.ca_dir))
        self.assertTrue(self.ica_openssl.get_revoke_status_from_cert())
    
class CertificateTestCase(unittest.TestCase):
    """Edge certificate testcases"""
    
    def setUp(self):
        
        CreateCaChain()
        
        self.rca = CertificateAuthority.objects.get(pk=1)
        self.ica = CertificateAuthority.objects.get(pk=2)
        self.eca = CertificateAuthority.objects.get(pk=3)
        openssl.refresh_pki_metadata([self.rca, self.ica, self.eca])
        
        Certificate(common_name='Server Edge Certificate', name='Server_Edge_Certificate', description="unit test server edge certificate", country='DE', \
                    state='Bavaria', locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=365, \
                    key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                    der_encoded=False, pkcs12_encoded=False, pkcs12_passphrase=None, parent=self.eca, parent_passphrase="1234567890", passphrase=None, \
                    extension=x509Extension.objects.get(pk=3)).save()
        
        Certificate(common_name='User Edge Certificate', name='User_Edge_Certificate', description="unit test user edge certificate", country='DE', \
                    state='Bavaria', locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=365, \
                    key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                    der_encoded=False, pkcs12_encoded=False, pkcs12_passphrase=None, parent=self.eca, parent_passphrase="1234567890", passphrase=None, \
                    extension=x509Extension.objects.get(pk=4)).save()
        
        self.srv = Certificate.objects.get(pk=1)
        self.usr = Certificate.objects.get(pk=2)
        
        self.srv_openssl = openssl.Openssl(self.srv)
        self.usr_openssl = openssl.Openssl(self.usr)
    
    def tearDown(self):
        CertificateAuthority.objects.all().delete()
        Certificate.objects.all().delete()
    
    def test_CreateEdgeCertificate(self):
        self.assertTrue(self.srv.active)
        self.assertTrue(self.usr.active)
        self.assertTrue(os.path.exists(self.srv_openssl.key))
        self.assertTrue(os.path.exists(self.srv_openssl.csr))
        self.assertTrue(os.path.exists(self.srv_openssl.crt))
        self.assertTrue(os.path.exists(self.usr_openssl.key))
        self.assertTrue(os.path.exists(self.usr_openssl.csr))
        self.assertTrue(os.path.exists(self.usr_openssl.crt))
    
    def test_RevokeParentCertificateAuthority(self):
        self.eca.action = "revoke"
        self.eca.parent_passphrase = "1234567890"
        self.eca.save()
        self.assertFalse(CertificateAuthority.objects.get(pk=self.eca.pk).active)
        self.assertFalse(Certificate.objects.get(pk=self.srv.pk).active)
        self.assertFalse(Certificate.objects.get(pk=self.usr.pk).active)
    
    def test_RevokeEdgeCertificate(self):
        self.srv.action = "revoke"
        self.srv.parent_passphrase = "1234567890"
        self.srv.save()
        self.assertFalse(Certificate.objects.get(pk=self.srv.pk).active)
        self.assertTrue(self.srv_openssl.get_revoke_status_from_cert())
    
    def test_RemoveEdgeCertificate(self):
        self.srv.delete(passphrase="1234567890")
        self.assertFalse(os.path.exists(self.srv_openssl.key))
        self.assertFalse(os.path.exists(self.srv_openssl.csr))
        self.assertFalse(os.path.exists(self.srv_openssl.crt))
        self.assertTrue(self.srv_openssl.get_revoke_status_from_cert())
    
    def test_RenewEdgeCertificate(self):
        old_sn = self.srv.serial
        self.srv.action = "renew"
        self.srv.parent_passphrase = "1234567890"
        self.srv.save()
        self.srv_openssl = openssl.Openssl(Certificate.objects.get(pk=self.srv.pk))
        self.assertNotEqual(old_sn, Certificate.objects.get(pk=self.srv.pk).serial)
        self.assertTrue(Certificate.objects.get(pk=self.srv.pk).active)
        self.assertFalse(self.srv_openssl.get_revoke_status_from_cert())
    
    def test_DerEncodeCertificate(self):
        self.srv.action = "update"
        self.srv.der_encoded = True
        self.srv.save()
        self.assertTrue(os.path.exists(self.srv_openssl.der))
        self.srv.der_encoded = False
        self.srv.save()
        self.assertFalse(os.path.exists(self.srv_openssl.der))
    
    def test_PKCS12EncodeCertificate(self):
        self.srv.action = "update"
        self.srv.pkcs12_encoded = True
        self.srv.pkcs12_passphrase = "1234567890"
        self.srv.save()
        self.assertTrue(os.path.exists(self.srv_openssl.pkcs12))
        self.srv.pkcs12_encoded = False
        self.srv.save()
        self.assertFalse(os.path.exists(self.srv_openssl.pkcs12))

class EmailDeliveryTestCase(unittest.TestCase):
    
    def setUp(self): pass
    
    def test_CheckSmtpConnection(self):
        if PKI_ENABLE_EMAIL:
            self.assertTrue(get_connection(backend="django.core.mail.backends.smtp.EmailBackend").open())
        else:
            self.assertTrue(True)

class HttpClientTestCase(TestCase):
    
    def setUp(self):
        from django.core.management import call_command
        call_command("loaddata", "test_users.json", verbosity=0)
        
        self.c = Client()
    
    def test_201_AddCertificateAuthority(self):
        self.c.login(username="pki_user_1", password="admin")
        r = self.c.post('/admin/pki/certificateauthority/add/', { 'common_name': 'Root CA', 'name': 'Root_CA', 'description': "unit test", \
                                                             'country': 'DE', 'state': 'Bavaria', 'locality': 'Munich', 'organization': 'Bozo Clown Inc.', \
                                                             'OU': 'IT', 'email': 'a@b.com', 'valid_days': 1000, 'key_length': 1024, 'expiry_date': '', \
                                                             'created': '', 'revoked': '', 'active': '', 'serial': '', 'ca_chain': '', \
                                                             'pem_encoded': True, 'der_encoded': False, 'parent': '', 'passphrase': '1234567890', \
                                                             'subcas_allowed': True
                                                           })
        
        self.failUnlessEqual(r.status_code, 200)
    
    def test_201_DownloadWithoutLogin(self):
        r = self.c.get('/admin/pki/download/ca/1')
        self.assertEqual(r.status_code, 404)
    
    #def test_209_AdminLogin(self):
    #    self.assertTrue(self.c.login(username="pki_user_1", password="admin"))

#class TestProjectWindmillTest(djangotest.WindmillDjangoUnitTest):
#    fixtures = ["test_users.json"]
#    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'windmilltests')
#    browser  = 'firefox'
