import unittest
import datetime
import os
import sys
import logging
import datetime

from django.core.mail import get_connection
from django.test.client import Client
from django.test import TestCase
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User, Permission

from windmill.authoring import djangotest 

from pki.models import CertificateAuthority, Certificate, x509Extension, PkiChangelog
from pki import openssl
from pki.helper import *
from pki.settings import PKI_DIR, PKI_ENABLE_EMAIL, PKI_ENABLE_GRAPHVIZ, PKI_ENABLE_EMAIL

if not os.path.exists(PKI_DIR):
    os.mkdir(PKI_DIR, 0700)

logger = logging.getLogger("pki")

l_hdlr = logging.FileHandler(os.path.join(PKI_DIR, 'pki.log'))
l_hdlr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s.%(funcName)s > %(message)s"))
logger.addHandler(l_hdlr)
logger.setLevel(logging.DEBUG)

##-----------------------------------------##
## Model function testcases
##-----------------------------------------##

class CertificateBaseModelTestCases(TestCase):
    """Test abstract model CertificateBase functions"""
    
    def setUp(self):
        self.obj = CertificateAuthority(common_name='Root CA', name='Root_CA', description="unittest", country='DE', state='Bavaria', \
                                        locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                                        key_length=1024, expiry_date=datetime.datetime(2021, 01, 01, 20, 00, 00).date(), \
                                        created=datetime.datetime(2011, 01, 01, 20, 00, 00), \
                                        revoked=datetime.datetime(2011, 01, 01, 20, 00, 00), active=None, serial=None, ca_chain=None, \
                                        der_encoded=False, parent=None, passphrase='1234567890', id=999)
    
    def test_State(self):
        self.assertTrue(self.obj.State().find("icon-yes.gif"))
        self.obj.active = False
        self.assertTrue(self.obj.State().find("icon-no.gif"))
    
    def test_Valid_center(self):
        self.assertTrue(self.obj.Valid_center().find("icon-yes.gif"))
        self.obj.active = False
        self.assertTrue(self.obj.Valid_center().find("icon-no.gif"))
    
    def test_Serial_align_right(self):
        self.assertTrue(self.obj.Serial_align_right().find('class="serial_align_right"'))
    
    def test_Description(self):
        self.assertEqual(self.obj.Description(), "unittest")
        self.obj.description = "1234567890123456789012345678901234567890"
        self.assertEqual(self.obj.Description(), "123456789012345678901234567890...")
    
    def test_Creation_date(self):
        self.assertEqual(self.obj.Creation_date(), '2011-01-01 20:00:00')
    
    def test_Revocation_date(self):
        self.assertEqual(self.obj.Revocation_date(), '2011-01-01 20:00:00')
    
    def test_Expiry_date(self):
        self.obj.expiry_date = datetime.datetime.now().date() + datetime.timedelta(15)
        self.assertTrue(self.obj.Expiry_date().find('class="almods_expired"'))
        self.obj.expiry_date = datetime.datetime.now().date() - datetime.timedelta(10)
        self.assertTrue(self.obj.Expiry_date().find('class="expired"'))
        self.obj.active = False
        self.assertTrue(self.obj.Expiry_date().find('class="revoked"'))
    
    def test_Chain_link(self):
        PKI_ENABLE_GRAPHVIZ = False
        self.assertTrue(self.obj.Chain_link().find("Enable setting PKI_ENABLE_GRAPHVIZ"))
        PKI_ENABLE_GRAPHVIZ = True
        self.assertTrue(self.obj.Chain_link().find("Show object chain"))
    
    def test_Email_link(self):
        PKI_ENABLE_EMAIL= False
        self.assertTrue(self.obj.Email_link().find("Enable setting PKI_ENABLE_EMAIL"))
        PKI_ENABLE_EMAIL = True
        self.obj.active = False
        self.assertTrue(self.obj.Email_link().find("Certificate is revoked"))
        self.obj.active = True
        self.obj.email = "a@b.com"
        self.assertTrue(self.obj.Email_link().find("Send to"))
        self.obj.email = None
        self.assertTrue(self.obj.Email_link().find("Certificate has no email set. Disabled"))
    
    def test_Download_link(self):
        self.obj.active = True
        self.assertTrue(self.obj.Download_link().find("Download certificate zip"))
        self.obj.active = False
        self.assertTrue(self.obj.Download_link().find("Certificate is revoked. Disabled"))
    
    def test_Parent_link(self):
        self.assertTrue(self.obj.Parent_link().find("self-signed"))
    
    def test_Certificate_Dump(self):
        ## Requires real CRT. Skipped for now
        pass
    
    def test_CA_Clock(self):
        self.assertTrue(self.obj.CA_Clock().find("clock_container"))
    
class CertificateAuthorityModelTestCases(TestCase):
    """Test model CertificateAuthority functions"""
    
    fixtures = ["eku_and_ku.json"]
    
    def setUp(self):
        self.obj = CertificateAuthority(common_name='Root CA', name='Root_CA', description="unittest", country='DE', state='Bavaria', \
                                        locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                                        key_length=1024, expiry_date=datetime.datetime(2021, 01, 01, 20, 00, 00).date(), \
                                        created=datetime.datetime(2011, 01, 01, 20, 00, 00), revoked=datetime.datetime(2011, 01, 01, 20, 00, 00), \
                                        active=None, serial=None, ca_chain=None, der_encoded=False, parent=None, passphrase='1234567890', id=999)
    
    def tearDown(self):
        openssl.refresh_pki_metadata([])
    
    def test_unicode(self):
        self.assertEqual(self.obj.__unicode__(), "Root CA")
    
    def test_rebuild_ca_metadata(self):
        self.obj_ssl = openssl.Openssl(self.obj)
        self.obj.rebuild_ca_metadata(modify=True, task='append')
        self.assertTrue(os.path.exists(self.obj_ssl.ca_dir))
        self.obj.rebuild_ca_metadata(modify=True, task='exclude', skip_list=[self.obj.pk,])
        self.assertFalse(os.path.exists(self.obj_ssl.ca_dir))
    
    def test_is_edge_ca(self):
        self.obj.extension = x509Extension.objects.get(pk=1)
        self.assertFalse(self.obj.is_edge_ca())
        self.obj.extension = x509Extension.objects.get(pk=2)
        self.assertTrue(self.obj.is_edge_ca())
    
    def test_Tree_link(self):
        PKI_ENABLE_GRAPHVIZ = True
        self.assertTrue(self.obj.Tree_link().find( "Show CA tree"))
        PKI_ENABLE_GRAPHVIZ = False
        self.assertTrue(self.obj.Tree_link().find( "Enable setting PKI_ENABLE_GRAPHVIZ"))
    
    def test_Child_certs(self):
        self.obj.extension = x509Extension.objects.get(pk=1)
        self.assertTrue(self.obj.Child_certs().find("No children"))
        self.obj.extension = x509Extension.objects.get(pk=2)
        self.assertTrue(self.obj.Child_certs().find("Show child certificates"))

class x509ExtensionModelTestCases(TestCase):
    """Test model x509Extension functions"""
    
    fixtures = ["eku_and_ku.json"]

    def setUp(self):
        self.ca   = x509Extension.objects.get(pk=1)
        self.cert = x509Extension.objects.get(pk=3)

    def test_key_usage_csv(self):
        self.assertEqual(self.ca.key_usage_csv(), "critical,keyCertSign,cRLSign")
    
    def test_ext_key_usage_csv(self):
        self.assertEqual(self.cert.ext_key_usage_csv(), "critical,serverAuth")

##-----------------------------------------##
## OpenSSL function testcases
##-----------------------------------------##

class OpensslTestCases(TestCase):
    """Test Openssl library functions"""
    
    fixtures = ["eku_and_ku.json"]
    
    def setUp(self):
        self.ca = CertificateAuthority(common_name='Root CA', name='Root_CA', description="unit test", country='DE', state='Bavaria', \
                                       locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                                       key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                                       der_encoded=False, parent=None, passphrase='1234567890', extension=x509Extension.objects.get(pk=1))
        self.ca_ssl = openssl.Openssl(self.ca)
        openssl.refresh_pki_metadata([self.ca,])
    
    def tearDown(self):
        openssl.refresh_pki_metadata([])
    
    def test_refresh_pki_metadata(self):
        for d in ('certs', 'private', 'crl'):
            self.assertTrue(os.path.exists(os.path.join(self.ca_ssl.ca_dir, d)))
        for f in ('serial', 'index.txt', 'crlnumber'):
            self.assertTrue(os.path.exists(os.path.join(self.ca_ssl.ca_dir, f)))
    
    def test_exec_openssl(self):
        self.assertTrue(self.ca_ssl.exec_openssl(['version'], None))
    
    def test_generate_key(self):
        for k in (1024, 2048, 4096):
            self.ca_ssl.generate_key()
            self.assertTrue(os.path.exists(self.ca_ssl.key))
            os.unlink(self.ca_ssl.key)

##-----------------------------------------##
## Helper function testcases
##-----------------------------------------##

class HelperTestCase(TestCase):
    """Testcase for helper functions"""
    
    fixtures = ["test_users.json", "eku_and_ku.json"]
    
    def setUp(self):
        CertificateAuthority(common_name='Root CA', name='Root_CA', description="unit test", country='DE', state='Bavaria', \
                             locality='Munich', organization='Bozo Clown Inc.', OU='IT', email='a@b.com', valid_days=1000, \
                             key_length=1024, expiry_date='', created='', revoked=None, active=None, serial=None, ca_chain=None, \
                             der_encoded=False, parent=None, passphrase='1234567890', extension=x509Extension.objects.get(pk=1)).save()
        
        self.obj = CertificateAuthority.objects.get(pk=1)
    
    def test_files_for_object(self):
        f = files_for_object(self.obj)
        for i in ('chain', 'crl', 'pem', 'csr', 'der', 'pkcs12', 'key'):
            self.assertTrue(f[i])
    
    def test_subject_for_object(self):
        self.assertEqual(subject_for_object(self.obj), '/CN=%s/C=%s/ST=%s/localityName=%s/O=%s/organizationalUnitName=%s/emailAddress=%s' %
                                                        (self.obj.common_name, self.obj.country, self.obj.state, self.obj.locality,
                                                         self.obj.organization, self.obj.OU, self.obj.email))
    
    ## TODO: Testcase for chain_recursion and build_delete_item
    ## TODO: Testcase for build_zip_for_object. Fake of request is required
    
    def test_generate_temp_file(self):
        self.assertFalse(os.path.exists(generate_temp_file()))

##-----------------------------------------##
## Full operation testcases
##-----------------------------------------##

def CreateCaChain():
    """Create a 3 level CA chain"""
    
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
    
class CertificateAuthorityTestCase(TestCase):
    '''Testcase for a self-signed RootCA. Any affected function and the complete process (save+remove) are tested''' 
    
    fixtures = ["eku_and_ku.json"]
    
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
    
    def test_HistoryUpdated(self):
        self.rca.action = "update"
        self.rca.description = "UNIT_TEST_UPDATE"
        self.rca.save()
        self.assertEqual(PkiChangelog.objects.get(model_id=ContentType.objects.get_for_model(self.rca).pk, \
                                                  object_id=self.rca.pk, changes="Updated description to \"UNIT_TEST_UPDATE\"").changes, \
                                                  "Updated description to \"UNIT_TEST_UPDATE\"")
    
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
    
class CertificateTestCase(TestCase):
    """Edge certificate testcases"""
    
    fixtures = ["eku_and_ku.json"]
    
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
    
    def test_HistoryUpdated(self):
        self.srv.action = "update"
        self.srv.description = "UNIT_TEST_UPDATE"
        self.srv.save()
        self.assertEqual(PkiChangelog.objects.get(model_id=ContentType.objects.get_for_model(self.srv).pk, \
                                                  object_id=self.srv.pk, changes="Updated description to \"UNIT_TEST_UPDATE\"").changes, \
                                                  "Updated description to \"UNIT_TEST_UPDATE\"")
    
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

class x509ExtensionTestCase(TestCase):
    
    fixtures = ["eku_and_ku.json"]
    
    def test_Savex509Extension(self):
        x = x509Extension.objects.get(pk=1)
        desc = x.description
        x.description = "CHANGED"
        x.save()
        self.assertNotEqual(desc, x.description)

##-----------------------------------------##
## Email testcases
##-----------------------------------------##

class EmailDeliveryTestCase(unittest.TestCase):
    
    def setUp(self): pass
    
    def test_CheckSmtpConnection(self):
        if PKI_ENABLE_EMAIL:
            self.assertTrue(get_connection(backend="django.core.mail.backends.smtp.EmailBackend").open())
        else:
            self.assertTrue(True)

##-----------------------------------------##
## HTTP testcases
##-----------------------------------------##

class HttpClientTestCase(TestCase):
    
    fixtures = ["test_users.json", "eku_and_ku.json"]
    
    def setUp(self):
        openssl.refresh_pki_metadata([])
        self.post_data_rca = {'action':'create', 'common_name':'Root CA', 'name':'Root_CA', 'description':"unit test", \
                              'country':'DE', 'state':'Bavaria', 'locality':'Munich', 'organization':'Bozo Clown Inc.', \
                              'OU':'IT', 'email':'a@b.com', 'valid_days':1000, 'key_length':1024, 'der_encoded':False, \
                              'parent':'', 'passphrase':'1234567890', 'passphrase_verify':'1234567890', 'policy':'policy_anything', \
                              'extension':x509Extension.objects.get(name="v3_root_or_intermediate_ca").pk,}
        self.post_data_ica = {'action':'create', 'common_name':'Intermediate CA', 'name':'Intermediate_CA', 'description':"unit test", \
                              'country':'DE', 'state':'Bavaria', 'locality':'Munich', 'organization':'Bozo Clown Inc.', \
                              'OU':'IT', 'email':'a@b.com', 'valid_days':1000, 'key_length':1024, 'der_encoded':False, \
                              'parent':'1', 'passphrase':'1234567890', 'passphrase_verify':'1234567890', 'parent_passphrase':'1234567890', \
                              'policy':'policy_anything', 'extension':x509Extension.objects.get(name="v3_root_or_intermediate_ca").pk,}
        self.post_data_eca = {'action':'create', 'common_name':'Edge CA', 'name':'Edge', 'description':"unit test", \
                              'country':'DE', 'state':'Bavaria', 'locality':'Munich', 'organization':'Bozo Clown Inc.', \
                              'OU':'IT', 'email':'a@b.com', 'valid_days':1000, 'key_length':1024, 'der_encoded':False, \
                              'parent':'2', 'passphrase':'1234567890', 'passphrase_verify':'1234567890', 'parent_passphrase':'1234567890', \
                              'policy':'policy_anything', 'extension':x509Extension.objects.get(name="v3_edge_ca").pk,}
        
        self.post_data_srv = {'action':'create', 'common_name':'Server cert', 'name':'Server_cert', 'description':"unit test", \
                              'country':'DE', 'state':'Bavaria', 'locality':'Munich', 'organization':'Bozo Clown Inc.', \
                              'OU':'IT', 'email':'a@b.com', 'valid_days':1000, 'key_length':1024, 'der_encoded':False, \
                              'parent':'3', 'passphrase':'1234567890', 'passphrase_verify':'1234567890', 'parent_passphrase':'1234567890', \
                              'extension':x509Extension.objects.get(name="v3_edge_cert_server").pk,}
        
        self.post_data_usr = {'action':'create', 'common_name':'User cert', 'name':'User_cert', 'description':"unit test", \
                              'country':'DE', 'state':'Bavaria', 'locality':'Munich', 'organization':'Bozo Clown Inc.', \
                              'OU':'IT', 'email':'a@b.com', 'valid_days':1000, 'key_length':1024, 'der_encoded':False, \
                              'parent':'3', 'passphrase':'1234567890', 'passphrase_verify':'1234567890', 'parent_passphrase':'1234567890', \
                              'extension':x509Extension.objects.get(name="v3_edge_cert_client").pk,}
        
        self.c = Client()
        self.assertTrue(self.c.login(username="admin", password="admin"))
        
        r = self.c.post('/admin/pki/certificateauthority/add/', self.post_data_rca, follow=True)
        self.assertContains(r, 'was added successfully')
        self.failUnlessEqual(r.status_code, 200)
        
        r = self.c.post('/admin/pki/certificateauthority/add/', self.post_data_ica, follow=True)
        self.assertContains(r, 'was added successfully')
        self.failUnlessEqual(r.status_code, 200)
        
        r = self.c.post('/admin/pki/certificateauthority/add/', self.post_data_eca, follow=True)
        self.assertContains(r, 'was added successfully')
        self.failUnlessEqual(r.status_code, 200)
        
        r = self.c.post('/admin/pki/certificate/add/', self.post_data_srv, follow=True)
        self.assertContains(r, 'was added successfully')
        self.failUnlessEqual(r.status_code, 200)
        
        #r = self.c.post('/admin/pki/certificate/add/', self.post_data_usr, follow=True)
        #self.assertContains(r, 'was added successfully')
        #self.failUnlessEqual(r.status_code, 200)
    
    def tearDown(self):
        self.c.logout()
        openssl.refresh_pki_metadata([])

    def test_RevokeEdgeCertificateAuthority(self):
        self.post_data_eca['action'] = 'revoke'
        self.post_data_eca['parent_passphrase'] = '1234567890'
        r = self.c.post('/admin/pki/certificateauthority/3/', self.post_data_eca, follow=True)
        self.assertContains(r, 'was changed successfully')
        self.failUnlessEqual(r.status_code, 200)
        eca_obj = CertificateAuthority.objects.get(pk=3)
        eca_ssl = openssl.Openssl(eca_obj)
        self.assertFalse(eca_obj.active)
        self.assertTrue(eca_ssl.get_revoke_status_from_cert())
    
    def test_RevokeIntermediateCertificateAuthority(self):
        self.post_data_ica['action'] = 'revoke'
        self.post_data_ica['parent_passphrase'] = '1234567890'
        r = self.c.post('/admin/pki/certificateauthority/2/', self.post_data_ica, follow=True)
        self.assertContains(r, 'was changed successfully')
        self.failUnlessEqual(r.status_code, 200)
        ica_obj = CertificateAuthority.objects.get(pk=2)
        ica_ssl = openssl.Openssl(ica_obj)
        self.assertFalse(ica_obj.active)
        self.assertTrue(ica_ssl.get_revoke_status_from_cert())
        for ca in ica_obj.certificateauthority_set.all():
            self.assertFalse(ca.active)
    
    def test_DeleteEdgeCertificateAuthority(self):
        eca_obj = CertificateAuthority.objects.get(pk=3)
        eca_ssl = openssl.Openssl(eca_obj)
        r = self.c.post('/admin/pki/certificateauthority/3/delete/', {'_model':'certificateauthority', '_id':3, 'passphrase':'1234567890'}, follow=True)
        self.assertContains(r, 'was deleted successfully')
        self.failUnlessEqual(r.status_code, 200)
        self.assertEqual(len(CertificateAuthority.objects.filter(pk=3)), 0)
        self.assertTrue(eca_ssl.get_revoke_status_from_cert())
        self.assertFalse(os.path.exists(eca_ssl.ca_dir))
    
    def test_DeleteRootCertificateAuthority(self):
        rca_obj = CertificateAuthority.objects.get(pk=1)
        rca_ssl = openssl.Openssl(rca_obj)
        r = self.c.post('/admin/pki/certificateauthority/1/delete/', {'_model':'certificateauthority', '_id':1, 'passphrase':'1234567890'}, follow=True)
        self.assertContains(r, 'was deleted successfully')
        self.failUnlessEqual(r.status_code, 200)
        self.assertEqual(len(CertificateAuthority.objects.filter(pk=1)), 0)
        self.assertFalse(os.path.exists(rca_ssl.ca_dir))
        for ca in rca_obj.certificateauthority_set.all():
            self.assertEqual(len(CertificateAuthority.objects.filter(pk=ca.pk)), 0)
            self.assertFalse(os.path.exists(rca_ssl.ca_dir)) 
    
    def test_DownloadCertificateAuthority(self):
        self.c.logout()
        ct = model_id=ContentType.objects.get(model='certificateauthority')
        user = User.objects.create_user('pki_user_1', 'a@b.com', 'pki')
        user.is_staff = True
        user.user_permissions.add(Permission.objects.get(codename="change_certificateauthority", content_type=ct))
        user.save()
        self.c.login(username="pki_user_1", password="pki")
        r = self.c.get('/pki/download/certificateauthority/1/', follow=True)
        self.failUnlessEqual(r.status_code, 200)
        self.assertContains(r, 'Permission denied!')
        user.user_permissions.add(Permission.objects.get(codename="can_download", content_type=ct))
        user.save()
        r = self.c.get('/pki/download/certificateauthority/1/', follow=True)
        self.failUnlessEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'application/force-download')
    
    def test_DownloadCertificate(self):
        self.c.logout()
        ct = model_id=ContentType.objects.get(model='certificate')
        user = User.objects.create_user('pki_user_1', 'a@b.com', 'pki')
        user.is_staff = True
        user.user_permissions.add(Permission.objects.get(codename="change_certificate", content_type=ct))
        user.save()
        self.c.login(username="pki_user_1", password="pki")
        r = self.c.get('/pki/download/certificate/1/', follow=True)
        self.failUnlessEqual(r.status_code, 200)
        self.assertContains(r, 'Permission denied!')
        user.user_permissions.add(Permission.objects.get(codename="can_download", content_type=ct))
        user.save()
        r = self.c.get('/pki/download/certificate/1/', follow=True)
        self.failUnlessEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'application/force-download')
    
    
