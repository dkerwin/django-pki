import os
import re
import sys
import string
import random

from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
from logging import getLogger

from django.template.loader import render_to_string

from pki.settings import PKI_OPENSSL_BIN, PKI_OPENSSL_CONF, PKI_DIR, PKI_OPENSSL_TEMPLATE, PKI_SELF_SIGNED_SERIAL
from pki.helper import subject_for_object
import pki.models

try:
    # available in python-2.5 and greater
    from hashlib import md5 as md5_constructor
except ImportError:
    # compatibility fallback
    from md5 import new as md5_constructor

logger = getLogger("pki")

##------------------------------------------------------------------##
## OpenSSLConfig: Config related stuff
##------------------------------------------------------------------##

def refresh_pki_metadata(ca_list):
    """Refresh pki metadata (PKI storage directories and openssl configuration files)

    Each ca_list element is a dictionary:
    'name': CA name
    'subcas_allowed': sub CAs allowed (boolean)
    """
    
    status = True
    
    # refresh directory structure
    dirs = { 'certs'  : 0755,
             'private': 0700,
             'crl'    : 0755,
           }
    
    try:
        # create base PKI directory if necessary
        if not os.path.exists(PKI_DIR):
            logger.info('Creating base PKI directory')
            os.mkdir(PKI_DIR, 0700)
        
        # list of old CA directories for possible purging
        purge_dirs = set([os.path.join(PKI_DIR, d) for d in os.listdir(PKI_DIR)
                          if os.path.isdir(os.path.join(PKI_DIR, d))])
        
        # loop over CAs and create necessary filesystem objects
        for ca in ca_list:
            
            ca_dir = os.path.join(PKI_DIR, ca.name)
            
            # create CA directory if necessary
            if not ca_dir in purge_dirs:
                logger.info('Creating base directory for CA %s' % ca.name)
                os.mkdir(ca_dir)
                
                # create nested directories for key storage with proper permissions
                for d, m in dirs.items():
                    os.mkdir(os.path.join(ca_dir, d), m)
                
                initial_serial = 0x01
                
                try:
                    if not ca.parent and int(PKI_SELF_SIGNED_SERIAL) > 0:
                        initial_serial = PKI_SELF_SIGNED_SERIAL+1 
                except ValueError:
                    logger.error( "PKI_SELF_SIGNED_SERIAL failed conversion to int!" )
                
                h2s = '%X' % initial_serial
                
                if len(h2s) % 2 == 1:
                    h2s = '0' + h2s
                
                # initialize certificate serial number
                s = open(os.path.join(ca_dir, 'serial'), 'wb')
                s.write(h2s)
                s.close()
                
                # initialize CRL serial number
                s = open(os.path.join(ca_dir, 'crlnumber'), 'wb')
                s.write('01')
                s.close()
                
                # touch certificate index file
                open(os.path.join(ca_dir, 'index.txt'), 'wb').close()
            
            # do not delete existing CA dir
            purge_dirs.discard(ca_dir)
        
        # purge unused CA directories
        for d in purge_dirs:
            if os.path.isdir(d):
                # extra check in order to keep unrelated directory from recursive removal...
                # (in case if something wrong with paths)
                # probably can be removed when debugging will be finished
                if os.path.isfile(os.path.join(d, 'crlnumber')):
                    logger.debug("Purging CA directory tree %s" % d)
                    rmtree(d) # FIXME: commented for debugging purposes
                else:
                    logger.warning('Directory %s does not contain any metadata, preserving it' % d)
        
    except OSError, e: # FIXME: probably catch any exception here, not just OS
        status = False
        logger.error("Refreshing directory structure failed: %s" % e)
    
    # prepare context for template rendering
    ctx = {'ca_list': ca_list}

    # render template and save result to openssl.conf
    conf = render_to_string(PKI_OPENSSL_TEMPLATE, ctx)
    
    f = open(PKI_OPENSSL_CONF, 'wb')
    f.write(conf)
    f.close()
    return status # is it used somewhere?

##------------------------------------------------------------------##
## OpenSSLActions: All non config related actions
##------------------------------------------------------------------##

class OpensslActions():
    """OpenSSL command and task wrapper class
    
    instance must be a CertificateAuthority or Certificate object.
    """
    
    def __init__(self, instance):
        """Initialize shared varaibles and verify instance type"""
        
        self.i    = instance
        self.subj = subject_for_object(self.i)
        
        if self.i.parent != None:
            self.parent_certs = os.path.join(PKI_DIR, self.i.parent.name, 'certs')
            self.crl = os.path.join(PKI_DIR, self.i.parent.name, 'crl', '%s.crl.pem' % self.i.parent.name)
        else:
            self.parent_certs = os.path.join(PKI_DIR, self.i.name, 'certs')
            self.crl = os.path.join(PKI_DIR, self.i.name, 'crl', '%s.crl.pem' % self.i.name)
        
        if isinstance(instance, pki.models.CertificateAuthority):
            ca_dir      = os.path.join(PKI_DIR, self.i.name)
            self.key    = os.path.join(ca_dir, 'private', '%s.key.pem' % self.i.name)
            self.pkcs12 = False
            self.i.subjaltname = ''
        elif isinstance(instance, pki.models.Certificate):
            if self.i.parent:
                ca_dir = os.path.join(PKI_DIR, self.i.parent.name)
            else:
                ca_dir = os.path.join(PKI_DIR, "_SELF_SIGNED_CERTIFICATES")
                if not os.path.exists(ca_dir):
                    try:
                        os.mkdir(ca_dir, 0755)
                        os.mkdir(os.path.join(ca_dir, "certs"))
                    except OSError, e:
                        logger.exception("Failed to create directories for self-signed certificates %s" % ca_dir)
                        raise

            self.key    = os.path.join(ca_dir, 'certs', '%s.key.pem' % self.i.name)
            self.pkcs12 = os.path.join(ca_dir, 'certs', '%s.cert.p12' % self.i.name)
            
            if not self.i.subjaltname:
                self.i.subjaltname = 'email:copy'
            
            if self.i.parent and self.i.parent.crl_distribution:
                self.i.crl_distribution = self.i.parent.crl_distribution
        else:
            raise Exception( "Given object type is unknown!" )
        
        self.csr  = os.path.join(ca_dir, 'certs', '%s.csr.pem'  % self.i.name)
        self.crt  = os.path.join(ca_dir, 'certs', '%s.cert.pem' % self.i.name)
        self.der  = os.path.join(ca_dir, 'certs', '%s.cert.der' % self.i.name)
        
        ## Generate a random string as ENV variable name
        self.env_pw = "".join(random.sample(string.letters+string.digits, 10))
    
    def exec_openssl(self, command, env_vars=None):
        """Run a openssl command.
        
        command is prefixed with openssl binary from PKI_OPENSSL_BIN
        env_vars is a dict containing the set environment variables
        """
        
        c = [PKI_OPENSSL_BIN]
        c.extend(command)
        
        # add PKI_DIR environment variable if caller did not set it
        if env_vars:
            env_vars.setdefault('PKI_DIR', PKI_DIR)
        else:
            env_vars = { 'PKI_DIR': PKI_DIR }
        
        proc = Popen( c, shell=False, env=env_vars, stdin=PIPE, stdout=PIPE, stderr=STDOUT )
        stdout_value, stderr_value = proc.communicate()
        
        if proc.returncode != 0:
            logger.error( 'openssl command "%s" failed with returncode %d' % (c[1], proc.returncode) )
            logger.error( stdout_value )
            
            raise Exception( stdout_value )
        else:
            return stdout_value
    
    def generate_key(self):
        """RSA key generation.
        
        Key will be encrypted with des3 if passphrase is given.
        """
        
        key_type = po = pf = ''
        
        if self.i.passphrase:
            key_type = '-des3'
            po = '-passout'
            pf = 'env:%s' % self.env_pw
        
        command = 'genrsa %s -out %s %s %s %s' % (key_type, self.key, po, pf, self.i.key_length)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.passphrase) } )
    
    def generate_self_signed_cert(self):
        """Generate a self signed root certificate.
        
        Serial is set to user specified value when PKI_SELF_SIGNED_SERIAL > 0
        """
        
        logger.info( 'Generating self-signed root certificate' )
        
        try:
            extension = self.i.cert_extension
        except:
            if self.i.crl_distribution:
                extension = "v3_ca_cdp"
            else:
                extension = "v3_ca"
        
        command = ['req', '-config', PKI_OPENSSL_CONF, '-verbose', '-batch', '-new', '-x509', '-subj', self.subj, '-days', str(self.i.valid_days), \
                   '-extensions', extension, '-key', self.key, '-out', self.crt, '-passin', 'env:%s' % self.env_pw]
        
        try:
            if PKI_SELF_SIGNED_SERIAL and int(PKI_SELF_SIGNED_SERIAL) > 0:
                command.extend( [ '-set_serial', str(PKI_SELF_SIGNED_SERIAL) ] )
        except ValueError, e:
            logger.error( "Not setting inital serial number to %s. Fallback to random number" % PKI_SELF_SIGNED_SERIAL )
            logger.error( e )
        
        env = { self.env_pw: str(self.i.passphrase), "S_A_N": self.i.subjaltname }
        try:
            env['C_D_P'] = self.i.crl_distribution
        except:
            pass
        
        self.exec_openssl( command, env_vars=env )
    
    def generate_csr(self):
        """CSR (Certificate Signing Request) generation"""
        
        logger.info( 'Generating the CSR for %s' % self.i.name )
        
        command = ['req', '-config', PKI_OPENSSL_CONF, '-new', '-batch', '-subj', self.subj, '-key', self.key, '-out', self.csr, \
                   '-days', str(self.i.valid_days), '-passin', 'env:%s' % self.env_pw]        
        self.exec_openssl(command, env_vars={ self.env_pw: str(self.i.passphrase) })
    
    def generate_der_encoded(self):
        """Generate a DER encoded certificate"""
        
        logger.info( 'Generating DER encoded certificate for %s' % self.i.name )
        
        command = 'x509 -in %s -out %s -outform DER' % (self.crt, self.der)
        self.exec_openssl(command.split())
    
    def remove_der_encoded(self):
        """Remove a DER encoded certificate"""
        
        if os.path.exists(self.der):
            logger.info( 'Removal of DER encoded certificate for %s' % self.i.name )
            
            try:
                os.remove(self.der)
            except OSError, e:
                logger.error( "Failed to remove %s" % self.der )
                raise Exception( e )
    
    def generate_pkcs12_encoded(self):
        """Generate a PKCS12 encoded certificate.
        
        Passphrase is required as empty passwords not work in batch mode.
        """
        
        command = 'pkcs12 -export -nokeys -in %s -inkey %s -out %s -passout env:%s' % (self.crt, self.key, self.pkcs12, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.pkcs12_passphrase) })
    
    def remove_pkcs12_encoded(self):
        """Remove a PKCS12 encoded certificate if it exists"""
        
        if self.pkcs12 and os.path.exists(self.pkcs12):
            logger.info( 'Removal of PKCS12 encoded certificate for %s' % self.i.name )
            
            os.remove(self.pkcs12)
    
    def remove_complete_certificate(self):
        """Remove all files related to the given certificate.
        
        This includes the hash alias, key, csr and the certificate itself.
        """
        
        self.remove_der_encoded()
        self.remove_pkcs12_encoded()
        
        hash = "%s/%s.0" % (self.parent_certs, self.get_hash_from_cert())
        if os.path.exists(hash):
            os.remove(hash)
        
        serial = "%s/%s.pem" % (self.parent_certs, self.get_serial_from_cert())
        if os.path.exists(serial):
            os.remove(serial)
        
        if os.path.exists(self.csr):
            os.remove(self.csr)
        
        if os.path.exists(self.key):
            os.remove(self.key)
        
        if os.path.exists(self.crt):
            os.remove(self.crt)
    
    def sign_csr(self):
        """Sign the CSR.
        
        Certificate signing and hash creation in CA's certificate directory
        """
        
        env = { self.env_pw: str(self.i.parent_passphrase), "S_A_N": self.i.subjaltname, }
        
        try:
            extension = "-extensions %s" % self.i.cert_extension
            if self.i.crl_distribution:
                extension += "_cdp"
                env["C_D_P"] = self.i.crl_distribution
        except:
            extension = ""
        
        command = 'ca -config %s -name %s -batch -in %s -out %s -days %d %s -passin env:%s' % \
                  ( PKI_OPENSSL_CONF, self.i.parent.name, self.csr, self.crt, self.i.valid_days, extension, self.env_pw)
        
        self.exec_openssl(command.split(), env_vars=env)
        
        ## Get the just created serial
        if self.parent_certs:
            serial = self.get_serial_from_cert()
            hash   = self.get_hash_from_cert()
            
            if os.path.exists('%s/%s.0' % (self.parent_certs, hash)):
                os.remove('%s/%s.0' % (self.parent_certs, hash))
            
            os.symlink('%s.pem' % serial, '%s/%s.0' % (self.parent_certs, hash))
    
    def revoke_certificate(self, ppf):
        """Revoke a certificate.
        
        Requires the parents passphrase.
        """
        
        ## Check if certificate is already revoked. May have happened during a incomplete transaction
        if self.get_revoke_status_from_cert():
            logger.info( "Skipping revoke as it already happened" )
            return True
        
        command = 'ca -config %s -name %s -batch -revoke %s -passin env:%s' % (PKI_OPENSSL_CONF, self.i.parent.name, self.crt, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(ppf) })
    
    def generate_crl(self, ca=None, pf=None):
        """CRL (Certificate Revocation List) generation.
        
        Requires the Certificate Authority and the passphrase. 
        """
        
        crl = os.path.join(PKI_DIR, ca, 'crl', '%s.crl.pem' % ca)
        
        command = 'ca -config %s -name %s -gencrl -out %s -crldays 1 -passin env:%s' % (PKI_OPENSSL_CONF, ca, crl, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(pf) })
    
    def update_ca_chain_file(self):
        """Build/update the CA chain.
        
        Generates a chain file containing all CA's required to verify the given certificate.
        """
        
        ## Build list of parents
        chain = []
        chain_str = ''
        
        p = self.i.parent
        
        if self.i.parent == None:
            chain.append( self.i.name )
        else:
            chain.append( self.i.name )
            while p != None:
                chain.append(p.name)
                p = p.parent
        
        chain.reverse()
        
        chain_file = os.path.join( PKI_DIR, self.i.name, '%s-chain.cert.pem' % self.i.name )
        
        try:
            w = open(chain_file, 'w')
            
            for c in chain:
                cert_file = os.path.join( PKI_DIR, c, 'certs', '%s.cert.pem' % c )
                command = 'x509 -in %s' % cert_file
                output  = self.exec_openssl(command.split())
                
                ## Get the subject to print it first in the chain file
                subj = subject_for_object(self.i)
                
                w.write( '%s\n' % subj )
                w.write(output)
            
            w.close()
        except:
            raise Exception( 'Failed to write chain file!' )
    
    def get_serial_from_cert(self):
        """Extract serial from certificate.
        
        Use openssl to get the serial number from a certificate.
        """
        
        command = 'x509 -in %s -noout -serial' % self.crt
        output  = self.exec_openssl(command.split())
        
        x = output.rstrip("\n").split('=')
        
        if (len(x[1]) > 2):
            sl = re.findall('[a-fA-F0-9]{2}', x[1].lower())
            return ':'.join(sl)
        
        return x[1].lower()
    
    def get_hash_from_cert(self):
        """Extract hash from certificate.
        
        Use openssl to get the hash value from a certificate.
        """
        
        command = 'x509 -hash -noout -in %s' % self.crt
        output  = self.exec_openssl(command.split())
        
        return output.rstrip("\n")
    
    def get_revoke_status_from_cert(self):
        """Get the revoke status from certificate.
        
        Certificate is revoked => True
        Certificate is active  => False
        """
        
        command = 'crl -text -noout -in %s' % self.crl
        output  = self.exec_openssl(command.split())
        
        serial_re = re.compile('^\s+Serial\sNumber\:\s+(\w+)')
        lines = output.split('\n')
        
        for l in lines:
            if serial_re.match(l):
                if serial_re.match(l).group(1) == self.i.serial:
                    logger.info( "The certificate is revoked" )
                    return True
        
        return False
    
    def dump_certificate(self):
        """Dump a certificate"""
        
        command = "x509 -in %s -noout -text" % self.crt
        output  = self.exec_openssl(command.split())
        
        return "%s" % output
