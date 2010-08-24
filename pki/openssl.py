import os, re, sys
import datetime
import string, random

from pki.settings import PKI_OPENSSL_BIN, PKI_OPENSSL_CONF, PKI_DIR, PKI_OPENSSL_TEMPLATE, PKI_SELF_SIGNED_SERIAL

from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
from logging import getLogger

try:
    # available in python-2.5 and greater
    from hashlib import md5 as md5_constructor
except ImportError:
    # compatibility fallback
    from md5 import new as md5_constructor

from django.template.loader import render_to_string

logger = getLogger("pki")

##------------------------------------------------------------------##
## Exception handlers
##------------------------------------------------------------------##

def handle_exception( func='unknown', exception='No exception data available', traceback='No traceback available' ):
    '''Universal exception handler - log and raise'''
    
    logger.error( '' )
    logger.error( '=============================================================' )
    logger.error( ' Exception or error in %s' % func )
    logger.error( '=============================================================' )
    logger.error( '' )
    logger.error( exception )
    logger.error( traceback )
    logger.error( '' )
    
    raise Exception()

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
    try:
        conf = render_to_string(PKI_OPENSSL_TEMPLATE, ctx)
        
        f = open(PKI_OPENSSL_CONF, 'wb')
        f.write(conf)
        f.close()

    except:
        handle_exception("%s.%s" % (self.__class__.__name__, sys._getframe().f_code.co_name), sys.exc_info()[0], sys.exc_info()[1])
        status = False

    return status # is it used somewhere?

##------------------------------------------------------------------##
## OpenSSLActions: All non config related actions
##------------------------------------------------------------------##

class OpensslActions():
    '''Do the real openssl work - Generate keys, csr, sign'''
    
    def __init__(self, type, instance):
        '''Class constructor'''
        
        self.i    = instance
        self.subj = self.build_subject()
        
        if self.i.parent != None:
            self.parent_certs = os.path.join(PKI_DIR, self.i.parent.name, 'certs')
            self.crl = os.path.join(PKI_DIR, self.i.parent.name, 'crl', '%s.crl.pem' % self.i.parent.name)
        else:
            ## self-signed RootCA            
            self.parent_certs = os.path.join(PKI_DIR, self.i.name, 'certs')
            self.crl = os.path.join(PKI_DIR, self.i.name, 'crl', '%s.crl.pem' % self.i.name)
        
        if type == 'ca':
            ca_dir      = os.path.join(PKI_DIR, self.i.name)
            self.key    = os.path.join(ca_dir, 'private', '%s.key.pem' % self.i.name)
            self.ext    = ''
            self.pkcs12 = False
            self.i.subjaltname = ''
        elif type == 'cert':
            ca_dir      = os.path.join(PKI_DIR, self.i.parent.name)
            self.key    = os.path.join(ca_dir, 'certs', '%s.key.pem' % self.i.name)
            self.ext    = '-extensions v3_cert'
            self.pkcs12 = os.path.join(ca_dir, 'certs', '%s.cert.p12' % self.i.name)
            
            if not self.i.subjaltname:
                self.i.subjaltname = 'email:copy'
        
        self.csr  = os.path.join(ca_dir, 'certs', '%s.csr.pem'  % self.i.name)
        self.crt  = os.path.join(ca_dir, 'certs', '%s.cert.pem' % self.i.name)
        self.der  = os.path.join(ca_dir, 'certs', '%s.cert.der' % self.i.name)
        
        ## Generate a random string as ENV variable name
        self.env_pw = "".join(random.sample(string.letters+string.digits, 10))
    
    def exec_openssl(self, command, env_vars=None):
        '''Run openssl command. PKI_OPENSSL_BIN doesn't need to be specified'''
        
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
            logger.error( 'openssl command "%s" failed in %s.%s with returncode %d' % (c[1], self.__class__.__name__, sys._getframe().f_code.co_name, proc.returncode) )
            logger.error( stdout_value )
            
            handle_exception("%s.%s" % (self.__class__.__name__, sys._getframe().f_code.co_name))
        else:
            #logger.error( stdout_value )
            return stdout_value
    
    def generate_key(self):
        '''Generate the secret key'''
        
        logger.info( 'Generating private key' )
        
        key_type = po = pf = ''
        
        if self.i.passphrase:
            key_type = '-des3'
            po = '-passout'
            pf = 'env:%s' % self.env_pw
        
        command = 'genrsa %s -out %s %s %s %s' % (key_type, self.key, po, pf, self.i.key_length)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.passphrase) } )
    
    def generate_self_signed_cert(self):
        '''Generate a self signed root certificate'''
        
        logger.info( 'Generating self-signed root certificate' )
        
        command = ['req', '-config', PKI_OPENSSL_CONF, '-verbose', '-batch', '-new', '-x509', '-subj', self.subj, '-days', str(self.i.valid_days), \
                   '-extensions', 'v3_ca', '-key', self.key, '-out', self.crt, '-passin', 'env:%s' % self.env_pw]
        
        try:
            if PKI_SELF_SIGNED_SERIAL and int(PKI_SELF_SIGNED_SERIAL) > 0:
                command.extend( [ '-set_serial', str(PKI_SELF_SIGNED_SERIAL) ] )
        except:
            logger.error( "Not setting inital serial number to %s. Fallback to random number" % PKI_SELF_SIGNED_SERIAL )
        
        self.exec_openssl( command, env_vars={ self.env_pw: str(self.i.passphrase), })
    
    def generate_csr(self):
        '''Generate the CSR'''
        
        logger.info( 'Generating the CSR for %s' % self.i.name )
        
        command = ['req', '-config', PKI_OPENSSL_CONF, '-new', '-batch', '-subj', self.subj, '-key', self.key, '-out', self.csr, \
                   '-days', str(self.i.valid_days), '-passin', 'env:%s' % self.env_pw]        
        self.exec_openssl(command, env_vars={ self.env_pw: str(self.i.passphrase) })
    
    def generate_der_encoded(self):
        '''Generate a DER encoded version of a given certificate'''
        
        logger.info( 'Generating DER encoded certificate for %s' % self.i.name )
        
        command = 'x509 -in %s -out %s -outform DER' % (self.crt, self.der)
        self.exec_openssl(command.split())
        
        return True
    
    def generate_pkcs12_encoded(self):
        '''Generate a PKCS12 encoded version of a given certificate'''
        
        logger.info( 'Generating PKCS12 encoded certificate for %s' % self.i.name )
        
        command = 'pkcs12 -export -nokeys -in %s -inkey %s -out %s -passout env:%s' % (self.crt, self.key, self.pkcs12, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.pkcs12_passphrase) })
    
    def remove_complete_certificate(self):
        '''Remove all files related to the given certificate'''
        
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
        
        return True
    
    def remove_der_encoded(self):
        '''Remove a DER encoded certificate if it exists'''
        
        if os.path.exists(self.der):
            logger.info( 'Removal of DER encoded certificate for %s' % self.i.name )
            
            os.remove(self.der)
        
        return True
    
    def remove_pkcs12_encoded(self):
        '''Remove a PKCS12 encoded certificate if it exists'''
        
        if self.pkcs12 and os.path.exists(self.pkcs12):
            logger.info( 'Removal of PKCS12 encoded certificate for %s' % self.i.name )
            
            os.remove(self.pkcs12)
    
    def sign_csr(self):
        '''Sign the CSR with given CA'''
        
        logger.info( 'Signing CSR' )
        
        try:
            extension = "-extensions %s" % self.i.cert_extension
        except:
            extension = ""
        
        command = 'ca -config %s -name %s -batch %s -in %s -out %s -days %d %s -passin env:%s' % \
                  ( PKI_OPENSSL_CONF, self.i.parent, self.ext, self.csr, self.crt, self.i.valid_days, extension, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.parent_passphrase), "S_A_N": self.i.subjaltname, })
        
        ## Get the just created serial
        if self.parent_certs:
            serial = self.get_serial_from_cert()
            hash   = self.get_hash_from_cert()
            
            if os.path.exists('%s/%s.0' % (self.parent_certs, hash)):
                os.remove('%s/%s.0' % (self.parent_certs, hash))
            
            os.symlink('%s.pem' % serial, '%s/%s.0' % (self.parent_certs, hash))
    
    def revoke_certificate(self, ppf):
        '''Revoke a given certificate'''
        
        ## Check if certificate is already revoked. May have happened during a incomplete transaction
        if self.get_revoke_status_from_cert():
            logger.info( "Skipping revoke as it already happened" )
            return True
        
        logger.info( 'Revoking certificate %s' % self.i.name )
        
        command = 'ca -config %s -name %s -batch -revoke %s -passin env:%s' % (PKI_OPENSSL_CONF, self.i.parent, self.crt, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(ppf) })
    
    def renew_certificate(self):
        '''Renew/Reissue a given certificate'''
        
        logger.info( 'Renewing certificate %s' % self.i.name )
        
        if os.path.exists(self.csr):
            self.sign_csr()
        else:
            handle_exception( func=__name__, exception="Failed to renew certificate %s! CSR is missing!" % self.i.name )
    
    def generate_crl(self, ca=None, pf=None):
        '''Generate CRL: When a CA is modified'''
        
        logger.info( 'CRL generation for CA %s' % ca )
        
        crl = os.path.join(PKI_DIR, ca, 'crl', '%s.crl.pem' % ca)
        
        command = 'ca -config %s -name %s -gencrl -out %s -crldays 1 -passin env:%s' % (PKI_OPENSSL_CONF, ca, crl, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(pf) })
    
    def update_ca_chain_file(self):
        '''Build/update the CA chain'''
        
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
        
        #ca_cert    = os.path.join( PKI_DIR, self.name, 'certs', '%s.cert.pem' % self.name )
        chain_file = os.path.join( PKI_DIR, self.i.name, '%s-chain.cert.pem' % self.i.name )
        
        try:
            w = open(chain_file, 'w')
            
            for c in chain:
                cert_file = os.path.join( PKI_DIR, c, 'certs', '%s.cert.pem' % c )
                command = 'x509 -in %s' % cert_file
                output  = self.exec_openssl(command.split())
                
                ## Get the subject to print it first in the chain file
                subj = self.get_subject_from_cert(cert_file)
                
                w.write( '%s\n' % subj )
                w.write(output)
            
            w.close()
        except:
            handle_exception(__name__, 'Failed to write chain file!')
    
    
    def build_subject(self):
        '''Return a subject string for CSR and self-sgined certs'''
        
        subj = '/CN=%s/C=%s/ST=%s/localityName=%s/O=%s' % ( self.i.common_name,
                                                            self.i.country,
                                                            self.i.state,
                                                            self.i.locality,
                                                            self.i.organization,
                                                          )
        
        if self.i.OU:
            subj += '/organizationalUnitName=%s' % self.i.OU
        
        if self.i.email:
            subj += '/emailAddress=%s' % self.i.email
        
        return subj
    
    def get_serial_from_cert(self):
        '''Use openssl to get the serial number from a given certificate'''
        
        command = 'x509 -in %s -noout -serial' % self.crt
        output  = self.exec_openssl(command.split())
        
        x = output.rstrip("\n").split('=')
        
        return x[1]
    
    def get_hash_from_cert(self):
        '''Use openssl to get the hash value of a given certificate'''
        
        command = 'x509 -hash -noout -in %s' % self.crt
        output  = self.exec_openssl(command.split())
        
        return output.rstrip("\n")
    
    def get_subject_from_cert(self, cert):
        '''Get the subject form a given CA certificate'''
        
        command = 'x509 -noout -subject -in %s' % cert
        output  = self.exec_openssl(command.split())
        return output.rstrip("\n")

    def get_revoke_status_from_cert(self):
        '''Is the given certificate already revoked? True=yes, False=no'''
        
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
    
class OpensslCaManagement():
    
    def __init__(self, ca, passphrase):
        
        self.ca      = ca
        self.ca_dir  = os.path.join(PKI_DIR, self.ca)
        self.ca_pass = passphrase
        
        self.openssl_conf = os.path.join(PKI_DIR, 'openssl.conf')
    
    def generate_crl(self):
        '''Generate CRL: When a CA is modified'''
        
        logger.info( 'CRL generation for CA %s' % self.ca )
        
        proc = Popen('/usr/bin/openssl ca -config %s -name %s -gencrl -crldays 1 -out %s/crl/%s.crl.pem -passin pass:"%s"' %
                      (self.openssl_conf, self.ca, self.ca_dir, self.ca, self.ca_pass),
                      shell=True,
                      stdin=PIPE,
                      stdout=PIPE,
                      stderr=STDOUT,
                    )
        stdout_value, stderr_value = proc.communicate()
        
        if proc.returncode != 0:
            logger.error( 'openssl command ca failed in %s.%s with returncode %d' % (self.__class__.__name__, sys._getframe().f_code.co_name, proc.returncode) )            
            handle_exception("%s.%s" % (self.__class__.__name__, sys._getframe().f_code.co_name))
        
        return True

