import os
import datetime
from logging import getLogger
from shutil import rmtree

from django.db import models

from pki.openssl import OpensslActions, md5_constructor, refresh_pki_metadata
from pki.settings import ADMIN_MEDIA_PREFIX, MEDIA_URL, PKI_BASE_URL, PKI_DEFAULT_COUNTRY, PKI_ENABLE_GRAPHVIZ, PKI_ENABLE_EMAIL

logger = getLogger("pki")

##------------------------------------------------------------------##
## Choices
##------------------------------------------------------------------##

KEY_LENGTH = ( (1024, '1024'), (2048, '2048'), (4096, '4096'), )
POLICY     = ( ('policy_match', 'policy_match'), ('policy_anything', 'policy_anything'), )
ACTIONS    = ( ('create', 'Create a new certificate'),
               ('update', 'Update description and export options'),
               ('revoke', 'Revoke certificate. May break chain'),
               ('renew',  'Renew CSR but name, CN and key stay the same. Doesn\'t break chains'),
             )
CA_TYPES   = ( ('RootCA', 'self-signed (RootCA)'), ('SubCA', 'SubCA'), )
EXTENSIONS = ( ('v3_server_cert', 'V3 Server'), ('v3_client_cert', 'V3 Client' ), )
COUNTRY    = ( ('AD', 'AD'),('AE', 'AE'),('AF', 'AF'),('AG', 'AG'),('AI', 'AI'),('AL', 'AL'),('AM', 'AM'),
               ('AN', 'AN'),('AO', 'AO'),('AQ', 'AQ'),('AR', 'AR'),('AS', 'AS'),('AT', 'AT'),('AU', 'AU'),
               ('AW', 'AW'),('AZ', 'AZ'),('BA', 'BA'),('BB', 'BB'),('BD', 'BD'),('BE', 'BE'),('BF', 'BF'),
               ('BG', 'BG'),('BH', 'BH'),('BI', 'BI'),('BJ', 'BJ'),('BM', 'BM'),('BN', 'BN'),('BO', 'BO'),
               ('BR', 'BR'),('BS', 'BS'),('BT', 'BT'),('BU', 'BU'),('BV', 'BV'),('BW', 'BW'),('BY', 'BY'),
               ('BZ', 'BZ'),('CA', 'CA'),('CC', 'CC'),('CF', 'CF'),('CG', 'CG'),('CH', 'CH'),('CI', 'CI'),
               ('CK', 'CK'),('CL', 'CL'),('CM', 'CM'),('CN', 'CN'),('CO', 'CO'),('CR', 'CR'),('CS', 'CS'),
               ('CU', 'CU'),('CV', 'CV'),('CX', 'CX'),('CY', 'CY'),('CZ', 'CZ'),('DD', 'DD'),('DE', 'DE'),
               ('DJ', 'DJ'),('DK', 'DK'),('DM', 'DM'),('DO', 'DO'),('DZ', 'DZ'),('EC', 'EC'),('EE', 'EE'),
               ('EG', 'EG'),('EH', 'EH'),('ER', 'ER'),('ES', 'ES'),('ET', 'ET'),('FI', 'FI'),('FJ', 'FJ'),
               ('FK', 'FK'),('FM', 'FM'),('FO', 'FO'),('FR', 'FR'),('FX', 'FX'),('GA', 'GA'),('GB', 'GB'),
               ('GD', 'GD'),('GE', 'GE'),('GF', 'GF'),('GH', 'GH'),('GI', 'GI'),('GL', 'GL'),('GM', 'GM'),
               ('GN', 'GN'),('GP', 'GP'),('GQ', 'GQ'),('GR', 'GR'),('GS', 'GS'),('GT', 'GT'),('GU', 'GU'),
               ('GW', 'GW'),('GY', 'GY'),('HK', 'HK'),('HM', 'HM'),('HN', 'HN'),('HR', 'HR'),('HT', 'HT'),
               ('HU', 'HU'),('ID', 'ID'),('IE', 'IE'),('IL', 'IL'),('IN', 'IN'),('IO', 'IO'),('IQ', 'IQ'),
               ('IR', 'IR'),('IS', 'IS'),('IT', 'IT'),('JM', 'JM'),('JO', 'JO'),('JP', 'JP'),('KE', 'KE'),
               ('KG', 'KG'),('KH', 'KH'),('KI', 'KI'),('KM', 'KM'),('KN', 'KN'),('KP', 'KP'),('KR', 'KR'),
               ('KW', 'KW'),('KY', 'KY'),('KZ', 'KZ'),('LA', 'LA'),('LB', 'LB'),('LC', 'LC'),('LI', 'LI'),
               ('LK', 'LK'),('LR', 'LR'),('LS', 'LS'),('LT', 'LT'),('LU', 'LU'),('LV', 'LV'),('LY', 'LY'),
               ('MA', 'MA'),('MC', 'MC'),('MD', 'MD'),('MG', 'MG'),('MH', 'MH'),('ML', 'ML'),('MM', 'MM'),
               ('MN', 'MN'),('MO', 'MO'),('MP', 'MP'),('MQ', 'MQ'),('MR', 'MR'),('MS', 'MS'),('MT', 'MT'),
               ('MU', 'MU'),('MV', 'MV'),('MW', 'MW'),('MX', 'MX'),('MY', 'MY'),('MZ', 'MZ'),('NA', 'NA'),
               ('NC', 'NC'),('NE', 'NE'),('NF', 'NF'),('NG', 'NG'),('NI', 'NI'),('NL', 'NL'),('NO', 'NO'),
               ('NP', 'NP'),('NR', 'NR'),('NT', 'NT'),('NU', 'NU'),('NZ', 'NZ'),('OM', 'OM'),('PA', 'PA'),
               ('PE', 'PE'),('PF', 'PF'),('PG', 'PG'),('PH', 'PH'),('PK', 'PK'),('PL', 'PL'),('PM', 'PM'),
               ('PN', 'PN'),('PR', 'PR'),('PT', 'PT'),('PW', 'PW'),('PY', 'PY'),('QA', 'QA'),('RE', 'RE'),
               ('RO', 'RO'),('RU', 'RU'),('RW', 'RW'),('SA', 'SA'),('SB', 'SB'),('SC', 'SC'),('SD', 'SD'),
               ('SE', 'SE'),('SG', 'SG'),('SH', 'SH'),('SI', 'SI'),('SJ', 'SJ'),('SK', 'SK'),('SL', 'SL'),
               ('SM', 'SM'),('SN', 'SN'),('SO', 'SO'),('SR', 'SR'),('ST', 'ST'),('SU', 'SU'),('SV', 'SV'),
               ('SY', 'SY'),('SZ', 'SZ'),('TC', 'TC'),('TD', 'TD'),('TF', 'TF'),('TG', 'TG'),('TH', 'TH'),
               ('TJ', 'TJ'),('TK', 'TK'),('TM', 'TM'),('TN', 'TN'),('TO', 'TO'),('TP', 'TP'),('TR', 'TR'),
               ('TT', 'TT'),('TV', 'TV'),('TW', 'TW'),('TZ', 'TZ'),('UA', 'UA'),('UG', 'UG'),('UM', 'UM'),
               ('US', 'US'),('UY', 'UY'),('UZ', 'UZ'),('VA', 'VA'),('VC', 'VC'),('VE', 'VE'),('VG', 'VG'),
               ('VI', 'VI'),('VN', 'VN'),('VU', 'VU'),('WF', 'WF'),('WS', 'WS'),('YD', 'YD'),('YE', 'YE'),
               ('YT', 'YT'),('YU', 'YU'),('ZA', 'ZA'),('ZM', 'ZM'),('ZR', 'ZR'),('ZW', 'ZW'),('ZZ', 'ZZ'),
               ('ZZ', 'ZZ'),
              )

##------------------------------------------------------------------##
## Base DB classes
##------------------------------------------------------------------##

class CertificateBase(models.Model):
    """Base class for all type of certificates"""
    
    description  = models.CharField(max_length=255)
    country      = models.CharField(max_length=2, choices=COUNTRY, default='%s' % PKI_DEFAULT_COUNTRY.upper() )
    state        = models.CharField(max_length=32)
    locality     = models.CharField(max_length=32)
    organization = models.CharField(max_length=64)
    OU           = models.CharField(max_length=64,blank=True, null=True)
    email        = models.EmailField(blank=True, null=True)
    valid_days   = models.IntegerField()
    key_length   = models.IntegerField(choices=KEY_LENGTH, default=2048)
    expiry_date  = models.DateField(blank=True,null=True)
    created      = models.DateTimeField(blank=True,null=True)
    revoked      = models.DateTimeField(blank=True,null=True)
    active       = models.BooleanField(default=True, help_text="Turn off to revoke this certificate")
    serial       = models.CharField(max_length=64, blank=True, null=True)
    ca_chain     = models.CharField(max_length=200, blank=True, null=True)
    pem_encoded  = models.BooleanField(default=False)
    der_encoded  = models.BooleanField(default=False, verbose_name="DER encoding")
    action       = models.CharField(max_length=32, choices=ACTIONS, default='create', help_text="Yellow fields can/have to be modified!")
    
    class Meta:
        abstract = True
    
    ##------------------------------------------------------------------##
    ## Helper functions
    ##------------------------------------------------------------------##
    
    def get_icon_html(self, state):
        """Return HTML based on state.
        
        True : Return Django's yes icon
        False: Return Django's no icon
        """
        
        if state is True:
            return '<img class="centered" src="%simg/admin/icon-yes.gif" alt="True">' % ADMIN_MEDIA_PREFIX
        else:
            return '<img class="centered" src="%simg/admin/icon-no.gif" alt="False" />'  % ADMIN_MEDIA_PREFIX
    
    def get_pki_icon_html(self, img, alt="", title="", css="centered"):
        """Return HTML for given image.
        
        Can add optional alt and title parameters.
        """
        
        if css:
            css_class = 'class=%s' % css
        else:
            css_class = ''
        
        img_path = os.path.join(PKI_BASE_URL, MEDIA_URL, 'pki/img', img)
        return '<img %s src="%s" alt="%s" title="%s"/>' % (css_class, img_path, alt, title)
    
    ##------------------------------------------------------------------##
    ## Changelist list_display functions
    ##------------------------------------------------------------------##
    
    def active_center(self):
        """Overwrite the Booleanfield admin for admin's changelist"""
        
        return self.get_icon_html(self.active)
    
    active_center.allow_tags = True
    active_center.short_description = 'Active'
    active_center.admin_order_field = 'active'
    
    def Serial_align_right(self):
        """Make serial in changelist right justified"""
        
        return '<div class="serial_align_right">%s</div>' % self.serial
    
    Serial_align_right.allow_tags = True
    Serial_align_right.short_description = 'Serial'
    Serial_align_right.admin_order_field = 'serial'
    
    def Description(self):
        """Limit description for changelist.
        
        Limit description to 30 characters to make changelist stay on one line per item.
        At least in most cases.
        """
        
        if len(self.description) > 30:
            return "%s..." % self.description[:30]
        else:
            return "%s" % self.description
    
    Description.allow_tags = True
    Description.admin_order_field = 'description'
    
    def Creation_date(self):
        """Return creation date in custom format"""
        
        return self.created.strftime("%Y-%m-%d %H:%M:%S")
    
    def Expiry_date(self):
        """Return expiry date with days left.
        
        Return color marked expiry date based on days left.
        < 0 : EXPIRED text and red font color
        < 30: Orange color
        > 30: Just date and days left
        """
        now = datetime.datetime.now().date()        
        diff = self.expiry_date - now
        
        if diff.days < 30 and diff.days >= 0:
            return '<div class="almost_expired">%s (%sd)</div>' % (self.expiry_date, diff.days)
        elif diff.days < 0:
            return '<div class="expired">%s (EXPIRED)</div>' % self.expiry_date
        else:
            return '%s (%sd)' % (self.expiry_date, diff.days)
    
    Expiry_date.allow_tags = True
    Expiry_date.admin_order_field = 'expiry_date'
    
    def Chain(self):
        """Display chain with working arrows"""
        
        return self.ca_chain
    
    Chain.allow_tags = True
    Chain.short_description = "CA Chain"
    
    def Chain_link(self):
        """Display chain link.
        
        If PKI_ENABLE_GRAPHVIZ is True a colored chain link is displayed. Otherwise
        a b/w chain icon without link is displayed.
        """
        
        type = "cert"
        
        if self.__class__.__name__ == "CertificateAuthority":
            type = "ca"
        
        if PKI_ENABLE_GRAPHVIZ:
            return '<a href="%spki/chain/%s/%d" target="_blank">%s</a>' % (PKI_BASE_URL, type, self.pk, self.get_pki_icon_html('chain.png', "Show chain", "Show object chain"))
        else:
            return '<center>%s</center>' % self.get_pki_icon_html("chain.png", "Show chain", "Enable setting PKI_ENABLE_GRAPHVIZ")
    
    Chain_link.allow_tags = True
    Chain_link.short_description = 'Chain'
    
    def Email_link(self):
        """Display email link based on status.
        
        If PKI_ENABLE_EMAIL or certificate isn't active a disabled (b/w) icon is displayed.
        If no email address is set in the certificate a icon with exclamation mark is displayed.
        Otherwise the normal icon is returned.
        """
        
        if not PKI_ENABLE_EMAIL:
            result  = '<center>%s</center>' % self.get_pki_icon_html("mail--arrow_bw.png", "Send email", "Enable setting PKI_ENABLE_EMAIL")
        elif not self.active:
            result  = '<center>%s</center>' % self.get_pki_icon_html("mail--arrow_bw.png", "Send email", "Certificate is revoked. Disabled")
        else:
            type = "cert"
            
            if self.__class__.__name__ == "CertificateAuthority": type = "ca"
            
            if self.email:
                result  = '<center><a href="%spki/email/%s/%d">%s</a></center>' % (PKI_BASE_URL, type, self.pk, self.get_pki_icon_html("mail--arrow.png", "Send email", "Send cert to specified email"))
            else:
                result  = '<center>%s</center>' % self.get_pki_icon_html("mail--exclamation.png", "Send email", "Certificate has no email set. Disabled")
        
        return result
    
    Email_link.allow_tags = True
    Email_link.short_description = 'Email'
    
    def Download_link(self):
        """Return a download icon.
        
        Based on object status => clickable icon or just a b/w image
        """
        
        if self.active:
            type = "cert"
            
            if self.__class__.__name__ == "CertificateAuthority": type = "ca"
            
            return '<center><a href="%spki/download/%s/%d/">%s ZIP</href></center>' % (PKI_BASE_URL, type, self.pk, \
                                                                                                 self.get_pki_icon_html("drive-download.png", "Download", "Download certificate data", css=None))
        else:
            return '<center>%s<font color="grey">ZIP</font></center>' % self.get_pki_icon_html("drive-download_bw.png", "Download", "Cannot download because certificate is revoked")
    
    Download_link.allow_tags = True
    Download_link.short_description = 'Download'
    
    def Parent_link(self):
        """Return parent name.
        
        Returns parent's name when parent != None or self-signed
        """
        
        if self.parent:
            return '<a href="../certificateauthority/%d/">%s</a>' % (self.parent.pk, self.parent.common_name)
        else:
            return '<a href="../%s/%d/">self-signed</a>' % (self.__class__.__name__.lower(), self.pk)
    
    Parent_link.allow_tags = True
    Parent_link.short_description = 'Parent'
    Parent_link.admin_order_field = 'parent'
    
    def Certificate_Dump(self):
        """Dump of the certificate"""
        
        if self.pk:
            a = OpensslActions(self)
            return "<textarea id=\"certdump\">%s</textarea>" % a.dump_certificate()
        else:
            return "Nothing to display"
    
    Certificate_Dump.allow_tags = True
    Certificate_Dump.short_description = "Certificate dump"
    
##------------------------------------------------------------------##
## Certificate authority class
##------------------------------------------------------------------##

class CertificateAuthority(CertificateBase):
    """Certificate Authority model"""
    
    ##---------------------------------##
    ## Model definition
    ##---------------------------------##
    
    common_name       = models.CharField(max_length=64, unique=True)
    name              = models.CharField(max_length=64, unique=True, help_text="Only change the suggestion if you really know what you're doing")
    subcas_allowed    = models.BooleanField(verbose_name="Sub CA's allowed", help_text="If enabled you cannot sign certificates with this CA")
    parent            = models.ForeignKey('self', blank=True, null=True)
    type              = models.CharField(max_length=32, null=True, choices=CA_TYPES, default='RootCA')
    passphrase        = models.CharField(max_length=255, blank=True, help_text="At least 8 characters. Remeber this passphrase - <font color='red'> \
                                                                    <strong>IT'S NOT RECOVERABLE</strong></font><br>Will be shown as md5 encrypted string")
    parent_passphrase = models.CharField(max_length=255, null=True, blank=True, help_text="Leave empty if this is a top-level CA")
    pf_encrypted      = models.NullBooleanField()
    policy            = models.CharField(max_length=50, choices=POLICY, default='policy_anything', help_text='policy_match: All subject settings must \
                                                                                                              match the signing CA<br> \
                                                                                                              policy_anything: Nothing has to match the \
                                                                                                              signing CA')
    #crl_distribution  = models.URLField(verbose_name='CRL Distribution Point', null=True, blank=True, verify_exists=False, help_text='Optional CRL distribution URL (http://my.host.com/ca.crl)')

    class Meta:
        verbose_name_plural = 'Certificate Authorities'
        permissions         = ( ( "can_download_ca", "Can download", ), )
    
    def __unicode__(self):
        return self.common_name
    
    ##---------------------------------##
    ## Redefined functions
    ##---------------------------------##
    
    def save(self, *args, **kwargs):
        """Save the CertificateAuthority object"""
        
        if self.pk:
            ## existing CA
            if self.action in ('update', 'revoke', 'renew'):
                
                action = OpensslActions(self)
                prev   = CertificateAuthority.objects.get(pk=self.pk)
                
                ## Update description. This is always allowed
                prev.description = self.description
                
                ## Create or remove DER certificate. Doesn't hurt to do this anyway
                if self.der_encoded:
                    action.generate_der_encoded()
                else:
                    action.remove_der_encoded()
                
                prev.der_encoded = self.der_encoded
                    
                if self.action == 'revoke':
                    if not self.parent:
                        raise Exception( "You cannot revoke a self-signed certificate! No parent => No revoke" )
                    
                    ## DB-revoke all related certs
                    garbage = []
                    id_dict = { 'cert': [], 'ca': [], }
                    
                    from pki.views import chain_recursion as r_chain_recursion
                    r_chain_recursion(self.id, garbage, id_dict)
                    
                    for i in id_dict['cert']:
                        x = Certificate.objects.get(pk=i)
                        x.active         = False
                        x.der_encoded    = False
                        x.pem_encoded    = False
                        x.pkcs12_encoded = False
                        x.revoked        = datetime.datetime.now()
                        
                        super(Certificate, x).save(*args, **kwargs)
                    
                    for i in id_dict['ca']:
                        x = CertificateAuthority.objects.get(pk=i)
                        x.active      = False
                        x.der_encoded = False
                        x.pem_encoded = False
                        x.revoked     = datetime.datetime.now()
                        
                        super(CertificateAuthority, x).save(*args, **kwargs)
                    
                    ## Revoke and generate CRL
                    action.revoke_certificate(self.parent_passphrase)
                    action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Modify fields
                    prev.parent_passphrase = None
                    prev.active            = False
                    prev.der_encoded       = False
                    prev.pem_encoded       = False
                    prev.revoked           = datetime.datetime.now()
                    
                elif self.action == 'renew':
                    ## Revoke if certificate is active
                    if self.parent and not action.get_revoke_status_from_cert():
                        action.revoke_certificate(self.parent_passphrase)
                        action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Rebuild the ca metadata
                    self.rebuild_ca_metadata(modify=True, task='replace')
                    
                    ## Renew certificate and update CRL
                    if self.parent == None:
                        action.generate_self_signed_cert()
                        action.generate_crl(self.name, self.passphrase)
                    else:
                        action.generate_csr()
                        action.sign_csr()
                        action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    action.update_ca_chain_file()
                    
                    ## Modify fields
                    prev.created = datetime.datetime.now()
                    delta = datetime.timedelta(self.valid_days)
                    prev.expiry_date = datetime.datetime.now() + delta
                    prev.valid_days = self.valid_days
                    
                    prev.parent_passphrase = None
                    prev.active            = True
                    prev.pem_encoded       = True
                    prev.der_encoded       = self.der_encoded
                    prev.revoked           = None
                    
                    ## Make sure possibly updated fields are saved to DB
                    prev.country      = self.country
                    prev.locality     = self.locality
                    prev.organization = self.organization
                    prev.email        = self.email
                    
                    ## Get the new serial
                    prev.serial = action.get_serial_from_cert()
                
                ## Save the data
                self = prev
                self.action = 'update'
                
                super(CertificateAuthority, self).save(*args, **kwargs)
            else:
                raise Exception( 'Invalid action %s supplied' % self.action )
        else:
            ## Set creation data
            self.created = datetime.datetime.now()
            delta = datetime.timedelta(self.valid_days)
            self.expiry_date = datetime.datetime.now() + delta
            
            ## Force instance to be active
            self.active = True
            
            ## Reset the action
            self.action = 'update'
            
            ## Rebuild the ca metadata
            self.rebuild_ca_metadata(modify=True, task='append')
            
            ## Generate keys and certificates
            action = OpensslActions(self)
            action.generate_key()
            
            if not self.parent:
                action.generate_self_signed_cert()
            else:
                action.generate_csr()
                action.sign_csr()
            
            if self.der_encoded:
                action.generate_der_encoded()
            
            ## Generate CRL
            action.generate_crl(self.name, self.passphrase)
            
            ## Always enable pem encoded flag
            self.pem_encoded = True
            
            ## Get the serial from certificate
            self.serial = action.get_serial_from_cert()
            
            ## Generate ca chain (db field and chain file)
            chain = []
            chain_str = ''
            
            p = self.parent
            
            if self.parent == None:
                chain.append('self-signed')
            else:
                chain.append( self.common_name )
                while p != None:
                    chain.append(p.common_name)
                    p = p.parent
            
            chain.reverse()
            
            ## Build chain string and file
            for i in chain:
                if chain_str == '':
                    chain_str += '%s' % i
                else:
                    chain_str += '&nbsp;&rarr;&nbsp;%s' % i
            
            self.ca_chain = chain_str
            
            action.update_ca_chain_file()
            
            ## Encrypt passphrase and blank parent's passphrase
            self.passphrase = md5_constructor(self.passphrase).hexdigest()
            self.parent_passphrase = None
            
        ## Save the data
        super(CertificateAuthority, self).save(*args, **kwargs)
    
    def delete(self, passphrase, *args, **kwargs):
        """Delete the CertificateAuthority object"""
        
        logger.info( "Certificate %s is going to be deleted" % self.name )
        
        ## Container for CA folders to delete
        self.remove_chain = []
        
        ## Is a revoke required?
        revoke_required = True
        
        ## Helper function for recusion
        def chain_recursion(r_id):
            
            ca = CertificateAuthority.objects.get(pk=r_id)
            self.remove_chain.append(ca.name)
            
            ## Search for related CA's
            child_cas = CertificateAuthority.objects.filter(parent=r_id)
            if child_cas:
                for ca in child_cas:
                    chain_recursion(ca.pk)
        
        if not self.parent:
            logger.info( "No revoking of certitifcates. %s is a toplevel CA" % self.name )
            revoke_required = False
        else:
            ## Collect child CA's and certificates
            chain_recursion(self.pk)
            logger.info( "Full chain is %s and pf is %s" % (self.remove_chain, self.passphrase))
        
        ## Remoke first ca in the chain
        if revoke_required:
            a = OpensslActions(CertificateAuthority.objects.get(pk=self.pk))
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)
        
        ## Rebuild the ca metadata
        self.rebuild_ca_metadata(modify=True, task='exclude')
        
        ## Call the "real" delete function
        super(CertificateAuthority, self).delete(*args, **kwargs)
    
    ##---------------------------------##
    ## Helper functions
    ##---------------------------------##
    
    def rebuild_ca_metadata(self, modify, task):
        """Wrapper around refresh_pki_metadata"""
        
        if modify:
            if task == 'append':
                ## Get list of all defined CA's
                known_cas = list(CertificateAuthority.objects.all())
                known_cas.append(self)
            elif task == 'replace':
                known_cas = list(CertificateAuthority.objects.exclude(pk=self.pk))
                known_cas.append(self)
            elif task == 'exclude':
                known_cas = list(CertificateAuthority.objects.exclude(pk=self.pk))
        else:
            known_cas = list(CertificateAuthority.objects.all())
        
        ## Rebuild the CA store metadata
        refresh_pki_metadata(known_cas)
    
    ##---------------------------------##
    ## View functions
    ##---------------------------------##
    
    def Tree_link(self):
        
        if PKI_ENABLE_GRAPHVIZ:
            return '<center><a href="%spki/tree/%d" target="_blank"><img src="%s/pki/img/tree.png" height="13px" width="13px" alt="Tree" title="Show full CA tree"/></a></center>' % (PKI_BASE_URL, self.pk, os.path.join(PKI_BASE_URL, MEDIA_URL))
        else:
            return '<center><img src="%spki/img/tree_disabled.png" alt="Tree" title="Enable setting PKI_ENABLE_GRAPHVIZ"/></center>' % os.path.join(PKI_BASE_URL, MEDIA_URL)
    
    Tree_link.allow_tags = True
    Tree_link.short_description = 'Tree'
  
##------------------------------------------------------------------##
## Certificate class
##------------------------------------------------------------------##

class Certificate(CertificateBase):
    """Certificate model"""
    
    common_name       = models.CharField(max_length=64)
    name              = models.CharField(max_length=64, help_text="Only change the suggestion if you really know what you're doing")
    parent            = models.ForeignKey('CertificateAuthority', blank=True, null=True, help_text='Leave blank to generate self-signed certificate')
    passphrase        = models.CharField(max_length=255, null=True, blank=True)
    pf_encrypted      = models.NullBooleanField()
    parent_passphrase = models.CharField(max_length=255, blank=True, null=True)
    pkcs12_encoded    = models.BooleanField(default=False, verbose_name="PKCS#12 encoding")
    pkcs12_passphrase = models.CharField(max_length=255, verbose_name="PKCS#12 passphrase", blank=True, null=True)
    cert_extension    = models.CharField(max_length=64, choices=EXTENSIONS, verbose_name="Purpose")
    subjaltname       = models.CharField(max_length=255, blank=True, null=True, verbose_name="SubjectAltName", \
                                         help_text='Comma seperated list of alt names. Valid are DNS:www.xyz.com, IP:1.2.3.4 and email:a@b.com in any \
                                         combination. Refer to the official openssl documentation for details' )

    class Meta:
        verbose_name_plural = 'Certificates'
        permissions         = ( ( "can_download", "Can download certificate", ), )
        unique_together     = ( ( "name", "parent" ), ("common_name", "parent"), )
    
    def __unicode__(self):
        return self.common_name
    
    ##---------------------------------##
    ## Redefined functions
    ##---------------------------------##
    
    def save(self, *args, **kwargs):
        """Save the Certificate object"""
        
        if self.pk:
            if self.action in ('update', 'revoke', 'renew'):
                
                action = OpensslActions(self)
                prev   = Certificate.objects.get(pk=self.pk)
                
                ## Update description. This is always allowed
                prev.description = self.description
                
                ## Create or remove DER certificate
                if self.der_encoded:
                    action.generate_der_encoded()
                else:
                    action.remove_der_encoded()
                
                prev.der_encoded    = self.der_encoded
                
                ## Create or remove PKCS12 certificate
                if self.pkcs12_encoded:
                    if prev.pkcs12_encoded and prev.pkcs12_passphrase == self.pkcs12_passphrase:
                        logger.debug( 'PKCS12 passphrase is unchanged. Nothing to do' )
                    else:
                        action.generate_pkcs12_encoded()
                else:
                    action.remove_pkcs12_encoded()
                    self.pkcs12_passphrase = prev.pkcs12_passphrase = None
                
                if self.pkcs12_passphrase:
                    prev.pkcs12_passphrase = md5_constructor(self.pkcs12_passphrase).hexdigest()
                else:
                    prev.pkcs12_passphrase = None
                
                prev.pkcs12_encoded = self.pkcs12_encoded
                
                if self.action == 'revoke' and self.parent:
                    
                    ## Revoke and generate CRL
                    action.revoke_certificate(self.parent_passphrase)
                    action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Modify fields
                    prev.parent_passphrase = None
                    prev.active            = False
                    prev.der_encoded       = False
                    prev.pem_encoded       = False
                    prev.pkcs12_encoded    = False
                    prev.revoked           = datetime.datetime.now()
                    
                elif self.action == 'renew':
                    
                    ## Revoke if certificate is active
                    if self.parent and not action.get_revoke_status_from_cert():
                        action.revoke_certificate(self.parent_passphrase)
                    
                    ## Renew and update CRL
                    if self.parent == None:
                        action.generate_self_signed_cert()
                    else:
                        action.generate_csr()
                        action.sign_csr()
                        action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Modify fields
                    prev.created     = datetime.datetime.now()
                    delta            = datetime.timedelta(self.valid_days)
                    prev.expiry_date = datetime.datetime.now() + delta
                    
                    prev.parent_passphrase = None
                    prev.active            = True
                    prev.pem_encoded       = True
                    prev.der_encoded       = self.der_encoded
                    prev.pkcs12_encoded    = self.pkcs12_encoded
                    prev.revoked           = None
                    prev.valid_days        = self.valid_days
                    
                    ## Make sure possibly updated fields are saved to DB
                    prev.country      = self.country
                    prev.locality     = self.locality
                    prev.organization = self.organization
                    prev.email        = self.email
                    
                    ## Get the new serial
                    prev.serial = action.get_serial_from_cert()
                
                ## Save the data
                self = prev
                self.action = 'update'
                
                super(Certificate, self).save(*args, **kwargs)
        else:
            ## Set creation data
            self.created = datetime.datetime.now()
            delta = datetime.timedelta(self.valid_days)
            self.expiry_date = datetime.datetime.now() + delta
            
            ## Force instance to be active
            self.active = True
            
            logger.info( "***** { New certificate generation: %s } *****" % self.name )
            
            ## Generate key and certificate
            action = OpensslActions(self)
            action.generate_key()
            
            if self.parent:
                action.generate_csr()
                action.sign_csr()
                self.ca_chain = self.parent.ca_chain
                if self.ca_chain == 'self-signed':
                    self.ca_chain = self.parent.name
            else:
                action.generate_self_signed_cert()
                self.ca_chain = "self-signed"
            
            ## Get the serial from certificate
            self.serial = action.get_serial_from_cert()
            
            self.pem_encoded = True
            
            ## Create or remove DER certificate
            if self.der_encoded:
                action.generate_der_encoded()
            else:
                action.remove_der_encoded()
            
            ## Create or remove PKCS12 certificate
            if self.pkcs12_encoded:
                action.generate_pkcs12_encoded()
            else:
                action.remove_pkcs12_encoded()
            
            if self.pkcs12_passphrase:
                self.pkcs12_passphrase = md5_constructor(self.pkcs12_passphrase).hexdigest()
            
            ## Encrypt passphrase and blank parent's passphrase
            if self.passphrase:
                self.passphrase = md5_constructor(self.passphrase).hexdigest()
            
            self.parent_passphrase = None
            
            ## Save the data
            super(Certificate, self).save(*args, **kwargs)
    
    def delete(self, passphrase, *args, **kwargs):
        """Delete the Certificate object"""
        
        ## Time for some rm action
        a = OpensslActions(self)
        
        if self.parent:
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)
        
        a.remove_complete_certificate()
        
        ## Call the "real" delete function
        super(Certificate, self).delete(*args, **kwargs)

    
