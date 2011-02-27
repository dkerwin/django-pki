import os
import datetime
from logging import getLogger
from shutil import rmtree

from django.db import models
from django.core import urlresolvers
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User

from pki.openssl import Openssl, md5_constructor, refresh_pki_metadata
from pki.settings import ADMIN_MEDIA_PREFIX, MEDIA_URL, PKI_BASE_URL, PKI_DEFAULT_COUNTRY, PKI_ENABLE_GRAPHVIZ, PKI_ENABLE_EMAIL

logger = getLogger("pki")

##------------------------------------------------------------------##
## Choices
##------------------------------------------------------------------##

KEY_LENGTH = ( (1024, '1024'), (2048, '2048'), (4096, '4096'), )
POLICY     = ( ('policy_match', 'policy_match'), ('policy_anything', 'policy_anything'), )
ACTIONS    = ( ('create', 'Create certificate'),
               ('update', 'Update description and export options'),
               ('revoke', 'Revoke certificate'),
               ('renew',  'Renew CSR (CN and key are kept)'),
             )
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
    der_encoded  = models.BooleanField(default=False, verbose_name="DER encoding")
    action       = models.CharField(max_length=32, choices=ACTIONS, default='create', help_text="Yellow fields can/have to be modified!")
    extension    = models.ForeignKey(to="x509Extension", blank=True, null=True, verbose_name="x509 Extension")
    
    class Meta:
        abstract = True
    
    ##------------------------------------------------------------------##
    ## Helper functions
    ##------------------------------------------------------------------##
    
    def get_pki_icon_html(self, img, title="", css="centered", id=""):
        """Return HTML for given image.
        
        Can add optional alt and title parameters.
        """
        
        if css:
            css_class = 'class=%s' % css
        else:
            css_class = ''
        
        img_path = os.path.join(PKI_BASE_URL, MEDIA_URL, 'pki/img', img)
        return '<img id="%s" %s src="%s" alt="%s" title="%s"/>' % (id, css_class, img_path, title, title)
    
    ##------------------------------------------------------------------##
    ## Changelist list_display functions
    ##------------------------------------------------------------------##
    
    def State(self):
        """Overwrite the Booleanfield admin for admin's changelist"""
        
        if not self.pk:
            return ""
        
        if self.active is True:
            return self.get_pki_icon_html('icon-yes.gif', "Certificate is valid", css="") + " <strong>/ valid</strong>"
        else:
            return self.get_pki_icon_html('icon-no.gif', "Certificate is revoked", css="") + " <strong>/ revoked</strong>"
    
    State.allow_tags = True
    State.short_description = 'State'
    
    def Valid_center(self):
        """Overwrite the Booleanfield admin for admin's changelist"""
        
        if self.active is True:
            return self.get_pki_icon_html('icon-yes.gif', "Certificate is valid", id="active_%d" % self.pk)
        else:
            return self.get_pki_icon_html('icon-no.gif', "Certificate is revoked", id="active_%d" % self.pk)
    
    Valid_center.allow_tags = True
    Valid_center.short_description = 'Valid'
    Valid_center.admin_order_field = 'active'
    
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
    
    Creation_date.admin_order_field = 'created'
    
    def Revocation_date(self):
        """Return revocation date in custom format"""
        
        return self.revoked.strftime("%Y-%m-%d %H:%M:%S")
    
    Revocation_date.admin_order_field = 'revoked'
    
    def Expiry_date(self):
        """Return expiry date with days left.
        
        Return color marked expiry date based on days left.
        < 0 : EXPIRED text and red font color
        < 30: Orange color
        > 30: Just date and days left
        """
        now = datetime.datetime.now().date()        
        diff = self.expiry_date - now
        
        
        if not self.active:
            return '<span class="revoked">%s (%sd)</span>' % (self.expiry_date, diff.days)
        
        if diff.days < 30 and diff.days >= 0:
            span_class = ""
            return '<span class="almost_expired">%s (%sd)</span>' % (self.expiry_date, diff.days)
        elif diff.days < 0:
            return '<span class="expired">%s (EXPIRED)</span>' % self.expiry_date
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
        
        if PKI_ENABLE_GRAPHVIZ:
            return '<a href="%s" target="_blank">%s</a>' % (urlresolvers.reverse('pki:chain', kwargs={'model': self.__class__.__name__.lower(), 'id': self.pk}), \
                                            self.get_pki_icon_html('chain.png', "Show object chain", id="chain_link_%d" % self.pk))
        else:
            return self.get_pki_icon_html("chain.png", "Enable setting PKI_ENABLE_GRAPHVIZ")
    
    Chain_link.allow_tags = True
    Chain_link.short_description = 'Chain'
    
    def Email_link(self):
        """Display email link based on status.
        
        If PKI_ENABLE_EMAIL or certificate isn't active a disabled (b/w) icon is displayed.
        If no email address is set in the certificate a icon with exclamation mark is displayed.
        Otherwise the normal icon is returned.
        """
        
        if not PKI_ENABLE_EMAIL:
            return self.get_pki_icon_html("mail--arrow_bw.png", "Enable setting PKI_ENABLE_EMAIL", id="email_delivery_%d" % self.pk)
        elif not self.active:
            return self.get_pki_icon_html("mail--arrow_bw.png", "Certificate is revoked. Disabled", id="email_delivery_%d" % self.pk)
        else:
            if self.email:
                return '<a href="%s">%s</a>' % (urlresolvers.reverse('pki:email', kwargs={'model': self.__class__.__name__.lower(), 'id': self.pk}), \
                                                self.get_pki_icon_html("mail--arrow.png", "Send to '<strong>%s</strong>'" % self.email, \
                                                                       id="email_delivery_%d" % self.pk))
            else:
                return self.get_pki_icon_html("mail--exclamation.png", "Certificate has no email set. Disabled", id="email_delivery_%d" % self.pk)
    
    Email_link.allow_tags = True
    Email_link.short_description = 'Delivery'
    
    def Download_link(self):
        """Return a download icon.
        
        Based on object status => clickable icon or just a b/w image
        """
        
        if self.active:
            return '<a href="%s">%s</a>' % (urlresolvers.reverse('pki:download', kwargs={'model': self.__class__.__name__.lower(), 'id': self.pk}), \
                                            self.get_pki_icon_html("drive-download.png", "Download certificate zip", id="download_link_%d" % self.pk))
        else:
            return self.get_pki_icon_html("drive-download_bw.png", "Certificate is revoked. Disabled", id="download_link_%d" % self.pk)
    
    Download_link.allow_tags = True
    Download_link.short_description = 'Download'
    
    def Parent_link(self):
        """Return parent name.
        
        Returns parent's name when parent != None or self-signed
        """
        
        if self.parent:
            return '<a href="%s">%s</a>' % (urlresolvers.reverse('admin:pki_certificateauthority_change', args=(self.parent.pk,)), self.parent.common_name)
        else:
            return '<a href="%s">self-signed</a>' % (urlresolvers.reverse('admin:pki_%s_change' % self.__class__.__name__.lower(), args=(self.pk,)))
    
    Parent_link.allow_tags = True
    Parent_link.short_description = 'Parent'
    Parent_link.admin_order_field = 'parent'
    
    def Certificate_Dump(self):
        """Dump of the certificate"""
        
        if self.pk and self.active:
            a = Openssl(self)
            return "<textarea id=\"certdump\">%s</textarea>" % a.dump_certificate()
        else:
            return "Nothing to display"
    
    Certificate_Dump.allow_tags = True
    Certificate_Dump.short_description = "Certificate dump"
    
    def CA_Clock(self):
        """"""
        return '<div id="clock_container"><img src="%spki/img/clock-frame.png" style="margin-right:5px"/><span id="clock"></span></div>' % MEDIA_URL
    
    CA_Clock.allow_tags = True
    CA_Clock.short_description = "CA clock"
    
    def Update_Changelog(self, obj, user, action, changes):
        """Update changelog for given object"""
        
        PkiChangelog(model_id=ContentType.objects.get_for_model(obj).pk, object_id=obj.pk, action=action, user=user, changes="; ".join(changes)).save()
    
    def Delete_Changelog(self, obj):
        """Delete changelogs for a given object"""
        
        PkiChangelog.objects.filter(model_id=ContentType.objects.get_for_model(obj).pk, object_id=obj.pk).delete()
    
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
    parent            = models.ForeignKey('self', blank=True, null=True)
    passphrase        = models.CharField(max_length=255, blank=True, help_text="At least 8 characters. Remeber this passphrase - <font color='red'> \
                                                                    <strong>IT'S NOT RECOVERABLE</strong></font><br>Will be shown as md5 encrypted string")
    parent_passphrase = models.CharField(max_length=255, null=True, blank=True, help_text="Leave empty if this is a top-level CA")
    policy            = models.CharField(max_length=50, choices=POLICY, default='policy_anything', help_text='policy_match: All subject settings must \
                                                                                                              match the signing CA<br> \
                                                                                                              policy_anything: Nothing has to match the \
                                                                                                              signing CA')
    crl_distribution  = models.CharField(max_length=255, verbose_name='CRL Distribution Points', null=True, blank=True, help_text='Comma seperated list of URI elements \
                                                                                                                                   just like subjectAltName. Example: \
                                                                                                                                   URI:http://ca.local/ca.crl,...')

    class Meta:
        db_table            = 'pki_certificateauthority'
        verbose_name_plural = 'Certificate Authorities'
        permissions         = ( ( "can_download", "Can download", ), )

    def __unicode__(self):
        return self.common_name
    
    ##---------------------------------##
    ## Redefined functions
    ##---------------------------------##
    
    def save(self, *args, **kwargs):
        """Save the CertificateAuthority object"""
        
        ## Set user to UNKNOWN if it's missing
        if not self.user:
            self.user = "UNKNOWN"
        
        ## Variables to track changes
        c_action = self.action
        c_user   = self.user
        c_list   = []
        
        if self.pk:
            if self.action in ('update', 'revoke', 'renew'):
                action = Openssl(self)
                prev   = CertificateAuthority.objects.get(pk=self.pk)
                
                if self.action == 'revoke':
                    if not self.parent:
                        raise Exception( "You cannot revoke a self-signed certificate! No parent => No revoke" )
                    
                    ## Revoke and generate CRL
                    action.revoke_certificate(self.parent_passphrase)
                    action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Modify fields
                    prev.active            = False
                    prev.der_encoded       = False
                    prev.revoked           = datetime.datetime.now()
                    
                    c_list.append('Revoked certificate "%s"' % self.common_name)
                elif self.action == 'renew':
                    c_list.append('Renewed certificate "%s"' % self.common_name)
                    
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
                    
                    if prev.valid_days != self.valid_days:
                        c_list.append("Changed valid days to %d" % (prev.valid_days, self.valid_days))
                    
                    prev.valid_days  = self.valid_days
                    prev.active      = True
                    prev.revoked     = None
                    
                    ## Make sure possibly updated fields are saved to DB
                    if prev.country != self.country: c_list.append('Updated country to "%s"' % self.country)
                    if prev.locality != self.locality: c_list.append('Updated locality to "%s"' % self.locality)
                    if prev.organization != self.organization: c_list.append('Updated organization to "%s"' % self.organization)
                    if prev.email != self.email: c_list.append('Updated email to "%s"' % self.email)
                    if prev.OU != self.OU: c_list.append('Updated OU to "%s"' % self.OU)
                    
                    prev.country      = self.country
                    prev.locality     = self.locality
                    prev.organization = self.organization
                    prev.email        = self.email
                    prev.OU           = self.OU
                    
                    ## Get the new serial
                    prev.serial = action.get_serial_from_cert()
                    c_list.append("Serial number changed to %s" % prev.serial)
                
                ## DB-revoke all related certs
                garbage = []
                id_dict = { 'cert': [], 'ca': [], }
                
                from pki.views import chain_recursion as r_chain_recursion
                r_chain_recursion(self.id, garbage, id_dict)
                
                for i in id_dict['cert']:
                    x = Certificate.objects.get(pk=i)
                    x.active         = False
                    x.der_encoded    = False
                    x.pkcs12_encoded = False
                    x.revoked        = datetime.datetime.now()
                    
                    super(Certificate, x).save(*args, **kwargs)
                    self.Update_Changelog(obj=x, user=c_user, action='broken', changes=(['Broken by %s of CA "%s"' % (c_action, self.common_name),]))
                
                for i in id_dict['ca']:
                    x = CertificateAuthority.objects.get(pk=i)
                    x.active      = False
                    x.der_encoded = False
                    x.revoked     = datetime.datetime.now()
                    
                    super(CertificateAuthority, x).save(*args, **kwargs)
                    if x.pk != self.pk:
                        self.Update_Changelog(obj=x, user=c_user, action='broken', changes=(['Broken by %s of CA "%s"' % (c_action, self.common_name),]))
                
                ## Update description. This is always allowed
                if prev.description != self.description:
                    c_list.append('Updated description to "%s"' % self.description)
                
                if prev.der_encoded is not self.der_encoded:
                    c_list.append("DER encoding set to %s" % self.der_encoded)
                
                if self.der_encoded and self.action != "revoke":
                    action.generate_der_encoded()
                else:
                    action.remove_der_encoded()
                
                self = prev
                self.action = 'update'
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
            action = Openssl(self)
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
            
            ## Set change text to fixed value
            c_list.append('Created certificate "%s"' % self.common_name)
        
        ## Blank parent passphrase
        self.parent_passphrase = None
        
        ## Save the data
        super(CertificateAuthority, self).save(*args, **kwargs)
        
        ## Update changelog
        self.Update_Changelog(obj=self, user=c_user, action=c_action, changes=c_list)
    
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
            a = Openssl(CertificateAuthority.objects.get(pk=self.pk))
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)
        
        ## Rebuild the ca metadata
        self.rebuild_ca_metadata(modify=True, task='exclude')
        
        ## Remove object history
        self.Delete_Changelog(obj=self)
        
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
    
    def is_edge_ca(self):
        """Return true if the CA is a edge CA that cannot contain other CA's"""
        
        return "pathlen:0" in self.extension.basic_constraints.lower()
    
    ##---------------------------------##
    ## View functions
    ##---------------------------------##
    
    def Tree_link(self):
        
        if PKI_ENABLE_GRAPHVIZ:
            return '<a href="%s" target="_blank">%s</a>' % (urlresolvers.reverse('pki:tree', kwargs={'id': self.pk}), \
                                                            self.get_pki_icon_html("tree.png", "Show CA tree", id="tree_link_%d" % self.pk))
        else:
            return self.get_pki_icon_html("tree_disabled.png", "Enable setting PKI_ENABLE_GRAPHVIZ")
    
    Tree_link.allow_tags = True
    Tree_link.short_description = 'Tree'
    
    def Child_certs(self):
        """Show associated client certificates"""
        
        if not self.is_edge_ca():
            return self.get_pki_icon_html("blue-document-tree_bw.png", "No children", id="show_child_certs_%d" % self.pk)
        else:
            return "<a href=\"%s\" target=\"_blank\">%s</a>" % ('?'.join([urlresolvers.reverse('admin:pki_certificate_changelist'), 'parent__id__exact=%d' % self.pk]), \
                                                                self.get_pki_icon_html("blue-document-tree.png", "Show child certificates", \
                                                                                       id="show_child_certs_%d" % self.pk))
    
    Child_certs.allow_tags = True
    Child_certs.short_description = "Children"
     
##------------------------------------------------------------------##
## Certificate class
##------------------------------------------------------------------##

class Certificate(CertificateBase):
    """Certificate model"""
    
    common_name       = models.CharField(max_length=64)
    name              = models.CharField(max_length=64, help_text="Only change the suggestion if you really know what you're doing")
    parent            = models.ForeignKey('CertificateAuthority', blank=True, null=True, help_text='Leave blank to generate self-signed certificate')
    passphrase        = models.CharField(max_length=255, null=True, blank=True)
    parent_passphrase = models.CharField(max_length=255, blank=True, null=True)
    pkcs12_encoded    = models.BooleanField(default=False, verbose_name="PKCS#12 encoding")
    pkcs12_passphrase = models.CharField(max_length=255, verbose_name="PKCS#12 passphrase", blank=True, null=True)
    subjaltname       = models.CharField(max_length=255, blank=True, null=True, verbose_name="SubjectAltName", \
                                         help_text='Comma seperated list of alt names. Valid are DNS:www.xyz.com, IP:1.2.3.4 and email:a@b.com in any \
                                         combination. Refer to the official openssl documentation for details' )

    class Meta:
        db_table            = 'pki_certificate'
        verbose_name_plural = 'Certificates'
        permissions         = ( ( "can_download", "Can download", ), )
        unique_together     = ( ( "name", "parent" ), ("common_name", "parent"), )
    
    def __unicode__(self):
        return self.common_name
    
    ##---------------------------------##
    ## Redefined functions
    ##---------------------------------##
    
    def save(self, *args, **kwargs):
        """Save the Certificate object"""
        
        ## Set user to UNKNOWN if it's missing
        if not self.user:
            self.user = "UNKNOWN"
        
        ## Variables to track changes
        c_action = self.action
        c_user   = self.user
        c_list   = []
        
        if self.pk:
            if self.action in ('update', 'revoke', 'renew'):
                action = Openssl(self)
                prev   = Certificate.objects.get(pk=self.pk)
                
                if self.action == 'revoke':
                    if not self.parent:
                        raise Exception( "You cannot revoke a self-signed certificate! No parent => No revoke" )
                    
                    ## Revoke and generate CRL
                    action.revoke_certificate(self.parent_passphrase)
                    action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Modify fields
                    prev.active            = False
                    prev.der_encoded       = False
                    prev.pkcs12_encoded    = False
                    prev.revoked           = datetime.datetime.now()
                    
                    c_list.append('Revoked certificate "%s"' % self.common_name)
                elif self.action == 'renew':
                    c_list.append('Renewed certificate "%s"' % self.common_name)
                    
                    ## Revoke if certificate is active
                    if self.parent and not action.get_revoke_status_from_cert():
                        action.revoke_certificate(self.parent_passphrase)
                        action.generate_crl(self.parent.name, self.parent_passphrase)
                    
                    ## Renew certificate and update CRL
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
                    
                    if prev.valid_days != self.valid_days:
                        c_list.append("Changed valid days to %d" % (prev.valid_days, self.valid_days))
                    
                    prev.valid_days  = self.valid_days
                    prev.active      = True
                    prev.revoked     = None
                    
                    ## Make sure possibly updated fields are saved to DB
                    if prev.country != self.country: c_list.append('Updated country to "%s"' % self.country)
                    if prev.locality != self.locality: c_list.append('Updated locality to "%s"' % self.locality)
                    if prev.organization != self.organization: c_list.append('Updated organization to "%s"' % self.organization)
                    if prev.email != self.email: c_list.append('Updated email to "%s"' % self.email)
                    if prev.OU != self.OU: c_list.append('Updated OU to "%s"' % self.OU)
                    
                    prev.country      = self.country
                    prev.locality     = self.locality
                    prev.organization = self.organization
                    prev.email        = self.email
                    prev.OU           = self.OU
                    
                    ## Get the new serial
                    prev.serial = action.get_serial_from_cert()
                    c_list.append("Serial number changed to %s" % prev.serial)
                    
                    ## Encoding
                    if prev.pkcs12_encoded != self.pkcs12_encoded:
                        c_list.append("PKCS12 encoding set to %s" % self.der_encoded)
                    
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
                    
                    if prev.der_encoded is not self.der_encoded:
                        c_list.append("DER encoding set to %s" % self.der_encoded)
                    
                    if self.der_encoded:
                        action.generate_der_encoded()
                    else:
                        action.remove_der_encoded()
                
                ## Update description. This is always allowed
                if prev.description != self.description:
                    c_list.append('Updated description to "%s"' % self.description)
                
                ## Save the data
                self = prev
                self.action = 'update'
        else:
            ## Set creation data
            self.created = datetime.datetime.now()
            delta = datetime.timedelta(self.valid_days)
            self.expiry_date = datetime.datetime.now() + delta
            
            ## Force instance to be active
            self.active = True
            
            logger.info( "***** { New certificate generation: %s } *****" % self.name )
            
            ## Generate key and certificate
            action = Openssl(self)
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
            
            ## Encoding
            if self.der_encoded:
                action.generate_der_encoded()
            
            if self.pkcs12_encoded:
                action.generate_pkcs12_encoded()
            
            ## Encrypt passphrase and blank parent's passphrase
            if self.passphrase:
                self.passphrase = md5_constructor(self.passphrase).hexdigest()
            
            ## Set change text to fixed value
            c_list.append('Created certificate "%s"' % action.subj)
        
        ## Blank parent passphrase
        self.parent_passphrase = None
        
        ## Save the data
        super(Certificate, self).save(*args, **kwargs)
        
        ## Update changelog
        self.Update_Changelog(obj=self, user=c_user, action=c_action, changes=c_list)
    
    def delete(self, passphrase, *args, **kwargs):
        """Delete the Certificate object"""
        
        ## Time for some rm action
        a = Openssl(self)
        
        if self.parent:
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)
        
        a.remove_complete_certificate()
        
        ## Remove object history
        self.Delete_Changelog(obj=self)
        
        ## Call the "real" delete function
        super(Certificate, self).delete(*args, **kwargs)

class PkiChangelog(models.Model):
    """Changlog for changes on the PKI. Overrides the builtin admin history"""
    
    model_id    = models.IntegerField()
    object_id   = models.IntegerField()
    action_time = models.DateTimeField(auto_now=True)
    action      = models.CharField(max_length=64)
    user        = models.ForeignKey(User, blank=True, null=True)
    changes     = models.TextField()
    
    class Meta:
        db_table = 'pki_changelog'
        ordering = ['-action_time']
    
    def __unicode__(self):
        return str(self.pk)

class x509Extension(models.Model):
    """x509 extensions"""
    
    SUBJECT_KEY_IDENTIFIER   = ( ('hash', 'hash'), )
    AUTHORITY_KEY_IDENTIFIER = ( ('keyid:always,issuer:always', 'keyid: always, issuer: always'), )
    BASIC_CONSTRAINTS        = ( ('CA:TRUE', 'Root or Intermediate CA (CA:TRUE)'),
                                 ('CA:TRUE,pathlen:0', 'Edge CA (CA:TRUE, pathlen:0)'),
                                 ('CA:FALSE', 'Enduser Certificate (CA:FALSE)'), )
    
    name                        = models.CharField(max_length=255, unique=True)
    description                 = models.CharField(max_length=255)
    created                     = models.DateTimeField(auto_now_add=True)
    basic_constraints           = models.CharField(max_length=255, choices=BASIC_CONSTRAINTS, verbose_name="basicConstraints")
    basic_constraints_critical  = models.BooleanField(default=True, verbose_name="Make basicConstraints critical")
    key_usage                   = models.ManyToManyField("KeyUsage", verbose_name="keyUsage",
                                                         help_text="Usual values:<br />\
                                                                    CA: keyCertSign, cRLsign<br />\
                                                                    Cert: digitalSignature, nonRedupiation, keyEncipherment<br />")
    key_usage_critical          = models.BooleanField(verbose_name="Make keyUsage critical")
    extended_key_usage          = models.ManyToManyField("ExtendedKeyUsage", blank=True, null=True, verbose_name="extendedKeyUsage", \
                                                         help_text="serverAuth - SSL/TLS Web Server Authentication<br /> \
                                                                    clientAuth - SSL/TLS Web Client Authentication.<br /> \
                                                                    codeSigning - Code signing<br /> \
                                                                    emailProtection - E-mail Protection (S/MIME)<br /> \
                                                                    timeStamping - Trusted Timestamping<br /> \
                                                                    msCodeInd - Microsoft Individual Code Signing (authenticode)<br /> \
                                                                    msCodeCom - Microsoft Commercial Code Signing (authenticode)<br /> \
                                                                    msCTLSign - Microsoft Trust List Signing<br /> \
                                                                    msSGC - Microsoft Server Gated Crypto<br /> \
                                                                    msEFS - Microsoft Encrypted File System<br /> \
                                                                    nsSGC - Netscape Server Gated Crypto<br />")
    extended_key_usage_critical = models.BooleanField(verbose_name="Make extendedKeyUsage critical")
    subject_key_identifier      = models.CharField(max_length=255, choices=SUBJECT_KEY_IDENTIFIER, default="hash", verbose_name="subjectKeyIdentifier")
    authority_key_identifier    = models.CharField(max_length=255, choices=AUTHORITY_KEY_IDENTIFIER, default="keyid:always,issuer:always", verbose_name="authorityKeyIdentifier")
    crl_distribution_point      = models.BooleanField(verbose_name="Require CRL Distribution Point", help_text="All objects using will require a CRLDistributionPoint set")
    
    class Meta:
        db_table = 'pki_x509extension'
    
    def __unicode__(self):
        return self.name
    
    def key_usage_csv(self):
        r = []
        if self.key_usage_critical:
            r.append('critical')
        for x in self.key_usage.all():
            r.append(x.name)
        return ",".join(r)
    
    def ext_key_usage_csv(self):
        r = []
        if self.extended_key_usage_critical:
            r.append('critical')
        for x in self.extended_key_usage.all():
            r.append(x.name)
        return ",".join(r)
    
class KeyUsage(models.Model):
    """Container table for KeyUsage"""
    
    name = models.CharField(max_length=64, unique=True)
    
    def __unicode__(self):
        return self.name

class ExtendedKeyUsage(models.Model):
    """Container table for Extended Key Usage"""
    
    name = models.CharField(max_length=64, unique=True)
    
    def __unicode__(self):
        return self.name
    