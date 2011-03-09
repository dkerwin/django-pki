# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

class Migration(SchemaMigration):

    def forwards(self, orm):
        
        # Adding model 'CertificateAuthority'
        db.create_table('pki_certificateauthority', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('description', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('country', self.gf('django.db.models.fields.CharField')(default='DE', max_length=2)),
            ('state', self.gf('django.db.models.fields.CharField')(max_length=32)),
            ('locality', self.gf('django.db.models.fields.CharField')(max_length=32)),
            ('organization', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('OU', self.gf('django.db.models.fields.CharField')(max_length=64, null=True, blank=True)),
            ('email', self.gf('django.db.models.fields.EmailField')(max_length=75, null=True, blank=True)),
            ('valid_days', self.gf('django.db.models.fields.IntegerField')()),
            ('key_length', self.gf('django.db.models.fields.IntegerField')(default=2048)),
            ('expiry_date', self.gf('django.db.models.fields.DateField')(null=True, blank=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('revoked', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('active', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('serial', self.gf('django.db.models.fields.CharField')(max_length=64, null=True, blank=True)),
            ('ca_chain', self.gf('django.db.models.fields.CharField')(max_length=200, null=True, blank=True)),
            ('pem_encoded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('der_encoded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('action', self.gf('django.db.models.fields.CharField')(default='create', max_length=32)),
            ('common_name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=64)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=64)),
            ('subcas_allowed', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('parent', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['pki.CertificateAuthority'], null=True, blank=True)),
            ('type', self.gf('django.db.models.fields.CharField')(default='RootCA', max_length=32, null=True)),
            ('passphrase', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('parent_passphrase', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
            ('pf_encrypted', self.gf('django.db.models.fields.NullBooleanField')(null=True, blank=True)),
            ('policy', self.gf('django.db.models.fields.CharField')(default='policy_anything', max_length=50)),
        ))
        db.send_create_signal('pki', ['CertificateAuthority'])

        # Adding model 'Certificate'
        db.create_table('pki_certificate', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('description', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('country', self.gf('django.db.models.fields.CharField')(default='DE', max_length=2)),
            ('state', self.gf('django.db.models.fields.CharField')(max_length=32)),
            ('locality', self.gf('django.db.models.fields.CharField')(max_length=32)),
            ('organization', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('OU', self.gf('django.db.models.fields.CharField')(max_length=64, null=True, blank=True)),
            ('email', self.gf('django.db.models.fields.EmailField')(max_length=75, null=True, blank=True)),
            ('valid_days', self.gf('django.db.models.fields.IntegerField')()),
            ('key_length', self.gf('django.db.models.fields.IntegerField')(default=2048)),
            ('expiry_date', self.gf('django.db.models.fields.DateField')(null=True, blank=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('revoked', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('active', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('serial', self.gf('django.db.models.fields.CharField')(max_length=64, null=True, blank=True)),
            ('ca_chain', self.gf('django.db.models.fields.CharField')(max_length=200, null=True, blank=True)),
            ('pem_encoded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('der_encoded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('action', self.gf('django.db.models.fields.CharField')(default='create', max_length=32)),
            ('common_name', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('parent', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['pki.CertificateAuthority'], null=True, blank=True)),
            ('passphrase', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
            ('pf_encrypted', self.gf('django.db.models.fields.NullBooleanField')(null=True, blank=True)),
            ('parent_passphrase', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
            ('pkcs12_encoded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('pkcs12_passphrase', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
            ('cert_extension', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('subjaltname', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
        ))
        db.send_create_signal('pki', ['Certificate'])

        # Adding unique constraint on 'Certificate', fields ['name', 'parent']
        db.create_unique('pki_certificate', ['name', 'parent_id'])

        # Adding unique constraint on 'Certificate', fields ['common_name', 'parent']
        db.create_unique('pki_certificate', ['common_name', 'parent_id'])


    def backwards(self, orm):
        
        # Removing unique constraint on 'Certificate', fields ['common_name', 'parent']
        db.delete_unique('pki_certificate', ['common_name', 'parent_id'])

        # Removing unique constraint on 'Certificate', fields ['name', 'parent']
        db.delete_unique('pki_certificate', ['name', 'parent_id'])

        # Deleting model 'CertificateAuthority'
        db.delete_table('pki_certificateauthority')

        # Deleting model 'Certificate'
        db.delete_table('pki_certificate')


    models = {
        'pki.certificate': {
            'Meta': {'unique_together': "(('name', 'parent'), ('common_name', 'parent'))", 'object_name': 'Certificate'},
            'OU': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            'action': ('django.db.models.fields.CharField', [], {'default': "'create'", 'max_length': '32'}),
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'ca_chain': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'cert_extension': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'common_name': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'country': ('django.db.models.fields.CharField', [], {'default': "'DE'", 'max_length': '2'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'der_encoded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'description': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'expiry_date': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'key_length': ('django.db.models.fields.IntegerField', [], {'default': '2048'}),
            'locality': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'organization': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'parent': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['pki.CertificateAuthority']", 'null': 'True', 'blank': 'True'}),
            'parent_passphrase': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'passphrase': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'pem_encoded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'pf_encrypted': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'pkcs12_encoded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'pkcs12_passphrase': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'revoked': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'serial': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            'state': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'subjaltname': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'valid_days': ('django.db.models.fields.IntegerField', [], {})
        },
        'pki.certificateauthority': {
            'Meta': {'object_name': 'CertificateAuthority'},
            'OU': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            'action': ('django.db.models.fields.CharField', [], {'default': "'create'", 'max_length': '32'}),
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'ca_chain': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'common_name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'country': ('django.db.models.fields.CharField', [], {'default': "'DE'", 'max_length': '2'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'der_encoded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'description': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'expiry_date': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'key_length': ('django.db.models.fields.IntegerField', [], {'default': '2048'}),
            'locality': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'organization': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'parent': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['pki.CertificateAuthority']", 'null': 'True', 'blank': 'True'}),
            'parent_passphrase': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'passphrase': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'pem_encoded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'pf_encrypted': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'policy': ('django.db.models.fields.CharField', [], {'default': "'policy_anything'", 'max_length': '50'}),
            'revoked': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'serial': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            'state': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'subcas_allowed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'type': ('django.db.models.fields.CharField', [], {'default': "'RootCA'", 'max_length': '32', 'null': 'True'}),
            'valid_days': ('django.db.models.fields.IntegerField', [], {})
        }
    }

    complete_apps = ['pki']
