from django import template
from django.core import urlresolvers

register = template.Library()

@register.simple_tag
def pkinav():
    return """
    <div id="pkinav">
        <ul>
            <li><a href="%s">Certificate authorities</a>&nbsp;<a href="%s">(+)</a></li>
            <li><a href="%s">Certificates</a>&nbsp;<a href="%s">(+)</a></li>
            <li><a href="%s">x509 Extensions</a>&nbsp;<a href="%s">(+)</a></li>
            <li><a href="%s">Refresh PKI metadata</a></li>
        </ul>
    </div>""" % (urlresolvers.reverse('admin:pki_certificateauthority_changelist'),
                 urlresolvers.reverse('admin:pki_certificateauthority_add'),
                 urlresolvers.reverse('admin:pki_certificate_changelist'),
                 urlresolvers.reverse('admin:pki_certificate_add'),
                 urlresolvers.reverse('admin:pki_x509extension_changelist'),
                 urlresolvers.reverse('admin:pki_x509extension_add'),
                 urlresolvers.reverse('pki:refresh_metadata'),
                )
