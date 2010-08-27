from django import template
from pki import __version__ as version

register = template.Library()

@register.simple_tag
def pki_version():
    return version
